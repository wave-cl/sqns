//! The record store: verify, merge, persist.
//!
//! The store is the only place records enter the server, and every path in —
//! a client publishing, a peer replicating, a snapshot loading from disk —
//! goes through [`Store::put`], which verifies the signature chain before the
//! record is kept. A record is accepted only if it beats the one already held,
//! which makes replication order-independent and replay-safe.
//!
//! Two pieces of state outlive the records themselves, because both exist to
//! stop a stolen key from coming back:
//!
//! - **Revocations are terminal.** Once a key is revoked, no later record for
//!   it is ever accepted, and the tombstone never expires or gets swept.
//! - **Delegation marks.** The highest delegation serial seen for a key is
//!   remembered even after its records expire, so a service key retired by a
//!   newer delegation cannot publish again once the old record lapses.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use sqns_core::codec::Reader;
use sqns_core::error::{Error, Result};
use sqns_core::key::PubKey;
use sqns_core::record::{MAX_CLOCK_SKEW, SignedRecord, now_unix};

/// Snapshot file magic and format version.
const SNAPSHOT_MAGIC: &[u8; 6] = b"SQNSDB";
const SNAPSHOT_VERSION: u8 = 2;

/// What [`Store::put`] did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// Stored: this key had no record, or this one supersedes it.
    Stored,
    /// Ignored: an equal or newer record is already held.
    Stale,
}

impl PutOutcome {
    pub fn stored(self) -> bool {
        matches!(self, Self::Stored)
    }
}

/// In-memory record set with an optional on-disk snapshot.
pub struct Store {
    records: RwLock<HashMap<PubKey, SignedRecord>>,
    /// Highest delegation serial ever accepted for a key. Outlives the record
    /// it came from, so expiry cannot reopen a retired service key.
    delegation_marks: RwLock<HashMap<PubKey, u64>>,
    path: Option<PathBuf>,
    /// Bumped on every change, so the snapshot writer can skip idle intervals.
    revision: AtomicU64,
}

impl Store {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            delegation_marks: RwLock::new(HashMap::new()),
            path,
            revision: AtomicU64::new(0),
        }
    }

    /// Open a store, loading the snapshot at `path` when one exists.
    ///
    /// Records are re-verified on load: a snapshot that was tampered with on
    /// disk cannot inject anything the signing key did not sign.
    pub fn open(path: Option<PathBuf>) -> Result<Self> {
        let store = Self::new(path.clone());
        let Some(path) = path else {
            return Ok(store);
        };
        if !path.exists() {
            return Ok(store);
        }
        let bytes = fs::read(&path)?;
        // A snapshot we cannot read is not a reason to refuse to start: an
        // empty server recovers its records from peers, a dead one recovers
        // nothing.
        let (records, marks) = match decode_snapshot(&bytes) {
            Ok(loaded) => loaded,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e,
                    "ignoring unreadable snapshot; starting with no records");
                return Ok(store);
            }
        };
        store.delegation_marks.write().unwrap().extend(marks);
        let now = now_unix();
        let (mut loaded, mut dropped) = (0usize, 0usize);
        for rec in records {
            if rec.record.is_expired(now) {
                dropped += 1;
                continue;
            }
            match store.put(rec) {
                Ok(_) => loaded += 1,
                Err(e) => {
                    dropped += 1;
                    tracing::warn!(error = %e, "discarding record from snapshot");
                }
            }
        }
        tracing::info!(path = %path.display(), loaded, dropped, "snapshot loaded");
        Ok(store)
    }

    /// Verify a record and keep it if it supersedes what is held.
    pub fn put(&self, record: SignedRecord) -> Result<PutOutcome> {
        record.record.validate()?;
        record.verify()?;

        let now = now_unix();
        if record.record.issued_at > now + MAX_CLOCK_SKEW {
            return Err(Error::Record(format!(
                "record is issued {}s in the future (max skew {MAX_CLOCK_SKEW}s)",
                record.record.issued_at - now
            )));
        }
        if record.record.is_expired(now) {
            return Err(Error::Expired(now - record.record.expires_at()));
        }
        // Authority that has run out is no authority: a service key whose
        // delegation lapsed cannot publish, even though its signature is good.
        if let Some(d) = record.record.delegation()
            && d.is_expired(now)
        {
            return Err(Error::Delegation(format!(
                "delegation to {} expired {}s ago",
                d.service_key,
                now - d.not_after
            )));
        }

        let key = record.key();
        let delegation_serial = record.record.delegation_serial();

        let mut records = self.records.write().unwrap();
        let mut marks = self.delegation_marks.write().unwrap();

        // A revoked key is dead for good, whatever the record claims.
        if let Some(held) = records.get(&key)
            && let Some(revoked) = held.revocation_error()
        {
            return Err(revoked);
        }
        // A service key retired by a newer delegation stays retired, even once
        // the record that retired it has expired and been swept.
        if let Some(mark) = marks.get(&key)
            && delegation_serial < *mark
            && !record.record.is_revoked()
        {
            return Err(Error::Delegation(format!(
                "{key} has delegation {mark}; this record was signed under {delegation_serial}"
            )));
        }

        match records.get(&key) {
            Some(held) if !record.record.supersedes(&held.record) => Ok(PutOutcome::Stale),
            _ => {
                marks
                    .entry(key)
                    .and_modify(|m| *m = (*m).max(delegation_serial))
                    .or_insert(delegation_serial);
                records.insert(key, record);
                self.revision.fetch_add(1, Ordering::Relaxed);
                Ok(PutOutcome::Stored)
            }
        }
    }

    /// The record for `key`, unless it has expired.
    pub fn get(&self, key: &PubKey) -> Option<SignedRecord> {
        let now = now_unix();
        self.records
            .read()
            .unwrap()
            .get(key)
            .filter(|rec| !rec.record.is_expired(now))
            .cloned()
    }

    /// Unexpired records issued at or after `since`, oldest first.
    ///
    /// The bool is false when the batch hit `limit` and more may remain.
    pub fn since(&self, since: u64, limit: usize) -> (Vec<SignedRecord>, bool) {
        let now = now_unix();
        let records = self.records.read().unwrap();
        let mut out: Vec<SignedRecord> = records
            .values()
            .filter(|rec| rec.record.issued_at >= since && !rec.record.is_expired(now))
            .cloned()
            .collect();
        out.sort_by_key(|rec| (rec.record.issued_at, rec.key()));
        let complete = out.len() <= limit;
        out.truncate(limit);
        (out, complete)
    }

    /// Drop expired records; returns how many went.
    pub fn purge_expired(&self) -> usize {
        let now = now_unix();
        let mut records = self.records.write().unwrap();
        let before = records.len();
        records.retain(|_, rec| !rec.record.is_expired(now));
        let removed = before - records.len();
        if removed > 0 {
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    /// A counter that changes whenever the record set changes.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.records.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn snapshot_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Write the snapshot, if one is configured.
    ///
    /// The file is written beside its target and renamed into place, so a crash
    /// mid-write leaves the previous snapshot intact.
    pub fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let bytes = {
            let records = self.records.read().unwrap();
            let marks = self.delegation_marks.read().unwrap();
            encode_snapshot(records.values(), &marks)
        };

        let tmp = path.with_extension("tmp");
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn encode_snapshot<'a>(
    records: impl ExactSizeIterator<Item = &'a SignedRecord>,
    marks: &HashMap<PubKey, u64>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + records.len() * 128 + marks.len() * 40);
    buf.extend_from_slice(SNAPSHOT_MAGIC);
    buf.push(SNAPSHOT_VERSION);
    buf.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for rec in records {
        buf.extend_from_slice(&rec.encode());
    }
    // Marks are written after the records, and deliberately kept even for keys
    // whose records have lapsed.
    buf.extend_from_slice(&(marks.len() as u32).to_be_bytes());
    let mut sorted: Vec<_> = marks.iter().collect();
    sorted.sort_by_key(|(key, _)| **key);
    for (key, serial) in sorted {
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&serial.to_be_bytes());
    }
    buf
}

type Snapshot = (Vec<SignedRecord>, HashMap<PubKey, u64>);

fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    let mut r = Reader::new(bytes);
    let magic = r.bytes(SNAPSHOT_MAGIC.len(), "snapshot magic")?;
    if magic != SNAPSHOT_MAGIC {
        return Err(Error::Record("not an sqns snapshot file".into()));
    }
    let version = r.u8("snapshot version")?;
    if version != SNAPSHOT_VERSION {
        return Err(Error::Record(format!(
            "unsupported snapshot version {version} (this build writes {SNAPSHOT_VERSION})"
        )));
    }
    let count = r.u32("snapshot record count")? as usize;
    let mut records = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        records.push(SignedRecord::decode_from(&mut r)?);
    }
    let mark_count = r.u32("snapshot mark count")? as usize;
    let mut marks = HashMap::with_capacity(mark_count.min(4096));
    for _ in 0..mark_count {
        let key = PubKey::new(r.array::<32>("mark key")?);
        marks.insert(key, r.u64("mark delegation serial")?);
    }
    r.finish("snapshot")?;
    Ok((records, marks))
}
