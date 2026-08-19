//! The record store: verify, merge, persist.
//!
//! The store is the only place records enter the server, and every path in —
//! a client publishing, a peer replicating, a snapshot loading from disk —
//! goes through [`Store::put`], which verifies the signature before the record
//! is kept. A record is accepted only if it beats the one already held, which
//! makes replication order-independent and replay-safe.

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
const SNAPSHOT_VERSION: u8 = 1;

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
    path: Option<PathBuf>,
    /// Bumped on every change, so the snapshot writer can skip idle intervals.
    revision: AtomicU64,
}

impl Store {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
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
        let records = decode_snapshot(&bytes)?;
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

        let mut records = self.records.write().unwrap();
        match records.get(&record.key()) {
            Some(held) if !record.record.supersedes(&held.record) => Ok(PutOutcome::Stale),
            _ => {
                records.insert(record.key(), record);
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
            encode_snapshot(records.values())
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

fn encode_snapshot<'a>(records: impl ExactSizeIterator<Item = &'a SignedRecord>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + records.len() * 128);
    buf.extend_from_slice(SNAPSHOT_MAGIC);
    buf.push(SNAPSHOT_VERSION);
    buf.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for rec in records {
        buf.extend_from_slice(&rec.encode());
    }
    buf
}

fn decode_snapshot(bytes: &[u8]) -> Result<Vec<SignedRecord>> {
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
    let mut out = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        out.push(SignedRecord::decode_from(&mut r)?);
    }
    r.finish("snapshot")?;
    Ok(out)
}
