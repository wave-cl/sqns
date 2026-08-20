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
//! - **Retirement is terminal.** Once a key is superseded or revoked, no later
//!   record for it is ever accepted, and the tombstone never expires or gets
//!   swept.
//! - **Identity bindings.** The identity that issued a service key is pinned
//!   from that key's first record and kept for good. Only that identity can
//!   retire the key, and every later record for it must carry a delegation from
//!   it — so a thief holding the key cannot re-bind it to an identity of their
//!   own, nor drop the delegation to retire the key themselves.

use std::collections::{BTreeSet, HashMap};
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
const SNAPSHOT_VERSION: u8 = 3;

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
    /// The identity that issued each service key, pinned on first sight and
    /// kept even after the key's records expire.
    bindings: RwLock<HashMap<PubKey, PubKey>>,
    /// Reverse of `bindings`: every service key an identity has issued.
    identity_index: RwLock<HashMap<PubKey, BTreeSet<PubKey>>>,
    path: Option<PathBuf>,
    /// Bumped on every change, so the snapshot writer can skip idle intervals.
    revision: AtomicU64,
}

impl Store {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            bindings: RwLock::new(HashMap::new()),
            identity_index: RwLock::new(HashMap::new()),
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
        let (records, bindings) = match decode_snapshot(&bytes) {
            Ok(loaded) => loaded,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e,
                    "ignoring unreadable snapshot; starting with no records");
                return Ok(store);
            }
        };
        for (service_key, identity) in bindings {
            store.bind(service_key, identity);
        }
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
        let delegation = &record.record.delegation;
        if delegation.is_expired(now) && !record.record.is_terminal() {
            return Err(Error::Delegation(format!(
                "the delegation over {} from {} expired {}s ago",
                record.key(),
                delegation.identity,
                now - delegation.not_after
            )));
        }

        let key = record.key();

        let mut records = self.records.write().unwrap();

        // A retired key is finished, whatever the new record claims.
        if let Some(held) = records.get(&key)
            && let Some(retired) = retirement_error(held)
        {
            return Err(retired);
        }

        // Once a key is bound to an identity it stays bound: every later record
        // must come under a delegation from that same identity. Without this a
        // thief holding the key could simply drop the delegation and retire the
        // key itself, or re-bind it to an identity they control.
        if let Some(bound) = self.bindings.read().unwrap().get(&key).copied() {
            let identity = record.record.identity();
            if identity != bound {
                return Err(Error::Delegation(format!(
                    "{key} belongs to identity {bound}, but this record claims {identity}"
                )));
            }
        }

        match records.get(&key) {
            Some(held) if !record.record.supersedes(&held.record) => Ok(PutOutcome::Stale),
            _ => {
                let identity = record.record.identity();
                records.insert(key, record);
                drop(records);
                self.bind(key, identity);
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

    /// Pin a service key to the identity that issued it.
    fn bind(&self, service_key: PubKey, identity: PubKey) {
        self.bindings
            .write()
            .unwrap()
            .entry(service_key)
            .or_insert(identity);
        self.identity_index
            .write()
            .unwrap()
            .entry(identity)
            .or_default()
            .insert(service_key);
    }

    /// The identity that issued `service_key`, if one is known.
    pub fn identity_of(&self, service_key: &PubKey) -> Option<PubKey> {
        self.bindings.read().unwrap().get(service_key).copied()
    }

    /// Every record this server holds for keys `identity` has issued.
    ///
    /// Completeness is not something a caller can verify — a server can leave a
    /// key out — but resolution never depends on this; it is for tooling and
    /// for an operator auditing their own keys.
    pub fn identity_records(&self, identity: &PubKey, limit: usize) -> Vec<SignedRecord> {
        let index = self.identity_index.read().unwrap();
        let Some(keys) = index.get(identity) else {
            return Vec::new();
        };
        let records = self.records.read().unwrap();
        let now = now_unix();
        keys.iter()
            .filter_map(|key| records.get(key))
            .filter(|rec| !rec.record.is_expired(now))
            .take(limit)
            .cloned()
            .collect()
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
            let bindings = self.bindings.read().unwrap();
            encode_snapshot(records.values(), &bindings)
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

/// The error a held record's retirement should be reported as, if it retires
/// its key.
fn retirement_error(held: &SignedRecord) -> Option<Error> {
    if let Some(successor) = held.record.successor() {
        return Some(Error::Superseded {
            key: held.key().to_string(),
            successor: successor.to_string(),
        });
    }
    held.revocation_error()
}

fn encode_snapshot<'a>(
    records: impl ExactSizeIterator<Item = &'a SignedRecord>,
    bindings: &HashMap<PubKey, PubKey>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + records.len() * 128 + bindings.len() * 64);
    buf.extend_from_slice(SNAPSHOT_MAGIC);
    buf.push(SNAPSHOT_VERSION);
    buf.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for rec in records {
        buf.extend_from_slice(&rec.encode());
    }
    // Bindings are written after the records, and deliberately kept even for
    // keys whose records have lapsed.
    buf.extend_from_slice(&(bindings.len() as u32).to_be_bytes());
    let mut sorted: Vec<_> = bindings.iter().collect();
    sorted.sort_by_key(|(key, _)| **key);
    for (service_key, identity) in sorted {
        buf.extend_from_slice(service_key.as_bytes());
        buf.extend_from_slice(identity.as_bytes());
    }
    buf
}

type Snapshot = (Vec<SignedRecord>, HashMap<PubKey, PubKey>);

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
    let binding_count = r.u32("snapshot binding count")? as usize;
    let mut bindings = HashMap::with_capacity(binding_count.min(4096));
    for _ in 0..binding_count {
        let service_key = PubKey::new(r.array::<32>("binding service key")?);
        bindings.insert(
            service_key,
            PubKey::new(r.array::<32>("binding identity")?),
        );
    }
    r.finish("snapshot")?;
    Ok((records, bindings))
}
