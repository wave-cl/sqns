//! Answer cache.
//!
//! Positive answers live until the record's own expiry; "no such key" is cached
//! briefly so a burst of lookups for an unpublished key does not hammer the
//! server. Records are self-signed, so a cached answer is exactly as
//! trustworthy as a fresh one until it expires.

use std::collections::HashMap;
use std::sync::Mutex;

use sqns_core::key::PubKey;
use sqns_core::record::{SignedRecord, now_unix};

/// How long a negative answer is remembered, in seconds.
pub const NEGATIVE_TTL: u64 = 30;

#[derive(Debug, Clone)]
enum Entry {
    // Boxed: a record dwarfs the negative entry beside it.
    Found(Box<SignedRecord>),
    Missing { until: u64 },
}

/// A small TTL cache keyed by public key.
#[derive(Debug, Default)]
pub struct Cache {
    entries: Mutex<HashMap<PubKey, Entry>>,
}

impl Cache {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Some(Some(record))` on a positive hit, `Some(None)` on a cached
    /// negative, `None` when the cache cannot answer.
    pub fn get(&self, key: &PubKey) -> Option<Option<SignedRecord>> {
        let now = now_unix();
        let mut entries = self.entries.lock().unwrap();
        match entries.get(key) {
            Some(Entry::Found(rec)) if !rec.record.is_expired(now) => Some(Some((**rec).clone())),
            Some(Entry::Missing { until }) if now < *until => Some(None),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    pub fn put(&self, record: SignedRecord) {
        self.entries
            .lock()
            .unwrap()
            .insert(record.key(), Entry::Found(Box::new(record)));
    }

    pub fn put_missing(&self, key: PubKey) {
        self.entries.lock().unwrap().insert(
            key,
            Entry::Missing {
                until: now_unix() + NEGATIVE_TTL,
            },
        );
    }

    pub fn invalidate(&self, key: &PubKey) {
        self.entries.lock().unwrap().remove(key);
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    /// Drop expired entries; returns how many were removed.
    pub fn purge(&self) -> usize {
        let now = now_unix();
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|_, e| match e {
            Entry::Found(rec) => !rec.record.is_expired(now),
            Entry::Missing { until } => now < *until,
        });
        before - entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
