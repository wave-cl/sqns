//! Self-registration: sign your own endpoint set and keep it refreshed.
//!
//! A node holds the private key that its record speaks for, so it is the only
//! party that can publish or change that record. Records expire, so a node that
//! goes away stops being advertised without anyone having to retract it — the
//! publisher re-signs on a timer well inside the TTL.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqns_core::error::{Error, Result};
use sqns_core::protocol::ErrorCode;
use sqns_core::key::{PubKey, public_of};
use sqns_core::record::{Endpoint, Record, SignedRecord, now_unix};

use crate::resolver::Resolver;

/// Default record lifetime, in seconds.
pub const DEFAULT_TTL: u32 = 300;

/// Publishes and refreshes the record for one key.
pub struct Publisher {
    signing_key: SigningKey,
    endpoints: Vec<Endpoint>,
    ttl: u32,
    serial: AtomicU64,
}

impl Publisher {
    /// The serial starts at the current wall-clock second, so a record signed
    /// after a restart still supersedes whatever the network already holds.
    pub fn new(signing_key: SigningKey, endpoints: Vec<Endpoint>, ttl: u32) -> Self {
        Self {
            signing_key,
            endpoints,
            ttl,
            serial: AtomicU64::new(now_unix()),
        }
    }

    pub fn key(&self) -> PubKey {
        public_of(&self.signing_key)
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// How often the record should be re-published: a third of its TTL, so two
    /// refreshes can be lost before the record lapses.
    pub fn refresh_interval(&self) -> Duration {
        Duration::from_secs((self.ttl as u64 / 3).max(10))
    }

    /// Sign a fresh record, taking the next serial.
    pub fn build(&self) -> Result<SignedRecord> {
        self.sign(self.endpoints.clone())
    }

    fn sign(&self, endpoints: Vec<Endpoint>) -> Result<SignedRecord> {
        let serial = self.serial.fetch_add(1, Ordering::SeqCst);
        let record = Record::new(self.key(), serial, self.ttl, endpoints);
        record.validate()?;
        record.sign(&self.signing_key)
    }

    /// Sign and publish once.
    pub async fn publish(&self, resolver: &Resolver) -> Result<u64> {
        self.publish_endpoints(resolver, self.endpoints.clone())
            .await
    }

    /// Withdraw the key: publish a record with no endpoints, so lookups get a
    /// definite "deliberately unreachable" rather than a stale address.
    pub async fn withdraw(&self, resolver: &Resolver) -> Result<u64> {
        self.publish_endpoints(resolver, Vec::new()).await
    }

    /// Publish an endpoint set, raising the serial past whatever the network
    /// already holds if the first attempt is refused as stale.
    ///
    /// Serials start from the wall clock, so two publishes inside the same
    /// second — or a restart that rewinds nothing — would otherwise tie and be
    /// refused. Only the key holder can sign, so it is always right for them to
    /// win.
    async fn publish_endpoints(
        &self,
        resolver: &Resolver,
        endpoints: Vec<Endpoint>,
    ) -> Result<u64> {
        match resolver.publish(&self.sign(endpoints.clone())?).await {
            Err(Error::Server { code, .. }) if code == ErrorCode::Stale as u16 => {
                self.adopt_network_serial(resolver).await?;
                resolver.publish(&self.sign(endpoints)?).await
            }
            other => other,
        }
    }

    /// Raise the serial counter above the record the network currently holds.
    async fn adopt_network_serial(&self, resolver: &Resolver) -> Result<()> {
        if let Some(held) = resolver.lookup(&self.key()).await? {
            self.serial
                .fetch_max(held.record.serial.saturating_add(1), Ordering::SeqCst);
        }
        Ok(())
    }

    /// Publish now, then keep republishing every [`refresh_interval`] until the
    /// task is dropped. Transient failures are logged and retried on the next
    /// tick rather than ending the loop.
    ///
    /// [`refresh_interval`]: Publisher::refresh_interval
    pub async fn run(self: Arc<Self>, resolver: Arc<Resolver>) {
        let mut ticker = tokio::time::interval(self.refresh_interval());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match self.publish(&resolver).await {
                Ok(serial) => {
                    tracing::debug!(key = %self.key().short(), serial, "record refreshed")
                }
                Err(e) => tracing::warn!(key = %self.key().short(), error = %e, "refresh failed"),
            }
        }
    }
}
