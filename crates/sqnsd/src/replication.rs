//! Replication between sqns servers.
//!
//! Peers exchange whole signed records, so replication needs no trust between
//! servers: a peer that alters a record breaks its signature, and a peer that
//! replays an old one loses to the higher serial already held. Two mechanisms
//! run together — a push as soon as a record is accepted, for latency, and a
//! periodic anti-entropy pull, for anything a push missed.

use std::sync::Arc;
use std::time::Duration;

use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::protocol::{MAX_SYNC_BATCH, Request, Response};
use sqns_core::record::SignedRecord;
use tokio::sync::Mutex;

use crate::link::PeerLink;
use crate::store::Store;

/// A replication peer and how far through its records we have got.
struct Peer {
    link: PeerLink,
    /// Highest `issued_at` pulled so far; the next pull starts here.
    watermark: Mutex<u64>,
}

/// Pushes accepted records to peers and pulls theirs on a timer.
pub struct Replicator {
    peers: Vec<Peer>,
    store: Arc<Store>,
    sync_interval: Duration,
}

impl Replicator {
    pub fn new(
        peers: &[ServerAddr],
        store: Arc<Store>,
        client_key_hex: String,
        sync_interval: Duration,
    ) -> Self {
        Self {
            peers: peers
                .iter()
                .map(|addr| Peer {
                    link: PeerLink::new(
                        addr.clone(),
                        client_key_hex.clone(),
                        Duration::from_secs(10),
                    ),
                    watermark: Mutex::new(0),
                })
                .collect(),
            store,
            sync_interval,
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Forward a freshly accepted record to every peer.
    ///
    /// Failures are logged, not retried: the next anti-entropy pull picks up
    /// whatever a push could not deliver.
    pub async fn push(&self, record: SignedRecord) {
        if self.peers.is_empty() {
            return;
        }
        let req = Request::Publish {
            record: Box::new(record.clone()),
        };
        for peer in &self.peers {
            match peer.link.request(&req).await {
                Ok(Response::Published { .. }) => {
                    tracing::debug!(peer = %peer.link.addr(), key = %record.key().short(), "pushed");
                }
                // The peer already has this record or something newer.
                Ok(Response::Error { code, .. }) => {
                    tracing::trace!(peer = %peer.link.addr(), ?code, "push not applied");
                }
                Ok(other) => {
                    tracing::debug!(peer = %peer.link.addr(), ?other, "unexpected push response");
                }
                Err(e) => tracing::debug!(peer = %peer.link.addr(), error = %e, "push failed"),
            }
        }
    }

    /// Pull from every peer, forever.
    pub async fn run(self: Arc<Self>) {
        if self.peers.is_empty() {
            return;
        }
        let mut ticker = tokio::time::interval(self.sync_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for peer in &self.peers {
                match self.pull(peer).await {
                    Ok(0) => tracing::trace!(peer = %peer.link.addr(), "in sync"),
                    Ok(n) => tracing::info!(peer = %peer.link.addr(), records = n, "pulled records"),
                    Err(e) => tracing::warn!(peer = %peer.link.addr(), error = %e, "sync failed"),
                }
            }
        }
    }

    /// Pull everything a peer has issued since our watermark. Returns how many
    /// records were new to us.
    async fn pull(&self, peer: &Peer) -> Result<usize> {
        let mut since = *peer.watermark.lock().await;
        let mut applied = 0usize;

        loop {
            let req = Request::Sync {
                since,
                limit: MAX_SYNC_BATCH,
            };
            let (records, complete) = match peer.link.request(&req).await? {
                Response::Records { records, complete } => (records, complete),
                other @ Response::Error { .. } => return Err(other.into_server_error()),
                other => {
                    return Err(Error::Protocol(format!("unexpected sync response: {other:?}")));
                }
            };

            let batch_high = records
                .iter()
                .map(|rec| rec.record.issued_at)
                .max()
                .unwrap_or(since);

            for rec in records {
                let key = rec.key();
                match self.store.put(rec) {
                    Ok(outcome) if outcome.stored() => applied += 1,
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(peer = %peer.link.addr(), key = %key.short(), error = %e,
                            "rejected record from peer");
                    }
                }
            }

            *peer.watermark.lock().await = batch_high;
            if complete {
                break;
            }
            if batch_high <= since {
                // More records remain but they all share our cursor's second,
                // so another pull would return the same batch.
                tracing::warn!(peer = %peer.link.addr(), since,
                    "sync batch full with no cursor progress; remaining records deferred");
                break;
            }
            since = batch_high;
        }
        Ok(applied)
    }

}
