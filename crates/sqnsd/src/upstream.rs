//! Asking other servers for keys this one does not hold.
//!
//! A server with upstreams configured stops being limited to what was published
//! to it: on a miss it forwards the question and relays the answer. That is
//! safe here in a way DNS recursion is not — the client verifies the record's
//! own signature, so a relaying server cannot alter an answer, substitute
//! endpoints, or invent a key. Its only power stays the one it already had:
//! withholding.
//!
//! Relayed answers are cached beside the store, never in it. They are not
//! offered in `Sync`, not persisted, and not listed under their identity, so a
//! leaf pointed upstream stays a leaf instead of quietly becoming a mirror of
//! the whole network.

use std::sync::Arc;
use std::time::Duration;

use sqns_client::Cache;
use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::key::PubKey;
use sqns_core::protocol::{Request, Response};
use sqns_core::record::{SignedRecord, now_unix};
use tokio::sync::Semaphore;

use crate::link::PeerLink;
use crate::store::Store;

/// An answer relayed from upstream.
pub struct Relayed {
    pub record: SignedRecord,
    /// The successor's record, when the answer forwards and we could fetch it.
    pub successor: Option<SignedRecord>,
}

/// Resolves keys this server does not hold by asking others.
pub struct Upstream {
    links: Vec<PeerLink>,
    cache: Option<Cache>,
    store: Arc<Store>,
    timeout: Duration,
    /// Caps how many upstream queries are in flight at once, so a slow upstream
    /// cannot pin an unbounded number of tasks.
    inflight: Semaphore,
}

impl Upstream {
    pub fn new(
        addrs: &[ServerAddr],
        store: Arc<Store>,
        client_key_hex: String,
        timeout: Duration,
        cache: bool,
        max_inflight: usize,
    ) -> Self {
        Self {
            links: addrs
                .iter()
                .map(|addr| PeerLink::new(addr.clone(), client_key_hex.clone(), timeout))
                .collect(),
            cache: cache.then(Cache::new),
            store,
            timeout,
            inflight: Semaphore::new(max_inflight.max(1)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// How many answers are held in the relay cache.
    pub fn cached(&self) -> usize {
        self.cache.as_ref().map(|c| c.len()).unwrap_or(0)
    }

    /// Drop cache entries that have expired; returns how many went.
    pub fn purge(&self) -> usize {
        self.cache.as_ref().map(|c| c.purge()).unwrap_or(0)
    }

    /// Resolve `key` upstream, forwarding with `recurse` hops remaining.
    ///
    /// `Ok(None)` means every upstream answered and none had it. An error means
    /// nobody could be reached, which is a different thing and must not be
    /// relayed as absence.
    pub async fn lookup(&self, key: &PubKey, recurse: u8) -> Result<Option<Relayed>> {
        if let Some(cache) = &self.cache {
            match cache.get(key) {
                Some(Some(record)) => {
                    let successor = self.cached_successor(&record);
                    return Ok(Some(Relayed { record, successor }));
                }
                Some(None) => return Ok(None),
                None => {}
            }
        }

        let req = Request::Lookup {
            key: *key,
            recurse,
        };
        let mut errors = Vec::new();
        let mut answered = 0usize;

        for link in &self.links {
            let permit = self.inflight.acquire().await;
            let outcome = tokio::time::timeout(self.timeout, link.request(&req)).await;
            drop(permit);

            let response = match outcome {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => {
                    errors.push(format!("{}: {e}", link.addr()));
                    continue;
                }
                Err(_) => {
                    errors.push(format!("{}: timed out", link.addr()));
                    continue;
                }
            };

            match response {
                Response::Answer { record: Some(rec), successor } => {
                    answered += 1;
                    let rec = *rec;
                    if let Err(e) = self.accept(key, &rec) {
                        tracing::warn!(upstream = %link.addr(), key = %key.short(), error = %e,
                            "refusing an upstream answer");
                        errors.push(format!("{}: {e}", link.addr()));
                        continue;
                    }
                    let successor = successor.and_then(|s| self.accept_successor(&rec, *s));
                    if let Some(cache) = &self.cache {
                        cache.put(rec.clone());
                        if let Some(s) = &successor {
                            cache.put(s.clone());
                        }
                    }
                    tracing::debug!(upstream = %link.addr(), key = %key.short(), "relayed");
                    return Ok(Some(Relayed { record: rec, successor }));
                }
                Response::Answer { record: None, .. } => answered += 1,
                Response::Error { code, message } => {
                    errors.push(format!("{}: {code:?}: {message}", link.addr()));
                }
                other => errors.push(format!("{}: unexpected {other:?}", link.addr())),
            }
        }

        // Only remember a negative when every upstream actually answered. An
        // upstream that was unreachable might have had it.
        if answered == self.links.len() {
            if let Some(cache) = &self.cache {
                cache.put_missing(*key);
            }
            return Ok(None);
        }
        if answered > 0 {
            return Ok(None);
        }
        Err(Error::Server {
            code: sqns_core::protocol::ErrorCode::UpstreamFailed as u16,
            message: format!("no upstream could answer ({})", errors.join("; ")),
        })
    }

    /// Check a relayed record before this server passes it on.
    ///
    /// The client verifies too, but a server should not relay something it has
    /// not checked itself — and it holds one piece of context the client may
    /// lack: which identity this key was first bound to.
    fn accept(&self, key: &PubKey, record: &SignedRecord) -> Result<()> {
        record.verify_answer(key, now_unix())?;
        if let Some(bound) = self.store.identity_of(key)
            && record.identity() != bound
        {
            return Err(Error::Delegation(format!(
                "{key} is bound to identity {bound} here, but upstream answered for {}",
                record.identity()
            )));
        }
        Ok(())
    }

    /// Validate the successor record that came with a forwarding answer.
    fn accept_successor(
        &self,
        record: &SignedRecord,
        successor: SignedRecord,
    ) -> Option<SignedRecord> {
        let expected = record.record.successor()?;
        if successor.key() != expected {
            return None;
        }
        self.accept(&expected, &successor).ok().map(|_| successor)
    }

    /// The successor for a cached tombstone, if it happens to be cached too.
    fn cached_successor(&self, record: &SignedRecord) -> Option<SignedRecord> {
        let next = record.record.successor()?;
        self.cache.as_ref()?.get(&next).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqns_core::key;
    use sqns_core::record::{Delegation, Endpoint, Host, Record};
    use std::net::Ipv4Addr;

    fn service_record(identity: &ed25519_dalek::SigningKey, service: &ed25519_dalek::SigningKey) -> SignedRecord {
        let delegation = Delegation::issue(
            identity,
            &key::public_of(service),
            now_unix() + 86_400,
        );
        Record::live(
            key::public_of(service),
            delegation,
            1,
            300,
            vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 5300)],
        )
        .sign(service)
        .unwrap()
    }

    /// An Upstream with no links: enough to exercise the checks that run before
    /// anything is relayed.
    fn checker(store: Arc<Store>) -> Upstream {
        Upstream::new(&[], store, String::new(), Duration::from_secs(1), true, 4)
    }

    #[test]
    fn an_answer_for_the_wrong_key_is_refused() {
        let up = checker(Arc::new(Store::new(None)));
        let record = service_record(&key::generate(), &key::generate());
        let someone_else = key::public_of(&key::generate());

        assert!(up.accept(&record.key(), &record).is_ok());
        assert!(
            up.accept(&someone_else, &record).is_err(),
            "a server must not relay an answer to a question nobody asked"
        );
    }

    /// The one check a relaying server can make that its clients cannot: it
    /// knows which identity this key was first bound to here.
    #[test]
    fn an_answer_contradicting_a_local_binding_is_refused() {
        let store = Arc::new(Store::new(None));
        let identity = key::generate();
        let service = key::generate();
        store.put(service_record(&identity, &service)).unwrap();

        let up = checker(Arc::clone(&store));
        let key = key::public_of(&service);

        // The same service key, re-issued by somebody else's identity.
        let reissued = service_record(&key::generate(), &service);
        let err = up.accept(&key, &reissued).unwrap_err();
        assert!(matches!(err, Error::Delegation(_)), "{err}");

        // The genuine one still passes.
        assert!(up.accept(&key, &service_record(&identity, &service)).is_ok());
    }

    #[test]
    fn a_tampered_answer_is_refused() {
        let up = checker(Arc::new(Store::new(None)));
        let mut record = service_record(&key::generate(), &key::generate());
        if let sqns_core::record::RecordBody::Live { endpoints } = &mut record.record.body {
            endpoints[0].port = 31337;
        }
        assert!(up.accept(&record.key(), &record).is_err());
    }

    #[tokio::test]
    async fn with_no_upstreams_every_lookup_is_a_clean_miss() {
        let up = checker(Arc::new(Store::new(None)));
        let key = key::public_of(&key::generate());
        assert!(up.lookup(&key, 4).await.unwrap().is_none());
        assert_eq!(up.cached(), 1, "a definite miss is worth remembering");
    }
}
