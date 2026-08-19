//! The resolver: look up keys, publish records, talk to several servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::key::PubKey;
use sqns_core::protocol::{ErrorCode, Request, Response, StatusInfo};
use sqns_core::record::{Endpoint, Record, SignedRecord, now_unix};
use tokio::sync::Mutex;

use crate::cache::Cache;
use crate::conn;
use crate::select::order_endpoints;

/// How a [`Resolver`] reaches its servers.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Servers to query, in preference order.
    pub servers: Vec<ServerAddr>,
    /// Hex Ed25519 seed for this caller's stable sQUIC identity. Needed when a
    /// server whitelists clients.
    pub client_key_hex: Option<String>,
    /// Handshake timeout per server.
    pub connect_timeout: Duration,
    /// Cache answers until they expire.
    pub cache: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            client_key_hex: None,
            connect_timeout: Duration::from_secs(10),
            cache: true,
        }
    }
}

impl ResolverConfig {
    pub fn with_client_key(mut self, sk: &SigningKey) -> Self {
        self.client_key_hex = Some(hex_seed(sk));
        self
    }
}

/// Hex encoding of a signing key's seed, as sQUIC's `client_key` wants it.
pub fn hex_seed(sk: &SigningKey) -> String {
    sk.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Where an identity currently lives, and which key to pin when dialing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLocation {
    /// The key that was looked up. This never changes across a rotation.
    pub identity: PubKey,
    /// The key to pin for the sQUIC handshake — the delegated service key, or
    /// the identity itself when the record carries no delegation.
    pub service_key: PubKey,
    /// Endpoints in the order they should be tried.
    pub endpoints: Vec<Endpoint>,
    /// Authority version. A higher value means the identity has rotated its
    /// service key since; callers that pin a key should update on a change.
    pub delegation_serial: u64,
}

impl ServiceLocation {
    /// True when the key to dial differs from the key that was looked up.
    pub fn is_delegated(&self) -> bool {
        self.service_key != self.identity
    }
}

/// How authoritative a record is, for spotting a server walking one backwards.
///
/// Ordered revocation-first, so a revocation outranks every live record and a
/// server can never follow one with anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    revoked: bool,
    delegation_serial: u64,
    serial: u64,
}

impl Rank {
    fn of(record: &Record) -> Self {
        Self {
            revoked: record.is_revoked(),
            delegation_serial: record.delegation_serial(),
            serial: record.serial,
        }
    }
}

/// Resolves public keys to endpoints, and publishes records.
///
/// Connections are kept open and reused; a server that fails is re-dialed on
/// the next request.
pub struct Resolver {
    config: ResolverConfig,
    conns: Vec<Mutex<Option<quinn::Connection>>>,
    cache: Arc<Cache>,
    /// Highest authority seen per identity, kept whether or not answers are
    /// cached. A server that replays an older record — a stale delegation, or a
    /// live record after a revocation — is refused here.
    marks: StdMutex<HashMap<PubKey, Rank>>,
}

impl Resolver {
    pub fn new(config: ResolverConfig) -> Result<Self> {
        if config.servers.is_empty() {
            return Err(Error::NoServer("no sqns servers configured".into()));
        }
        let conns = config.servers.iter().map(|_| Mutex::new(None)).collect();
        Ok(Self {
            config,
            conns,
            cache: Arc::new(Cache::new()),
            marks: StdMutex::new(HashMap::new()),
        })
    }

    /// Build a resolver for a single server.
    pub fn single(server: ServerAddr) -> Result<Self> {
        Self::new(ResolverConfig {
            servers: vec![server],
            ..Default::default()
        })
    }

    pub fn servers(&self) -> &[ServerAddr] {
        &self.config.servers
    }

    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// Fetch the record for `key`, or `None` if no server holds one.
    ///
    /// Every answer is signature-checked against `key` before it is returned or
    /// cached, so a server can withhold an answer but never fabricate one.
    pub async fn lookup(&self, key: &PubKey) -> Result<Option<SignedRecord>> {
        if self.config.cache && let Some(hit) = self.cache.get(key) {
            return Ok(hit);
        }
        let response = self
            .try_servers(Request::Lookup { key: *key }, "lookup")
            .await?;
        match response {
            Response::Answer { record: Some(rec) } => {
                let rec = *rec;
                rec.verify_answer(key, now_unix())?;
                self.note_rank(&rec)?;
                if self.config.cache {
                    self.cache.put(rec.clone());
                }
                Ok(Some(rec))
            }
            Response::Answer { record: None } => {
                if self.config.cache {
                    self.cache.put_missing(*key);
                }
                Ok(None)
            }
            other => Err(unexpected(other)),
        }
    }

    /// Record the authority of an answer, refusing anything below what this
    /// resolver has already seen for the same key.
    fn note_rank(&self, record: &SignedRecord) -> Result<()> {
        let rank = Rank::of(&record.record);
        let mut marks = self.marks.lock().unwrap();
        match marks.get(&record.key()) {
            Some(seen) if rank < *seen => Err(Error::Downgrade(record.key().to_string())),
            _ => {
                marks.insert(record.key(), rank);
                Ok(())
            }
        }
    }

    /// Like [`lookup`], but refuses a revoked key.
    ///
    /// [`lookup`] hands back the tombstone so a caller can show it; anything
    /// that intends to *connect* should come through here, so a dead identity
    /// is an error rather than an empty endpoint list.
    ///
    /// [`lookup`]: Resolver::lookup
    pub async fn lookup_live(&self, key: &PubKey) -> Result<Option<SignedRecord>> {
        let record = self.lookup(key).await?;
        if let Some(rec) = &record
            && let Some(revoked) = rec.revocation_error()
        {
            return Err(revoked);
        }
        Ok(record)
    }

    /// Where `key` lives and which key to pin when dialing it.
    ///
    /// Rotating the service key is invisible here beyond the returned
    /// `service_key` changing: the identity that was looked up stays the same,
    /// so callers keep resolving the key they already had.
    pub async fn resolve_service(&self, key: &PubKey) -> Result<ServiceLocation> {
        match self.lookup_live(key).await? {
            Some(rec) => Ok(ServiceLocation {
                identity: rec.key(),
                service_key: rec.service_key(),
                endpoints: order_endpoints(&rec.record),
                delegation_serial: rec.record.delegation_serial(),
            }),
            None => Err(Error::Unpublished(key.to_string())),
        }
    }

    /// Endpoints for `key`, in the order they should be tried.
    ///
    /// Returns [`Error::Unpublished`] when no server holds a record, and
    /// [`Error::Revoked`] when the key is dead. A record that exists but lists
    /// no endpoints is a deliberate withdrawal and yields an empty vector.
    pub async fn resolve(&self, key: &PubKey) -> Result<Vec<Endpoint>> {
        Ok(self.resolve_service(key).await?.endpoints)
    }

    /// Publish a signed record to every configured server.
    ///
    /// Succeeds if at least one server accepts it; the returned serial is the
    /// record's own. Per-server failures are logged, not fatal — replication
    /// carries the record to servers that were down.
    pub async fn publish(&self, record: &SignedRecord) -> Result<u64> {
        // The same checks a client applies to an answer, so a record that
        // could never be accepted fails here rather than on every server.
        record.verify_answer(&record.key(), now_unix())?;
        let req = Request::Publish {
            record: Box::new(record.clone()),
        };

        let mut accepted = None;
        let mut errors = Vec::new();
        // A record refused everywhere purely as stale is reported as such, so a
        // publisher can bump its serial and try again instead of giving up.
        let mut stale_only = true;
        for (idx, server) in self.config.servers.iter().enumerate() {
            match self.request_server(idx, &req).await {
                Ok(Response::Published { serial, .. }) => {
                    tracing::debug!(server = %server, serial, "record published");
                    accepted = Some(serial);
                }
                Ok(other) => {
                    stale_only &= matches!(
                        other,
                        Response::Error {
                            code: ErrorCode::Stale,
                            ..
                        }
                    );
                    errors.push(format!("{server}: {}", describe(other)));
                }
                Err(e) => {
                    stale_only = false;
                    errors.push(format!("{server}: {e}"));
                }
            }
        }
        self.cache.invalidate(&record.key());
        match accepted {
            Some(serial) => Ok(serial),
            None if stale_only && !errors.is_empty() => Err(Error::Server {
                code: ErrorCode::Stale as u16,
                message: errors.join("; "),
            }),
            None => Err(Error::NoServer(format!(
                "no server accepted the record ({})",
                errors.join("; ")
            ))),
        }
    }

    /// Counters from the first server that answers.
    pub async fn status(&self) -> Result<StatusInfo> {
        match self.try_servers(Request::Status, "status").await? {
            Response::Status(info) => Ok(info),
            other => Err(unexpected(other)),
        }
    }

    /// Send a request to each server in turn, returning the first answer.
    async fn try_servers(&self, req: Request, what: &str) -> Result<Response> {
        let mut errors = Vec::new();
        for (idx, server) in self.config.servers.iter().enumerate() {
            match self.request_server(idx, &req).await {
                Ok(Response::Error { code, message }) => {
                    errors.push(format!("{server}: server error {code:?}: {message}"));
                }
                Ok(resp) => return Ok(resp),
                Err(e) => errors.push(format!("{server}: {e}")),
            }
        }
        Err(Error::NoServer(format!(
            "{what} failed on every server ({})",
            errors.join("; ")
        )))
    }

    /// Request against one server, re-dialing once if the pooled connection is
    /// stale.
    async fn request_server(&self, idx: usize, req: &Request) -> Result<Response> {
        let mut slot = self.conns[idx].lock().await;
        if let Some(conn) = slot.as_ref() {
            match conn::exchange(conn, req).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(server = %self.config.servers[idx], error = %e, "re-dialing");
                    *slot = None;
                }
            }
        }
        let conn = conn::connect(
            &self.config.servers[idx],
            self.config.client_key_hex.clone(),
            self.config.connect_timeout,
        )
        .await?;
        let resp = conn::exchange(&conn, req).await?;
        *slot = Some(conn);
        Ok(resp)
    }
}

fn describe(resp: Response) -> String {
    match resp {
        Response::Error { code, message } => format!("server error {code:?}: {message}"),
        other => format!("unexpected response: {other:?}"),
    }
}

fn unexpected(resp: Response) -> Error {
    match resp {
        Response::Error { .. } => resp.into_server_error(),
        other => Error::Protocol(format!("unexpected response: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqns_core::key::{generate, public_of};
    use sqns_core::record::{Delegation, Host, Record};
    use std::net::Ipv4Addr;

    /// A resolver pointed at an address it never dials — enough to exercise the
    /// downgrade guard, which runs before any answer is trusted.
    fn offline_resolver() -> Resolver {
        let key = public_of(&generate());
        Resolver::single(ServerAddr::new("127.0.0.1", 1, key)).expect("resolver")
    }

    fn endpoints() -> Vec<Endpoint> {
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 5300)]
    }

    #[test]
    fn a_server_cannot_walk_a_delegation_backwards() {
        let resolver = offline_resolver();
        let identity = generate();
        let old_service = generate();
        let new_service = generate();
        let id_pub = public_of(&identity);
        let now = now_unix();

        let d1 = Delegation::issue(&identity, public_of(&old_service), 1, now + 86_400).unwrap();
        let d2 = Delegation::issue(&identity, public_of(&new_service), 2, now + 86_400).unwrap();
        let under_d1 = Record::delegated(id_pub, 5, 300, d1, endpoints())
            .sign(&old_service)
            .unwrap();
        let under_d2 = Record::delegated(id_pub, 1, 300, d2, endpoints())
            .sign(&new_service)
            .unwrap();

        resolver.note_rank(&under_d2).expect("first answer is accepted");

        // Both records are properly signed; the older authority is still a
        // downgrade, even though its record serial is higher.
        let err = resolver.note_rank(&under_d1).unwrap_err();
        assert!(matches!(err, Error::Downgrade(_)), "{err}");

        // Re-seeing the current answer is fine.
        resolver.note_rank(&under_d2).expect("same rank is not a downgrade");
    }

    #[test]
    fn a_server_cannot_follow_a_revocation_with_a_live_record() {
        let resolver = offline_resolver();
        let identity = generate();
        let id_pub = public_of(&identity);

        let revocation = Record::revoked(id_pub, 1, None, "stolen")
            .sign(&identity)
            .unwrap();
        let live = Record::live(id_pub, u64::MAX, 300, endpoints())
            .sign(&identity)
            .unwrap();

        resolver.note_rank(&revocation).expect("revocation accepted");
        let err = resolver.note_rank(&live).unwrap_err();
        assert!(matches!(err, Error::Downgrade(_)), "{err}");
    }

    #[test]
    fn an_ordinary_refresh_is_not_a_downgrade() {
        let resolver = offline_resolver();
        let node = generate();
        let key = public_of(&node);

        for serial in 1..5 {
            let record = Record::live(key, serial, 300, endpoints()).sign(&node).unwrap();
            resolver.note_rank(&record).expect("serials only go up");
        }
    }
}
