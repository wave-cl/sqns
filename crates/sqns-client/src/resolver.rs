//! The resolver: look up keys, publish records, talk to several servers.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::key::PubKey;
use sqns_core::protocol::{DEFAULT_RECURSE, ErrorCode, Request, Response, StatusInfo};
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
    /// How many hops a lookup may be forwarded through by servers that do not
    /// hold the key. Zero asks each server for what it holds itself.
    pub recurse: u8,
    /// Whether an `sqns://` address must resolve through a validated DNSSEC
    /// chain. Turning this off is what `--insecure-dns` does.
    pub require_dnssec: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            client_key_hex: None,
            connect_timeout: Duration::from_secs(10),
            cache: true,
            recurse: DEFAULT_RECURSE,
            require_dnssec: true,
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

/// Most supersede hops a lookup will follow before giving up.
pub const MAX_SUPERSEDE_HOPS: usize = 8;

/// Where a service key currently lives, after following any rotations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLocation {
    /// The key the caller asked for.
    pub requested: PubKey,
    /// The key actually reached, and the one to pin for the sQUIC handshake.
    /// It differs from `requested` when the key has been rotated.
    pub key: PubKey,
    /// The identity that issued `key`.
    pub identity: PubKey,
    /// Endpoints in the order they should be tried.
    pub endpoints: Vec<Endpoint>,
    /// Keys walked through to get here, oldest first. Empty when the requested
    /// key answered directly.
    pub superseded_from: Vec<PubKey>,
}

impl ServiceLocation {
    /// True when the caller's key has been rotated and its pinned copy is out
    /// of date.
    pub fn is_stale(&self) -> bool {
        self.key != self.requested
    }
}

/// How authoritative a record is, for spotting a server walking one backwards.
///
/// Ordered terminal-first, so a retirement outranks every live record and a
/// server can never follow one with anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    terminal: bool,
    serial: u64,
}

impl Rank {
    fn of(record: &Record) -> Self {
        Self {
            terminal: record.is_terminal(),
            serial: record.serial,
        }
    }
}

/// What this resolver has already established about a key.
#[derive(Debug, Clone, Copy)]
struct Seen {
    rank: Rank,
    /// The identity behind the key. It must never change: a key that suddenly
    /// answers to someone else is a thief who minted their own delegation, not
    /// a rotation. Rotation moves to a *different* key and says so.
    identity: PubKey,
}

/// Resolves public keys to endpoints, and publishes records.
///
/// Connections are kept open and reused; a server that fails is re-dialed on
/// the next request.
pub struct Resolver {
    config: ResolverConfig,
    conns: Vec<Mutex<Option<quinn::Connection>>>,
    cache: Arc<Cache>,
    /// What has been established about each key, kept whether or not answers
    /// are cached. A server that replays an older record, or hands back one
    /// answering to a different identity, is refused here.
    marks: StdMutex<HashMap<PubKey, Seen>>,
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
        Ok(self.fetch(key).await?.0)
    }

    /// The record for `key`, plus the successor's record when the answer
    /// forwards — the server sends both, which spares a round trip per hop.
    ///
    /// The successor is returned unverified; it is checked against the key the
    /// tombstone actually names before it is used.
    async fn fetch(&self, key: &PubKey) -> Result<(Option<SignedRecord>, Option<SignedRecord>)> {
        if self.config.cache && let Some(hit) = self.cache.get(key) {
            return Ok((hit, None));
        }
        let response = self
            .try_servers(
                Request::Lookup {
                    key: *key,
                    recurse: self.config.recurse,
                },
                "lookup",
            )
            .await?;
        match response {
            Response::Answer {
                record: Some(rec),
                successor,
            } => {
                let rec = *rec;
                rec.verify_answer(key, now_unix())?;
                self.note_rank(&rec)?;
                if self.config.cache {
                    self.cache.put(rec.clone());
                }
                Ok((Some(rec), successor.map(|s| *s)))
            }
            Response::Answer { record: None, .. } => {
                if self.config.cache {
                    self.cache.put_missing(*key);
                }
                Ok((None, None))
            }
            other => Err(unexpected(other)),
        }
    }

    /// Record what an answer establishes about a key, refusing anything that
    /// contradicts what this resolver has already seen for it.
    fn note_rank(&self, record: &SignedRecord) -> Result<()> {
        let seen = Seen {
            rank: Rank::of(&record.record),
            identity: record.identity(),
        };
        let key = record.key();
        let mut marks = self.marks.lock().unwrap();
        if let Some(before) = marks.get(&key) {
            if before.identity != seen.identity {
                return Err(Error::Delegation(format!(
                    "{key} was issued by {}, but this answer claims {}",
                    before.identity, seen.identity
                )));
            }
            if seen.rank < before.rank {
                return Err(Error::Downgrade(key.to_string()));
            }
        }
        marks.insert(key, seen);
        Ok(())
    }

    /// Like [`lookup`], but refuses a key that has been retired.
    ///
    /// [`lookup`] hands back the tombstone so a caller can show it; anything
    /// that intends to *connect* should come through here or
    /// [`resolve_service`], so a dead key is an error rather than an empty
    /// endpoint list.
    ///
    /// [`lookup`]: Resolver::lookup
    /// [`resolve_service`]: Resolver::resolve_service
    pub async fn lookup_live(&self, key: &PubKey) -> Result<Option<SignedRecord>> {
        let record = self.lookup(key).await?;
        if let Some(rec) = &record {
            retirement_error(rec).map_or(Ok(()), Err)?;
        }
        Ok(record)
    }

    /// Where `key` lives, following any rotations along the way.
    ///
    /// A key that has been superseded forwards to its replacement, and the
    /// returned location names the key actually reached — pin that one. Every
    /// hop is verified against the key the previous record named, the walk is
    /// capped at [`MAX_SUPERSEDE_HOPS`], and a cycle is an error rather than a
    /// spin.
    pub async fn resolve_service(&self, key: &PubKey) -> Result<ServiceLocation> {
        let mut current = *key;
        let mut visited = HashSet::from([current]);
        let mut chain = Vec::new();
        // A successor record the server already handed us, saving a round trip.
        let mut prefetched: Option<SignedRecord> = None;

        for _ in 0..MAX_SUPERSEDE_HOPS {
            let (record, successor) = match prefetched.take() {
                Some(rec) => (Some(rec), None),
                None => self.fetch(&current).await?,
            };
            let Some(record) = record else {
                return Err(Error::Unpublished(current.to_string()));
            };
            if let Some(revoked) = record.revocation_error() {
                return Err(revoked);
            }

            let Some(next) = record.record.successor() else {
                return Ok(ServiceLocation {
                    requested: *key,
                    key: record.key(),
                    identity: record.identity(),
                    endpoints: order_endpoints(&record.record),
                    superseded_from: chain,
                });
            };

            if !visited.insert(next) {
                return Err(Error::SupersedeChain(format!(
                    "{key} forwards in a cycle, back to {next}"
                )));
            }
            chain.push(current);

            // Use the inline successor only if it is really the record for the
            // key this tombstone named.
            if let Some(candidate) = successor
                && candidate.key() == next
                && candidate.verify_answer(&next, now_unix()).is_ok()
                && self.note_rank(&candidate).is_ok()
            {
                if self.config.cache {
                    self.cache.put(candidate.clone());
                }
                prefetched = Some(candidate);
            }
            current = next;
        }

        Err(Error::SupersedeChain(format!(
            "{key} forwards through more than {MAX_SUPERSEDE_HOPS} keys"
        )))
    }

    /// Every record this server holds for keys `identity` has issued.
    ///
    /// A server can leave a key out, so this is for tooling and auditing, not
    /// for resolution — which never depends on it.
    pub async fn lookup_identity(&self, identity: &PubKey) -> Result<Vec<SignedRecord>> {
        let response = self
            .try_servers(
                Request::LookupIdentity {
                    identity: *identity,
                },
                "identity lookup",
            )
            .await?;
        match response {
            Response::Records { records, .. } => {
                let now = now_unix();
                let mut out = Vec::with_capacity(records.len());
                for rec in records {
                    // Each record still has to stand on its own signature, and
                    // really be issued by the identity we asked about.
                    let key = rec.key();
                    rec.verify_answer(&key, now)?;
                    if rec.identity() != *identity {
                        return Err(Error::Delegation(format!(
                            "{key} was listed under {identity} but is not issued by it"
                        )));
                    }
                    out.push(rec);
                }
                Ok(out)
            }
            other => Err(unexpected(other)),
        }
    }

    /// Endpoints for `key`, in the order they should be tried.
    ///
    /// Follows rotations, so this returns the endpoints of whatever key the
    /// requested one now points at. Use [`resolve_service`] when the caller
    /// needs to know that the key changed.
    ///
    /// Returns [`Error::Unpublished`] when no server holds a record, and
    /// [`Error::Revoked`] when the key is dead. A record that exists but lists
    /// no endpoints is a deliberate withdrawal and yields an empty vector.
    ///
    /// [`resolve_service`]: Resolver::resolve_service
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
        let conn = conn::connect_with(
            &self.config.servers[idx],
            self.config.client_key_hex.clone(),
            self.config.connect_timeout,
            self.config.require_dnssec,
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

/// The error a retired key should be reported as, if it is one.
pub fn retirement_error(record: &SignedRecord) -> Option<Error> {
    if let Some(successor) = record.record.successor() {
        return Some(Error::Superseded {
            key: record.key().to_string(),
            successor: successor.to_string(),
        });
    }
    record.revocation_error()
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
    use ed25519_dalek::SigningKey;
    use sqns_core::key::{generate, public_of};
    use sqns_core::record::{Delegation, Host, Record};
    use std::net::Ipv4Addr;

    /// A service key and the identity that issued it.
    struct Service {
        identity: SigningKey,
        key: SigningKey,
        delegation: Delegation,
    }

    impl Service {
        fn new() -> Self {
            let identity = generate();
            let key = generate();
            let delegation =
                Delegation::issue(&identity, &public_of(&key), now_unix() + 86_400);
            Self {
                identity,
                key,
                delegation,
            }
        }

        fn pubkey(&self) -> PubKey {
            public_of(&self.key)
        }

        fn live(&self, serial: u64) -> SignedRecord {
            Record::live(
                self.pubkey(),
                self.delegation.clone(),
                serial,
                300,
                vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 5300)],
            )
            .sign(&self.key)
            .unwrap()
        }

        fn revoked(&self, serial: u64) -> SignedRecord {
            Record::revoked(self.pubkey(), self.delegation.clone(), serial, "stolen")
                .sign(&self.identity)
                .unwrap()
        }

        fn superseded(&self, serial: u64) -> SignedRecord {
            Record::superseded(
                self.pubkey(),
                self.delegation.clone(),
                serial,
                public_of(&generate()),
                "rotated",
            )
            .sign(&self.identity)
            .unwrap()
        }
    }

    /// A resolver pointed at an address it never dials — enough to exercise the
    /// guards, which run before any answer is trusted.
    fn offline_resolver() -> Resolver {
        Resolver::single(ServerAddr::new("127.0.0.1", 1, public_of(&generate()))).expect("resolver")
    }

    #[test]
    fn a_server_cannot_follow_a_retirement_with_a_live_record() {
        for retired in [Service::new().superseded(1), Service::new().revoked(1)] {
            let resolver = offline_resolver();
            resolver.note_rank(&retired).expect("retirement accepted");

            // A live record for the same key, at the highest serial there is.
            let service = Service::new();
            let mut live = service.live(u64::MAX);
            live.record.key = retired.key();
            live.record.delegation = retired.record.delegation.clone();

            let err = resolver.note_rank(&live).unwrap_err();
            assert!(matches!(err, Error::Downgrade(_)), "{err}");
        }
    }

    #[test]
    fn a_server_cannot_walk_a_serial_backwards() {
        let resolver = offline_resolver();
        let service = Service::new();

        resolver
            .note_rank(&service.live(9))
            .expect("first answer is accepted");
        let err = resolver.note_rank(&service.live(4)).unwrap_err();
        assert!(matches!(err, Error::Downgrade(_)), "{err}");
        resolver
            .note_rank(&service.live(9))
            .expect("same rank is not a downgrade");
    }

    /// A key answering to a different identity is a thief who minted their own
    /// delegation, not a rotation — rotation moves to a different key and says
    /// so. A resolver that has seen the key before must notice.
    #[test]
    fn a_key_cannot_change_the_identity_behind_it() {
        let resolver = offline_resolver();
        let service = Service::new();
        resolver.note_rank(&service.live(1)).expect("first answer");

        // Same service key, re-issued by an identity of the attacker's own.
        let attacker = generate();
        let reissued = Record::live(
            service.pubkey(),
            Delegation::issue(&attacker, &service.pubkey(), now_unix() + 86_400),
            2,
            300,
            vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 6000)],
        )
        .sign(&service.key)
        .unwrap();

        // It verifies on its own — that is the point of the guard.
        reissued.verify_answer(&service.pubkey(), now_unix()).unwrap();
        let err = resolver.note_rank(&reissued).unwrap_err();
        assert!(matches!(err, Error::Delegation(_)), "{err}");
    }

    #[test]
    fn an_ordinary_refresh_is_not_a_downgrade() {
        let resolver = offline_resolver();
        let service = Service::new();

        for serial in 1..5 {
            resolver
                .note_rank(&service.live(serial))
                .expect("serials only go up");
        }
    }
}
