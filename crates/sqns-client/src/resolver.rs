//! The resolver: look up keys, publish records, talk to several servers.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::key::PubKey;
use sqns_core::protocol::{ErrorCode, Request, Response, StatusInfo};
use sqns_core::record::{Endpoint, SignedRecord, now_unix};
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

/// Resolves public keys to endpoints, and publishes records.
///
/// Connections are kept open and reused; a server that fails is re-dialed on
/// the next request.
pub struct Resolver {
    config: ResolverConfig,
    conns: Vec<Mutex<Option<quinn::Connection>>>,
    cache: Arc<Cache>,
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

    /// Endpoints for `key`, in the order they should be tried.
    ///
    /// Returns [`Error::Unpublished`] when no server holds a record. A record
    /// that exists but lists no endpoints is a deliberate withdrawal and yields
    /// an empty vector.
    pub async fn resolve(&self, key: &PubKey) -> Result<Vec<Endpoint>> {
        match self.lookup(key).await? {
            Some(rec) => Ok(order_endpoints(&rec.record)),
            None => Err(Error::Unpublished(key.to_string())),
        }
    }

    /// Publish a signed record to every configured server.
    ///
    /// Succeeds if at least one server accepts it; the returned serial is the
    /// record's own. Per-server failures are logged, not fatal — replication
    /// carries the record to servers that were down.
    pub async fn publish(&self, record: &SignedRecord) -> Result<u64> {
        record.verify()?;
        record.record.validate()?;
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
