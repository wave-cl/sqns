//! The server: accept sQUIC connections, answer requests, keep the store fresh.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use sqns_core::error::{Error, Result};
use sqns_core::key::public_of;
use sqns_core::protocol::{ALPN, ErrorCode, MAX_SYNC_BATCH, Request, Response, StatusInfo};
use sqns_core::record::SignedRecord;

use crate::config::Config;
use crate::replication::Replicator;
use crate::upstream::Upstream;
use crate::store::{PutOutcome, Store};

/// How often expired records are swept.
const PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// Everything a request handler needs.
struct Server {
    store: Arc<Store>,
    replicator: Arc<Replicator>,
    upstream: Arc<Upstream>,
    allow_sync: bool,
    started: Instant,
}

impl Server {
    fn status(&self) -> StatusInfo {
        StatusInfo {
            records: self.store.len() as u64,
            cached: self.upstream.cached() as u64,
            peers: self.replicator.peer_count() as u32,
            upstreams: self.upstream.len() as u32,
            uptime_secs: self.started.elapsed().as_secs(),
            version: sqns_core::VERSION.to_string(),
        }
    }

    /// Handle one request. Errors are returned to the caller as `Response`s;
    /// this never fails the connection on a bad request.
    async fn handle(self: &Arc<Self>, req: Request) -> Response {
        match req {
            Request::Lookup { key, recurse } => {
                if let Some(record) = self.store.get(&key) {
                    // A tombstone that forwards travels with the record it
                    // forwards to, so the caller resolves a rotated key in one
                    // exchange.
                    let successor = record
                        .record
                        .successor()
                        .and_then(|next| self.store.get(&next))
                        .map(Box::new);
                    tracing::debug!(key = %key.short(), forwarded = successor.is_some(), "lookup");
                    return Response::Answer {
                        record: Some(Box::new(record)),
                        successor,
                    };
                }

                // Not ours. Ask upstream, if we have any hops left to spend.
                if recurse == 0 || self.upstream.is_empty() {
                    tracing::debug!(key = %key.short(), recurse, "lookup miss");
                    return Response::Answer {
                        record: None,
                        successor: None,
                    };
                }
                match self.upstream.lookup(&key, recurse - 1).await {
                    Ok(Some(relayed)) => Response::Answer {
                        record: Some(Box::new(relayed.record)),
                        successor: relayed.successor.map(Box::new),
                    },
                    Ok(None) => Response::Answer {
                        record: None,
                        successor: None,
                    },
                    Err(e) => {
                        tracing::warn!(key = %key.short(), error = %e, "upstream lookup failed");
                        Response::error(ErrorCode::UpstreamFailed, e.to_string())
                    }
                }
            }

            Request::LookupIdentity { identity } => {
                let records = self
                    .store
                    .identity_records(&identity, MAX_SYNC_BATCH as usize);
                tracing::debug!(identity = %identity.short(), keys = records.len(), "identity lookup");
                Response::Records {
                    records,
                    complete: true,
                }
            }

            Request::Publish { record } => self.handle_publish(*record).await,

            Request::Status => Response::Status(self.status()),

            Request::Sync { since, limit } => {
                if !self.allow_sync {
                    return Response::error(
                        ErrorCode::NotAuthorized,
                        "this server does not answer sync requests",
                    );
                }
                let limit = limit.clamp(1, MAX_SYNC_BATCH) as usize;
                let (records, complete) = self.store.since(since, limit);
                tracing::debug!(since, returned = records.len(), complete, "sync");
                Response::Records { records, complete }
            }
        }
    }

    async fn handle_publish(self: &Arc<Self>, record: SignedRecord) -> Response {
        let key = record.key();
        let (serial, expires_at) = (record.record.serial, record.record.expires_at());

        match self.store.put(record.clone()) {
            Ok(PutOutcome::Stored) => {
                tracing::info!(
                    key = %key.short(),
                    serial,
                    identity = %record.record.identity().short(),
                    terminal = record.record.is_terminal(),
                    endpoints = record.record.endpoints().len(),
                    "record stored"
                );
                // Fan out without making the publisher wait on peer round trips.
                let replicator = Arc::clone(&self.replicator);
                tokio::spawn(async move { replicator.push(record).await });
                Response::Published { serial, expires_at }
            }
            Ok(PutOutcome::Stale) => Response::error(
                ErrorCode::Stale,
                format!("a record with serial >= {serial} is already held for {key}"),
            ),
            Err(e) => {
                tracing::debug!(key = %key.short(), error = %e, "record rejected");
                let code = match e {
                    Error::Signature(_) => ErrorCode::BadSignature,
                    Error::Revoked { .. } => ErrorCode::Revoked,
                    Error::Superseded { .. } => ErrorCode::Superseded,
                    Error::Delegation(_) => ErrorCode::BadDelegation,
                    _ => ErrorCode::Malformed,
                };
                Response::error(code, e.to_string())
            }
        }
    }
}

/// A bound, ready-to-serve server.
///
/// Binding is separate from serving so a caller — a test, or a supervisor that
/// wants the assigned port — can learn the local address before the accept loop
/// starts.
pub struct Bound {
    listener: squic::ServerListener,
    server: Arc<Server>,
    store: Arc<Store>,
    replicator: Arc<Replicator>,
    persist_interval: Duration,
    upstream: Arc<Upstream>,
    local_addr: std::net::SocketAddr,
    public_key: sqns_core::key::PubKey,
}

impl Bound {
    /// The address actually bound, which is what to use when the configured
    /// port was 0.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// This server's public key — the one clients pin.
    pub fn public_key(&self) -> sqns_core::key::PubKey {
        self.public_key
    }

    /// `sqc://host:port/<key>`, ready to hand to a client.
    pub fn connection_string(&self) -> String {
        format!("sqc://{}/{}", self.local_addr, self.public_key)
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }
}

/// Bind the listener and prepare the server without accepting yet.
pub async fn bind(config: Config, signing_key: SigningKey) -> Result<Bound> {
    let store = Arc::new(Store::open(config.state_file.clone())?);
    let client_key_hex = sqns_client::hex_seed(&signing_key);
    let replicator = Arc::new(Replicator::new(
        &config.peers,
        Arc::clone(&store),
        client_key_hex.clone(),
        config.sync_interval,
        config.require_dnssec,
    ));
    let upstream = Arc::new(Upstream::new(
        &config.upstreams,
        Arc::clone(&store),
        client_key_hex,
        config.upstream_timeout,
        config.upstream_cache,
        config.max_upstream_inflight,
        config.require_dnssec,
    ));

    let allowed_keys = if config.allowed_clients.is_empty() {
        None
    } else {
        let mut keys = Vec::with_capacity(config.allowed_clients.len());
        for k in &config.allowed_clients {
            let x = squic::crypto::ed25519_public_to_x25519(k.as_bytes())
                .map_err(|e| Error::Key(format!("client key {k} is unusable: {e}")))?;
            keys.push(x.to_bytes());
        }
        Some(keys)
    };

    let squic_config = squic::Config {
        alpn_protocols: vec![ALPN.to_vec()],
        allowed_keys,
        max_incoming_streams: 256,
        max_idle_timeout: Duration::from_secs(60),
        accepted_envelope_versions: config.accepted_envelope_versions.clone(),
        ..Default::default()
    };

    let listener = squic::listen(config.listen, &signing_key, squic_config)
        .await
        .map_err(|e| Error::Connection(format!("cannot listen on {}: {e}", config.listen)))?;

    let server = Arc::new(Server {
        store: Arc::clone(&store),
        replicator: Arc::clone(&replicator),
        upstream: Arc::clone(&upstream),
        allow_sync: config.allow_sync,
        started: Instant::now(),
    });

    let local_addr = listener
        .local_addr()
        .map_err(|e| Error::Connection(format!("cannot read the local address: {e}")))?;

    Ok(Bound {
        listener,
        server,
        store,
        replicator,
        persist_interval: config.persist_interval,
        upstream: Arc::clone(&upstream),
        local_addr,
        public_key: public_of(&signing_key),
    })
}

/// Serve until interrupted, then write a final snapshot.
pub async fn serve(bound: Bound) -> Result<()> {
    let Bound {
        listener,
        server,
        store,
        replicator,
        persist_interval,
        upstream,
        local_addr,
        public_key,
    } = bound;

    tracing::info!(
        listen = %local_addr,
        key = %public_key,
        records = store.len(),
        peers = replicator.peer_count(),
        upstreams = upstream.len(),
        "sqnsd {} listening", sqns_core::VERSION
    );
    tracing::info!("connection string: sqc://{local_addr}/{public_key}");

    tokio::spawn(Arc::clone(&replicator).run());
    tokio::spawn(maintenance(
        Arc::clone(&store),
        Arc::clone(&upstream),
        persist_interval,
    ));

    let accept_loop = async {
        while let Some(incoming) = listener.accept().await {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::debug!(error = %e, "handshake failed");
                        return;
                    }
                };
                let peer = conn.remote_address();
                tracing::debug!(%peer, "connection established");
                serve_connection(server, conn).await;
                tracing::debug!(%peer, "connection closed");
            });
        }
    };

    tokio::select! {
        _ = accept_loop => tracing::warn!("listener stopped accepting"),
        signal = shutdown_signal() => tracing::info!(%signal, "shutting down"),
    }

    // Records outlive the process only if the snapshot is current.
    listener.close(0u32.into(), b"shutdown");
    if store.snapshot_path().is_some() {
        match store.persist() {
            Ok(()) => tracing::info!(records = store.len(), "snapshot written"),
            Err(e) => tracing::error!(error = %e, "cannot write snapshot on shutdown"),
        }
    }
    Ok(())
}

/// Answer every stream on one connection.
async fn serve_connection(server: Arc<Server>, conn: quinn::Connection) {
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            // The peer hung up, which is the normal end of a connection.
            Err(_) => return,
        };
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let response = match Request::read_from(&mut recv).await {
                Ok(req) => server.handle(req).await,
                Err(e) => {
                    tracing::debug!(error = %e, "malformed request");
                    Response::error(ErrorCode::Malformed, e.to_string())
                }
            };
            if let Err(e) = response.write_to(&mut send).await {
                tracing::debug!(error = %e, "cannot send response");
                return;
            }
            let _ = send.finish();
        });
    }
}

/// Wait for a signal asking the server to stop.
///
/// SIGTERM matters as much as ctrl-C here: it is what service managers send on
/// stop, and the final snapshot is written after this returns. Missing it would
/// lose every record published since the last periodic write — including
/// retirement tombstones, which is the last thing that should evaporate.
async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => "SIGINT",
                    _ = term.recv() => "SIGTERM",
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot listen for SIGTERM; ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                "SIGINT"
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "ctrl-c"
    }
}

/// Bind and serve in one call.
pub async fn run(config: Config, signing_key: SigningKey) -> Result<()> {
    serve(bind(config, signing_key).await?).await
}

/// Sweep expired records and write the snapshot when something changed.
async fn maintenance(store: Arc<Store>, upstream: Arc<Upstream>, persist_interval: Duration) {
    let mut purge = tokio::time::interval(PURGE_INTERVAL);
    let mut persist = tokio::time::interval(persist_interval);
    purge.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    persist.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut persisted_revision = u64::MAX;

    loop {
        tokio::select! {
            _ = purge.tick() => {
                let removed = store.purge_expired();
                if removed > 0 {
                    tracing::info!(removed, "expired records swept");
                }
                let dropped = upstream.purge();
                if dropped > 0 {
                    tracing::debug!(dropped, "expired relay cache entries dropped");
                }
            }
            _ = persist.tick() => {
                if store.snapshot_path().is_none() {
                    continue;
                }
                let revision = store.revision();
                if revision == persisted_revision {
                    continue;
                }
                match store.persist() {
                    Ok(()) => {
                        persisted_revision = revision;
                        tracing::debug!(records = store.len(), "snapshot written");
                    }
                    Err(e) => tracing::error!(error = %e, "cannot write snapshot"),
                }
            }
        }
    }
}
