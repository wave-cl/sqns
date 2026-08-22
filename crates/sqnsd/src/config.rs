//! Server configuration: a TOML file, command line flags, or both.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::key::PubKey;
use sqns_core::protocol::DEFAULT_PORT;

fn default_listen() -> String {
    format!("[::]:{DEFAULT_PORT}")
}

fn default_sync_interval() -> u64 {
    60
}

fn default_persist_interval() -> u64 {
    30
}

fn default_upstream_timeout() -> u64 {
    5
}

fn default_max_upstream_inflight() -> usize {
    64
}

fn default_true() -> bool {
    true
}

/// The TOML file's shape. Every field except `key_file` has a default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Address to listen on. Default `[::]:5300`.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Hex Ed25519 seed for this server's identity.
    pub key_file: PathBuf,
    /// Where records are snapshotted. Omit to keep them in memory only.
    #[serde(default)]
    pub state_file: Option<PathBuf>,
    /// Replication peers, as `sqc://host:port/<base58 key>`.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Base58 client keys allowed to connect. Empty means anyone holding this
    /// server's public key may connect.
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    /// Servers to ask for keys this one does not hold, as
    /// `sqc://host:port/<base58 key>`. Distinct from `peers`: this is one-way
    /// resolution, not replication, so a leaf can answer for the whole network
    /// without mirroring it.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// How long to wait on each upstream, in seconds.
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_secs: u64,
    /// Keep relayed answers in memory until they expire. The cache is never
    /// replicated, persisted, or listed under an identity.
    #[serde(default = "default_true")]
    pub upstream_cache: bool,
    /// Most upstream queries in flight at once.
    #[serde(default = "default_max_upstream_inflight")]
    pub max_upstream_inflight: usize,

    /// Answer anti-entropy pulls. Turn off on a server that should not seed
    /// its whole record set to callers.
    #[serde(default = "default_true")]
    pub allow_sync: bool,
    /// How often to pull from each peer, in seconds.
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
    /// How often to write the snapshot, in seconds.
    #[serde(default = "default_persist_interval")]
    pub persist_interval_secs: u64,
}

/// Configuration with everything parsed and resolved.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub key_file: PathBuf,
    pub state_file: Option<PathBuf>,
    pub peers: Vec<ServerAddr>,
    pub upstreams: Vec<ServerAddr>,
    pub upstream_timeout: Duration,
    pub upstream_cache: bool,
    pub max_upstream_inflight: usize,
    pub allowed_clients: Vec<PubKey>,
    pub allow_sync: bool,
    pub sync_interval: Duration,
    pub persist_interval: Duration,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Protocol(format!("cannot read {}: {e}", path.display())))?;
        let file: FileConfig = toml::from_str(&text)
            .map_err(|e| Error::Protocol(format!("cannot parse {}: {e}", path.display())))?;
        file.resolve()
    }
}

impl FileConfig {
    pub fn resolve(self) -> Result<Config> {
        let listen = parse_listen(&self.listen)?;
        let peers = self
            .peers
            .iter()
            .map(|p| p.parse::<ServerAddr>())
            .collect::<Result<Vec<_>>>()?;
        let upstreams = self
            .upstreams
            .iter()
            .map(|u| u.parse::<ServerAddr>())
            .collect::<Result<Vec<_>>>()?;
        let allowed_clients = self
            .allowed_clients
            .iter()
            .map(|k| k.parse::<PubKey>())
            .collect::<Result<Vec<_>>>()?;
        Ok(Config {
            listen,
            key_file: self.key_file,
            state_file: self.state_file,
            peers,
            upstreams,
            upstream_timeout: Duration::from_secs(self.upstream_timeout_secs.max(1)),
            upstream_cache: self.upstream_cache,
            max_upstream_inflight: self.max_upstream_inflight.max(1),
            allowed_clients,
            allow_sync: self.allow_sync,
            sync_interval: Duration::from_secs(self.sync_interval_secs.max(5)),
            persist_interval: Duration::from_secs(self.persist_interval_secs.max(1)),
        })
    }
}

/// Parse a listen address, defaulting the port and accepting a bare port.
pub fn parse_listen(s: &str) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(port) = s.parse::<u16>() {
        return format!("[::]:{port}")
            .parse::<SocketAddr>()
            .map_err(|e| Error::Address(format!("bad listen port '{s}': {e}")));
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }
    Err(Error::Address(format!(
        "cannot parse listen address '{s}' (want host:port, an IP, or a port)"
    )))
}
