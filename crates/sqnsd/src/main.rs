//! `sqnsd` — the sqns server.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sqns_core::error::{Error, Result};
use sqns_core::key;

use sqnsd::config::{self, Config, FileConfig};
use sqnsd::server;

use config::parse_listen;

/// System-wide locations, used when running as root.
const SYSTEM_CONFIG: &str = "/etc/sqns/sqnsd.toml";
const SYSTEM_KEY: &str = "/etc/sqns/sqnsd.key";
const SYSTEM_STATE: &str = "/var/lib/sqns/records.db";

/// Per-user locations, used otherwise.
const USER_KEY: &str = "sqnsd.key";
const USER_STATE: &str = "records.db";

fn running_as_root() -> bool {
    // Safe: geteuid reads process state and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[derive(Parser)]
#[command(name = "sqnsd", version, about = "sqns server: signed key-to-endpoint records over sQUIC")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// TOML configuration file. Flags below override its values.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Address to listen on (host:port, an IP, or a bare port).
    #[arg(short, long, value_name = "ADDR")]
    listen: Option<String>,

    /// File holding this server's hex Ed25519 seed.
    #[arg(short, long, value_name = "FILE")]
    key_file: Option<PathBuf>,

    /// File to snapshot records into. Omit to stay in memory only.
    #[arg(short, long, value_name = "FILE")]
    state_file: Option<PathBuf>,

    /// Replication peer as sqc://host:port/<base58 key>. Repeatable.
    #[arg(short, long = "peer", value_name = "URL")]
    peers: Vec<String>,

    /// Server to ask for keys this one does not hold, as
    /// sqc://host:port/<base58 key>. Repeatable. Unlike a peer, this is
    /// one-way: nothing is replicated or mirrored.
    #[arg(short, long = "upstream", value_name = "URL")]
    upstreams: Vec<String>,

    /// Refuse anti-entropy pulls from callers.
    #[arg(long)]
    no_sync: bool,

    /// Resolve sqns:// peers and upstreams without requiring DNSSEC.
    #[arg(long)]
    insecure_dns: bool,

    /// Print this server's public key and exit.
    #[arg(long)]
    show_pubkey: bool,

    /// Log level: error, warn, info, debug, trace.
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    log: String,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a server identity keypair.
    Keygen {
        /// Where to write the hex private seed (mode 0600).
        #[arg(short, long, value_name = "FILE")]
        out: PathBuf,
        /// Overwrite an existing key file.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SQNSD_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log)),
        )
        // Logs on stderr keep stdout clean for --show-pubkey, which scripts read.
        .with_writer(std::io::stderr)
        .init();

    let result = match &cli.command {
        Some(Command::Keygen { out, force }) => keygen(out, *force),
        None if cli.show_pubkey => show_pubkey(&cli),
        None => serve(cli),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sqnsd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(out: &Path, force: bool) -> Result<()> {
    if out.exists() && !force {
        return Err(Error::Key(format!(
            "{} already exists; pass --force to overwrite it",
            out.display()
        )));
    }
    let signing_key = key::generate();
    key::save_secret_file(out, &signing_key)?;
    let public = key::public_of(&signing_key);
    println!("private key: {}", out.display());
    println!("public key:  {public}");
    println!("connect as:  sqc://<host>:{}/{public}", sqns_core::DEFAULT_PORT);
    Ok(())
}

/// Print the server's public key, generating one if this is a first run.
fn show_pubkey(cli: &Cli) -> Result<()> {
    let config = build_config(cli)?;
    let signing_key = load_or_create_key(&config.key_file, cli.key_file.is_some())?;
    println!("{}", key::public_of(&signing_key));
    Ok(())
}

/// Load the server's key, creating one on a first run.
///
/// A key file named explicitly on the command line must already exist: a
/// mistyped path should fail loudly, not quietly bring up a server under an
/// identity no client has ever heard of.
fn load_or_create_key(path: &Path, explicit: bool) -> Result<ed25519_dalek::SigningKey> {
    if path.exists() {
        return key::load_secret_file(path);
    }
    if explicit {
        return Err(Error::Key(format!(
            "no key at {} — generate one with: sqnsd keygen --out {}",
            path.display(),
            path.display()
        )));
    }
    let signing_key = key::generate();
    key::save_secret_file(path, &signing_key)?;
    tracing::info!(path = %path.display(), "generated a new server identity");
    Ok(signing_key)
}

fn serve(cli: Cli) -> Result<()> {
    let config = build_config(&cli)?;
    let explicit_key = cli.key_file.is_some();
    let signing_key = load_or_create_key(&config.key_file, explicit_key)?;

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Error::Connection(format!("cannot start the async runtime: {e}")))?;
    runtime.block_on(server::run(config, signing_key))
}

/// Where the key and the snapshot live when nothing says otherwise: system
/// paths for root, the caller's sqns directory for everyone else.
fn default_paths() -> Result<(PathBuf, PathBuf)> {
    if running_as_root() {
        Ok((PathBuf::from(SYSTEM_KEY), PathBuf::from(SYSTEM_STATE)))
    } else {
        let dir = key::ensure_sqns_dir()?;
        Ok((dir.join(USER_KEY), dir.join(USER_STATE)))
    }
}

/// Merge the config file (if any) with command line flags; flags win.
fn build_config(cli: &Cli) -> Result<Config> {
    // With no --config, a system config file is still picked up if one is
    // there, so an installed server behaves the same whether or not systemd
    // passes the flag.
    let config_path = cli
        .config
        .clone()
        .or_else(|| Some(PathBuf::from(SYSTEM_CONFIG)).filter(|p| p.exists()));

    let mut config = match &config_path {
        Some(path) => Config::from_file(path)?,
        None => {
            let (key_file, state_file) = default_paths()?;
            FileConfig {
                listen: format!("[::]:{}", sqns_core::DEFAULT_PORT),
                key_file,
                state_file: Some(state_file),
                peers: Vec::new(),
                upstreams: Vec::new(),
                require_dnssec: true,
                upstream_timeout_secs: 5,
                upstream_cache: true,
                max_upstream_inflight: 64,
                allowed_clients: Vec::new(),
                allow_sync: true,
                sync_interval_secs: 60,
                persist_interval_secs: 30,
            }
            .resolve()?
        }
    };

    if let Some(listen) = &cli.listen {
        config.listen = parse_listen(listen)?;
    }
    if let Some(key_file) = &cli.key_file {
        config.key_file = key_file.clone();
    }
    if let Some(state_file) = &cli.state_file {
        config.state_file = Some(state_file.clone());
    }
    for peer in &cli.peers {
        config.peers.push(peer.parse()?);
    }
    for upstream in &cli.upstreams {
        config.upstreams.push(upstream.parse()?);
    }
    if cli.no_sync {
        config.allow_sync = false;
    }
    if cli.insecure_dns {
        config.require_dnssec = false;
    }
    Ok(config)
}
