//! `sqnsd` — the sqns server.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sqns_core::error::{Error, Result};
use sqns_core::key;

use sqnsd::config::{self, Config, FileConfig};
use sqnsd::server;

use config::parse_listen;

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

    /// Refuse anti-entropy pulls from callers.
    #[arg(long)]
    no_sync: bool,

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
        .init();

    let result = match &cli.command {
        Some(Command::Keygen { out, force }) => keygen(out, *force),
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

fn serve(cli: Cli) -> Result<()> {
    let config = build_config(&cli)?;
    let signing_key = key::load_secret_file(&config.key_file)?;

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Error::Connection(format!("cannot start the async runtime: {e}")))?;
    runtime.block_on(server::run(config, signing_key))
}

/// Merge the config file (if any) with command line flags; flags win.
fn build_config(cli: &Cli) -> Result<Config> {
    let mut config = match &cli.config {
        Some(path) => Config::from_file(path)?,
        None => {
            let key_file = cli.key_file.clone().ok_or_else(|| {
                Error::Key(
                    "no key file: pass --key-file, or --config with key_file set \
                     (generate one with: sqnsd keygen --out sqnsd.key)"
                        .into(),
                )
            })?;
            FileConfig {
                listen: format!("[::]:{}", sqns_core::DEFAULT_PORT),
                key_file,
                state_file: None,
                peers: Vec::new(),
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
    if cli.no_sync {
        config.allow_sync = false;
    }
    Ok(config)
}
