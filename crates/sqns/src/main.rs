//! `sqns` — command line client: look up keys, publish your own endpoints.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use sqns_client::{Publisher, Resolver, ResolverConfig, order_endpoints};
use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::key::{self, PubKey};
use sqns_core::record::{Endpoint, now_unix};

/// Environment variable holding one or more server addresses.
const SERVER_ENV: &str = "SQNS_SERVER";

#[derive(Parser)]
#[command(name = "sqns", version, about = "Resolve sQUIC public keys to endpoints")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Server selection, accepted before or after the subcommand.
    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Args, Clone)]
struct ServerArgs {
    /// sqns server as sqc://host:port/<base58 key>. Repeatable.
    /// Defaults to $SQNS_SERVER (whitespace or comma separated).
    #[arg(short, long = "server", value_name = "URL", global = true)]
    servers: Vec<String>,

    /// Hex Ed25519 seed file giving this caller a stable identity, for servers
    /// that whitelist clients.
    #[arg(long, value_name = "FILE", global = true)]
    identity: Option<PathBuf>,

    /// Connection timeout in seconds.
    #[arg(long, default_value_t = 10, global = true)]
    timeout: u64,
}

#[derive(Subcommand)]
enum Command {
    /// Show the full record for a key.
    Lookup {
        /// Base58 (or hex) public key.
        key: String,
    },
    /// Print just the endpoints for a key, in the order to try them.
    Resolve {
        key: String,
    },
    /// Publish your endpoints, signed by your key.
    Publish {
        /// Hex Ed25519 seed file for the key being published.
        #[arg(short, long, value_name = "FILE")]
        key_file: PathBuf,
        /// host:port[,priority=N][,weight=N]. Repeatable.
        #[arg(short, long = "endpoint", value_name = "ADDR", required = true)]
        endpoints: Vec<String>,
        /// Record lifetime in seconds.
        #[arg(long, default_value_t = sqns_client::DEFAULT_TTL)]
        ttl: u32,
        /// Keep republishing until interrupted, instead of publishing once.
        #[arg(long)]
        keepalive: bool,
    },
    /// Withdraw a key: publish a record with no endpoints.
    Withdraw {
        #[arg(short, long, value_name = "FILE")]
        key_file: PathBuf,
        #[arg(long, default_value_t = sqns_client::DEFAULT_TTL)]
        ttl: u32,
    },
    /// Show server counters.
    Status,
    /// Generate a keypair.
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SQNS_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sqns: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    if let Command::Keygen { out, force } = &cli.command {
        return keygen(out, *force);
    }

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Error::Connection(format!("cannot start the async runtime: {e}")))?;
    runtime.block_on(run_async(cli.command, cli.server))
}

async fn run_async(command: Command, server: ServerArgs) -> Result<()> {
    match command {
        Command::Lookup { key } => {
            let key = key.parse::<PubKey>()?;
            let resolver = build_resolver(&server)?;
            match resolver.lookup(&key).await? {
                Some(rec) => print_record(&rec),
                None => return Err(Error::Unpublished(key.to_string())),
            }
            Ok(())
        }

        Command::Resolve { key } => {
            let key = key.parse::<PubKey>()?;
            let resolver = build_resolver(&server)?;
            let endpoints = resolver.resolve(&key).await?;
            if endpoints.is_empty() {
                return Err(Error::Unpublished(format!("{key} (withdrawn)")));
            }
            for ep in endpoints {
                println!("{}", ep.authority());
            }
            Ok(())
        }

        Command::Publish {
            key_file,
            endpoints,
            ttl,
            keepalive,
        } => {
            let signing_key = key::load_secret_file(&key_file)?;
            let parsed = endpoints
                .iter()
                .map(|e| e.parse::<Endpoint>())
                .collect::<Result<Vec<_>>>()?;
            let resolver = std::sync::Arc::new(build_resolver(&server)?);
            let publisher = std::sync::Arc::new(Publisher::new(signing_key, parsed, ttl));

            let serial = publisher.publish(&resolver).await?;
            println!(
                "published {} serial {serial}, expires in {ttl}s",
                publisher.key()
            );
            if keepalive {
                println!(
                    "refreshing every {}s; press ctrl-c to stop",
                    publisher.refresh_interval().as_secs()
                );
                tokio::select! {
                    _ = std::sync::Arc::clone(&publisher).run(std::sync::Arc::clone(&resolver)) => {}
                    _ = tokio::signal::ctrl_c() => {
                        println!("\nwithdrawing {}", publisher.key());
                        publisher.withdraw(&resolver).await?;
                    }
                }
            }
            Ok(())
        }

        Command::Withdraw { key_file, ttl } => {
            let signing_key = key::load_secret_file(&key_file)?;
            let resolver = build_resolver(&server)?;
            let publisher = Publisher::new(signing_key, Vec::new(), ttl);
            let serial = publisher.withdraw(&resolver).await?;
            println!("withdrew {} serial {serial}", publisher.key());
            Ok(())
        }

        Command::Status => {
            let resolver = build_resolver(&server)?;
            let info = resolver.status().await?;
            println!("version:  {}", info.version);
            println!("records:  {}", info.records);
            println!("peers:    {}", info.peers);
            println!("uptime:   {}", format_duration(info.uptime_secs));
            Ok(())
        }

        Command::Keygen { .. } => unreachable!("handled before the runtime starts"),
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
    println!("private key: {}", out.display());
    println!("public key:  {}", key::public_of(&signing_key));
    Ok(())
}

fn build_resolver(args: &ServerArgs) -> Result<Resolver> {
    let mut specs: Vec<String> = args.servers.clone();
    if specs.is_empty() && let Ok(env) = std::env::var(SERVER_ENV) {
        specs = env
            .split([',', ' ', '\t', '\n'])
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    if specs.is_empty() {
        return Err(Error::NoServer(format!(
            "no server given: pass --server sqc://host:port/<key> or set {SERVER_ENV}"
        )));
    }
    let servers = specs
        .iter()
        .map(|s| s.parse::<ServerAddr>())
        .collect::<Result<Vec<ServerAddr>>>()?;

    let client_key_hex = match &args.identity {
        Some(path) => Some(sqns_client::hex_seed(&key::load_secret_file(path)?)),
        None => None,
    };

    Resolver::new(ResolverConfig {
        servers,
        client_key_hex,
        connect_timeout: Duration::from_secs(args.timeout),
        cache: false,
    })
}

fn print_record(record: &sqns_core::record::SignedRecord) {
    let rec = &record.record;
    let now = now_unix();
    println!("key:      {}", rec.key);
    println!("serial:   {}", rec.serial);
    println!("issued:   {}s ago", now.saturating_sub(rec.issued_at));
    println!(
        "expires:  in {} (ttl {}s)",
        format_duration(rec.remaining(now)),
        rec.ttl
    );
    if rec.is_withdrawal() {
        println!("endpoints: none — this key is withdrawn");
        return;
    }
    println!("endpoints:");
    for ep in order_endpoints(rec) {
        println!(
            "  {:<40} priority={:<5} weight={}",
            ep.authority(),
            ep.priority,
            ep.weight
        );
    }
}

fn format_duration(secs: u64) -> String {
    match secs {
        0 => "0s".to_string(),
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m{}s", s / 60, s % 60),
        s if s < 86400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86400, (s % 86400) / 3600),
    }
}
