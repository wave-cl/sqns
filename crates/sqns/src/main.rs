//! `sqns` — command line client: look up keys, publish your own endpoints.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use sqns_client::{Publisher, Resolver, ResolverConfig, order_endpoints};
use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::key::{self, PubKey};
use sqns_core::record::{
    DEFAULT_DELEGATION_LIFETIME, Delegation, DelegationFile, Endpoint, MAX_DELEGATION_LIFETIME,
    Record, RecordBody, now_unix,
};

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
        /// Hex Ed25519 seed file for the key that signs: the delegated service
        /// key when --delegation is given, otherwise the identity itself.
        #[arg(short, long, value_name = "FILE")]
        key_file: PathBuf,
        /// Delegation file from `sqns delegate`. With it, the identity key
        /// stays offline and only the service key is on this host.
        #[arg(short = 'D', long, value_name = "FILE")]
        delegation: Option<PathBuf>,
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
    /// Issue a delegation from an offline identity key to a service key.
    ///
    /// Run this where the identity key lives; it touches no network. Raise
    /// --serial on every rotation: a higher serial retires the previous service
    /// key and every record it signed.
    Delegate {
        /// Hex Ed25519 seed file for the identity key.
        #[arg(short, long, value_name = "FILE")]
        identity_key: PathBuf,
        /// The service key to delegate to: a base58 public key, or a path to
        /// its private seed file.
        #[arg(long, value_name = "KEY|FILE")]
        service_key: String,
        /// Delegation serial. Must increase on every rotation.
        #[arg(long)]
        serial: u64,
        /// Days the delegation stays valid.
        #[arg(long, default_value_t = DEFAULT_DELEGATION_LIFETIME / 86_400)]
        days: u64,
        /// Where to write the delegation, for the node to publish with.
        #[arg(short, long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Permanently revoke an identity. This cannot be undone.
    Revoke {
        /// Hex Ed25519 seed file for the identity key being revoked.
        #[arg(short, long, value_name = "FILE")]
        key_file: PathBuf,
        /// The operator's new identity, recorded as an unverifiable hint.
        #[arg(long, value_name = "KEY")]
        successor: Option<String>,
        /// Why the key is being revoked.
        #[arg(long, default_value = "revoked by the key holder")]
        reason: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
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
    match &cli.command {
        Command::Keygen { out, force } => return keygen(out, *force),
        Command::Delegate {
            identity_key,
            service_key,
            serial,
            days,
            out,
        } => return delegate(identity_key, service_key, *serial, *days, out),
        _ => {}
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
            delegation,
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
            let publisher = std::sync::Arc::new(match &delegation {
                Some(path) => {
                    let file = load_delegation(path)?;
                    Publisher::delegated(
                        file.identity,
                        signing_key,
                        file.delegation,
                        parsed,
                        ttl,
                    )?
                }
                None => Publisher::new(signing_key, parsed, ttl),
            });

            let serial = publisher.publish(&resolver).await?;
            println!(
                "published {} serial {serial}, expires in {ttl}s",
                publisher.key()
            );
            if let Some(d) = publisher.delegation() {
                println!(
                    "  dialed as {} under delegation {}",
                    d.service_key, d.serial
                );
            }
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

        Command::Revoke {
            key_file,
            successor,
            reason,
            yes,
        } => revoke(&key_file, successor, &reason, yes, &server).await,

        Command::Keygen { .. } | Command::Delegate { .. } => {
            unreachable!("handled before the runtime starts")
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
    println!("private key: {}", out.display());
    println!("public key:  {}", key::public_of(&signing_key));
    Ok(())
}

/// Issue a delegation. Offline: no network, no server needed.
fn delegate(
    identity_path: &Path,
    service_key: &str,
    serial: u64,
    days: u64,
    out: &Path,
) -> Result<()> {
    let identity = key::load_secret_file(identity_path)?;
    let identity_pub = key::public_of(&identity);

    // Accept the service key as a base58 public key or as a private seed file.
    let service_pub = match service_key.parse::<PubKey>() {
        Ok(k) => k,
        Err(_) => {
            let path = Path::new(service_key);
            if !path.exists() {
                return Err(Error::Key(format!(
                    "'{service_key}' is neither a base58 public key nor an existing file"
                )));
            }
            key::public_of(&key::load_secret_file(path)?)
        }
    };

    let lifetime = days.saturating_mul(86_400);
    if lifetime == 0 || lifetime > MAX_DELEGATION_LIFETIME {
        return Err(Error::Delegation(format!(
            "delegation must last 1..={} days, got {days}",
            MAX_DELEGATION_LIFETIME / 86_400
        )));
    }
    let not_after = now_unix() + lifetime;
    let delegation = Delegation::issue(&identity, service_pub, serial, not_after)?;
    std::fs::write(out, DelegationFile::new(identity_pub, delegation).encode())?;

    println!("delegation:  {}", out.display());
    println!("identity:    {identity_pub}");
    println!("service key: {service_pub}");
    println!("serial:      {serial}");
    println!("valid for:   {days} days");
    println!();
    println!("Publish with: sqns publish --key-file <service seed> --delegation {}", out.display());
    Ok(())
}

fn load_delegation(path: &Path) -> Result<DelegationFile> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Delegation(format!("cannot read {}: {e}", path.display())))?;
    DelegationFile::decode(&bytes)
}

/// Revoke an identity permanently.
async fn revoke(
    key_path: &Path,
    successor: Option<String>,
    reason: &str,
    yes: bool,
    server: &ServerArgs,
) -> Result<()> {
    let identity = key::load_secret_file(key_path)?;
    let identity_pub = key::public_of(&identity);
    let successor = successor
        .as_deref()
        .map(str::parse::<PubKey>)
        .transpose()?;

    if !yes {
        println!("This permanently revokes {identity_pub}.");
        println!("No record for this key will ever be accepted again, by any server that");
        println!("holds the revocation. It cannot be undone.");
        print!("Type the key's first 8 characters to confirm: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim() != identity_pub.short() {
            return Err(Error::Key("revocation cancelled".into()));
        }
    }

    let record = Record::revoked(identity_pub, now_unix(), successor, reason).sign(&identity)?;
    let resolver = build_resolver(server)?;
    let serial = resolver.publish(&record).await?;
    println!("revoked {identity_pub} serial {serial}");
    if let Some(s) = successor {
        println!("successor hint recorded: {s}");
    }
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

    if let RecordBody::Revoked { successor, reason } = &rec.body {
        println!("status:   REVOKED — this identity is permanently dead");
        println!("reason:   {reason}");
        match successor {
            Some(s) => {
                println!("successor: {s}");
                println!();
                println!("The successor is a hint from the revocation itself, which whoever");
                println!("holds the revoked key could have written. Confirm it out of band");
                println!("before trusting it.");
            }
            None => println!("successor: none recorded"),
        }
        return;
    }

    println!(
        "expires:  in {} (ttl {}s)",
        format_duration(rec.remaining(now)),
        rec.ttl
    );
    match rec.delegation() {
        Some(d) => {
            println!("dial key: {} (delegated)", d.service_key);
            println!(
                "          delegation {} valid for {}",
                d.serial,
                format_duration(d.not_after.saturating_sub(now))
            );
        }
        None => println!("dial key: {} (the identity itself)", rec.key),
    }
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

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    /// Catches clashing short flags and other command wiring mistakes, which
    /// clap only asserts on at runtime.
    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }
}
