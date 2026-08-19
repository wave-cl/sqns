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
    Record, RecordBody, SignedRecord, now_unix,
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
    /// Issue a delegation from an offline identity key over a service key.
    ///
    /// Run this where the identity key lives; it touches no network. One
    /// identity may issue as many service keys as it likes, and each resolves
    /// on its own.
    Delegate {
        /// Hex Ed25519 seed file for the identity key.
        #[arg(short, long, value_name = "FILE")]
        identity_key: PathBuf,
        /// The service key to delegate to: a base58 public key, or a path to
        /// its private seed file.
        #[arg(long, value_name = "KEY|FILE")]
        service_key: String,
        /// Days the delegation stays valid.
        #[arg(long, default_value_t = DEFAULT_DELEGATION_LIFETIME / 86_400)]
        days: u64,
        /// Where to write the delegation, for the node to publish with.
        #[arg(short, long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Retire a service key and forward lookups to its replacement.
    Supersede {
        /// The service key being retired.
        #[arg(long, value_name = "KEY")]
        old_key: String,
        /// The service key that replaces it.
        #[arg(long, value_name = "KEY")]
        new_key: String,
        /// Identity key that issued the old service key.
        #[arg(short, long, value_name = "FILE", conflicts_with = "key_file")]
        identity_key: Option<PathBuf>,
        /// The old service key's own seed, for a key with no identity.
        #[arg(short, long, value_name = "FILE")]
        key_file: Option<PathBuf>,
        /// Why the key is being retired.
        #[arg(long, default_value = "rotated")]
        reason: String,
    },
    /// Permanently revoke a service key. This cannot be undone.
    Revoke {
        /// The service key to revoke. Omit with --all.
        #[arg(long, value_name = "KEY")]
        key: Option<String>,
        /// Revoke every service key this identity has issued.
        #[arg(long, conflicts_with = "key")]
        all: bool,
        /// Identity key that issued the service key.
        #[arg(short, long, value_name = "FILE", conflicts_with = "key_file")]
        identity_key: Option<PathBuf>,
        /// The service key's own seed, for a key with no identity.
        #[arg(short, long, value_name = "FILE")]
        key_file: Option<PathBuf>,
        /// Why the key is being revoked.
        #[arg(long, default_value = "revoked by the key holder")]
        reason: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// List the service keys an identity has issued.
    Identity {
        /// The identity's base58 public key, or a path to its seed file.
        key: String,
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
            days,
            out,
        } => return delegate(identity_key, service_key, *days, out),
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
            let Some(rec) = resolver.lookup(&key).await? else {
                return Err(Error::Unpublished(key.to_string()));
            };
            print_record(&rec);

            // A retired key is only half the story; show where it leads.
            if rec.record.successor().is_some() {
                match resolver.resolve_service(&key).await {
                    Ok(location) => {
                        println!();
                        println!("--- resolves to {} ---", location.key);
                        if let Some(rec) = resolver.lookup(&location.key).await? {
                            print_record(&rec);
                        }
                    }
                    Err(e) => println!("\ncould not follow the forward: {e}"),
                }
            }
            Ok(())
        }

        Command::Resolve { key } => {
            let key = key.parse::<PubKey>()?;
            let resolver = build_resolver(&server)?;
            let location = resolver.resolve_service(&key).await?;
            if location.is_stale() {
                // stdout stays a clean endpoint list for scripts.
                eprintln!(
                    "sqns: {key} has been rotated; it now resolves to {}",
                    location.key
                );
            }
            if location.endpoints.is_empty() {
                return Err(Error::Unpublished(format!("{key} (withdrawn)")));
            }
            for ep in location.endpoints {
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
                    Publisher::delegated(signing_key, file.delegation, parsed, ttl)?
                }
                None => Publisher::new(signing_key, parsed, ttl),
            });

            let serial = publisher.publish(&resolver).await?;
            println!(
                "published {} serial {serial}, expires in {ttl}s",
                publisher.key()
            );
            if let Some(identity) = publisher.identity() {
                println!("  issued by identity {identity}");
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

        Command::Supersede {
            old_key,
            new_key,
            identity_key,
            key_file,
            reason,
        } => {
            supersede(
                &old_key,
                &new_key,
                identity_key.as_deref(),
                key_file.as_deref(),
                &reason,
                &server,
            )
            .await
        }

        Command::Revoke {
            key,
            all,
            identity_key,
            key_file,
            reason,
            yes,
        } => {
            revoke(
                key.as_deref(),
                all,
                identity_key.as_deref(),
                key_file.as_deref(),
                &reason,
                yes,
                &server,
            )
            .await
        }

        Command::Identity { key } => {
            let identity = read_pubkey(&key)?;
            let resolver = build_resolver(&server)?;
            let records = resolver.lookup_identity(&identity).await?;
            if records.is_empty() {
                println!("{identity} has no service keys on this server");
                return Ok(());
            }
            println!("{identity} has issued {} service key(s):", records.len());
            for rec in records {
                println!("  {}  {}", rec.key(), describe_state(&rec));
            }
            Ok(())
        }

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
fn delegate(identity_path: &Path, service_key: &str, days: u64, out: &Path) -> Result<()> {
    let identity = key::load_secret_file(identity_path)?;
    let service_pub = read_pubkey(service_key)?;

    let lifetime = days.saturating_mul(86_400);
    if lifetime == 0 || lifetime > MAX_DELEGATION_LIFETIME {
        return Err(Error::Delegation(format!(
            "delegation must last 1..={} days, got {days}",
            MAX_DELEGATION_LIFETIME / 86_400
        )));
    }
    let delegation = Delegation::issue(&identity, &service_pub, now_unix() + lifetime);
    std::fs::write(out, DelegationFile::new(service_pub, delegation).encode())?;

    println!("delegation:  {}", out.display());
    println!("identity:    {}", key::public_of(&identity));
    println!("service key: {service_pub}");
    println!("valid for:   {days} days");
    println!();
    println!(
        "Publish with: sqns publish --key-file <service seed> --delegation {}",
        out.display()
    );
    Ok(())
}

fn load_delegation(path: &Path) -> Result<DelegationFile> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Delegation(format!("cannot read {}: {e}", path.display())))?;
    DelegationFile::decode(&bytes)
}

/// Read a base58 public key, or derive one from a private seed file.
fn read_pubkey(value: &str) -> Result<PubKey> {
    if let Ok(k) = value.parse::<PubKey>() {
        return Ok(k);
    }
    let path = Path::new(value);
    if !path.exists() {
        return Err(Error::Key(format!(
            "'{value}' is neither a base58 public key nor an existing file"
        )));
    }
    Ok(key::public_of(&key::load_secret_file(path)?))
}

/// The signing key and delegation that retiring `service_key` calls for.
///
/// A delegated key is retired by its identity, which mints a fresh delegation
/// over the key to carry its authority in the record. A key with no identity
/// retires itself.
fn retirement_authority(
    service_key: &PubKey,
    identity_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<(ed25519_dalek::SigningKey, Option<Delegation>)> {
    match (identity_path, key_path) {
        (Some(path), _) => {
            let identity = key::load_secret_file(path)?;
            let delegation =
                Delegation::issue(&identity, service_key, now_unix() + DEFAULT_DELEGATION_LIFETIME);
            Ok((identity, Some(delegation)))
        }
        (None, Some(path)) => {
            let sk = key::load_secret_file(path)?;
            if key::public_of(&sk) != *service_key {
                return Err(Error::Key(format!(
                    "{} holds {}, not {service_key}",
                    path.display(),
                    key::public_of(&sk)
                )));
            }
            Ok((sk, None))
        }
        (None, None) => Err(Error::Key(
            "pass --identity-key (the identity that issued the key) or --key-file (the key itself)"
                .into(),
        )),
    }
}

/// Retire a service key, forwarding lookups to its replacement.
async fn supersede(
    old_key: &str,
    new_key: &str,
    identity_path: Option<&Path>,
    key_path: Option<&Path>,
    reason: &str,
    server: &ServerArgs,
) -> Result<()> {
    let old = read_pubkey(old_key)?;
    let new = read_pubkey(new_key)?;
    let (signing_key, delegation) = retirement_authority(&old, identity_path, key_path)?;

    let record = Record::superseded(old, delegation, now_unix(), new, reason).sign(&signing_key)?;
    let resolver = build_resolver(server)?;
    resolver.publish(&record).await?;

    println!("superseded {old}");
    println!("       now {new}");
    println!();
    println!("Lookups of the old key now return the new one and its endpoints.");
    println!("Nothing more will be accepted for the old key.");
    Ok(())
}

/// Permanently revoke one service key, or every key an identity issued.
async fn revoke(
    key_arg: Option<&str>,
    all: bool,
    identity_path: Option<&Path>,
    key_path: Option<&Path>,
    reason: &str,
    yes: bool,
    server: &ServerArgs,
) -> Result<()> {
    let resolver = build_resolver(server)?;

    let targets: Vec<PubKey> = if all {
        let path = identity_path.ok_or_else(|| {
            Error::Key("--all needs --identity-key: it revokes what that identity issued".into())
        })?;
        let identity = key::public_of(&key::load_secret_file(path)?);
        resolver
            .lookup_identity(&identity)
            .await?
            .iter()
            .filter(|rec| !rec.record.is_terminal())
            .map(|rec| rec.key())
            .collect()
    } else {
        let value = key_arg
            .ok_or_else(|| Error::Key("pass --key <service key>, or --all with --identity-key".into()))?;
        vec![read_pubkey(value)?]
    };

    if targets.is_empty() {
        println!("nothing to revoke");
        return Ok(());
    }

    if !yes {
        println!("This permanently revokes {} service key(s):", targets.len());
        for key in &targets {
            println!("  {key}");
        }
        println!("No record for them will ever be accepted again, by any server that holds");
        println!("the revocation. It cannot be undone.");
        print!("Type 'revoke' to confirm: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim() != "revoke" {
            return Err(Error::Key("revocation cancelled".into()));
        }
    }

    for target in targets {
        let (signing_key, delegation) = retirement_authority(&target, identity_path, key_path)?;
        let record =
            Record::revoked(target, delegation, now_unix(), reason).sign(&signing_key)?;
        resolver.publish(&record).await?;
        println!("revoked {target}");
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

/// One-line state of a record, for listings.
fn describe_state(record: &SignedRecord) -> String {
    let rec = &record.record;
    match &rec.body {
        RecordBody::Superseded { successor, .. } => format!("superseded by {successor}"),
        RecordBody::Revoked { reason } => format!("revoked ({reason})"),
        RecordBody::Live { endpoints } if endpoints.is_empty() => "withdrawn".to_string(),
        RecordBody::Live { endpoints } => format!("live, {} endpoint(s)", endpoints.len()),
    }
}

fn print_record(record: &SignedRecord) {
    let rec = &record.record;
    let now = now_unix();
    println!("key:      {}", rec.key);
    match rec.identity() {
        Some(identity) => println!("identity: {identity}"),
        None => println!("identity: none — this key stands on its own"),
    }
    println!("serial:   {}", rec.serial);
    println!("issued:   {}s ago", now.saturating_sub(rec.issued_at));

    match &rec.body {
        RecordBody::Superseded { successor, reason } => {
            println!("status:   SUPERSEDED — this key is retired ({reason})");
            println!("now use:  {successor}");
            println!();
            println!("Resolving the old key follows this forward automatically; update any");
            println!("pinned copy of it to the new key.");
        }
        RecordBody::Revoked { reason } => {
            println!("status:   REVOKED — this key is permanently dead");
            println!("reason:   {reason}");
        }
        RecordBody::Live { endpoints } => {
            println!(
                "expires:  in {} (ttl {}s)",
                format_duration(rec.remaining(now)),
                rec.ttl
            );
            if let Some(d) = &rec.delegation {
                println!(
                    "delegated until {} ({})",
                    format_duration(d.not_after.saturating_sub(now)),
                    d.identity
                );
            }
            if endpoints.is_empty() {
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
    use super::{Cli, Command};
    use clap::{CommandFactory, Parser};

    /// Catches clashing short flags and other command wiring mistakes, which
    /// clap only asserts on at runtime.
    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    /// Actually parses each command. `debug_assert` does not catch an argument
    /// whose id collides with a global one — that only surfaces when the value
    /// is read back, and then it panics in the user's face.
    #[test]
    fn every_command_parses_and_reads_its_arguments() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["sqns", "lookup", "KEY"],
            vec!["sqns", "resolve", "KEY", "--server", "sqc://h:1/K"],
            vec!["sqns", "identity", "KEY"],
            vec!["sqns", "publish", "--key-file", "k", "-e", "1.2.3.4:5"],
            vec!["sqns", "publish", "--key-file", "k", "-D", "d.bin", "-e", "1.2.3.4:5"],
            vec!["sqns", "withdraw", "--key-file", "k"],
            vec!["sqns", "status", "--identity", "id.key"],
            vec!["sqns", "keygen", "--out", "k"],
            vec!["sqns", "delegate", "--identity-key", "i", "--service-key", "s", "--out", "d"],
            vec!["sqns", "supersede", "--old-key", "A", "--new-key", "B", "--identity-key", "i"],
            vec!["sqns", "revoke", "--key", "A", "--identity-key", "i"],
            vec!["sqns", "revoke", "--all", "--identity-key", "i"],
        ];
        for args in cases {
            let cli = Cli::try_parse_from(&args)
                .unwrap_or_else(|e| panic!("{args:?} did not parse: {e}"));
            // Reading the arguments back is what trips an id collision.
            let _ = format!("{:?}", cli.server.servers);
            let _ = format!("{:?}", cli.server.identity);
            describe_command(&cli.command);
        }
    }

    /// Touch every field of the parsed command, so a bad id is caught here.
    fn describe_command(command: &Command) -> String {
        match command {
            Command::Lookup { key } | Command::Resolve { key } | Command::Identity { key } => {
                key.clone()
            }
            Command::Publish {
                key_file,
                delegation,
                endpoints,
                ttl,
                keepalive,
            } => format!("{key_file:?}{delegation:?}{endpoints:?}{ttl}{keepalive}"),
            Command::Withdraw { key_file, ttl } => format!("{key_file:?}{ttl}"),
            Command::Status => "status".into(),
            Command::Keygen { out, force } => format!("{out:?}{force}"),
            Command::Delegate {
                identity_key,
                service_key,
                days,
                out,
            } => format!("{identity_key:?}{service_key}{days}{out:?}"),
            Command::Supersede {
                old_key,
                new_key,
                identity_key,
                key_file,
                reason,
            } => format!("{old_key}{new_key}{identity_key:?}{key_file:?}{reason}"),
            Command::Revoke {
                key,
                all,
                identity_key,
                key_file,
                reason,
                yes,
            } => format!("{key:?}{all}{identity_key:?}{key_file:?}{reason}{yes}"),
        }
    }
}
