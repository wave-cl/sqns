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
    NEVER_EXPIRES, Record, RecordBody, SignedRecord, now_unix,
};

/// Environment variable holding one or more server addresses.
const SERVER_ENV: &str = "SQNS_SERVER";

/// Conventional names inside the sqns directory.
const IDENTITY_KEY: &str = "identity.key";
const SERVICE_KEY: &str = "service.key";
const SERVICE_DELEGATION: &str = "service.deleg";
const CONFIG_FILE: &str = "config";

/// A path flag, or its default inside the sqns directory.
///
/// Falling back creates the directory at 0700, so a first `sqns keygen` sets
/// the permissions before anything secret lands in it.
fn path_or_default(given: Option<PathBuf>, name: &str) -> Result<PathBuf> {
    match given {
        Some(path) => Ok(path),
        None => Ok(key::ensure_sqns_dir()?.join(name)),
    }
}

/// Load a private key, pointing at the command that would create it.
fn load_key(path: &Path, hint: &str) -> Result<ed25519_dalek::SigningKey> {
    if !path.exists() {
        return Err(Error::Key(format!(
            "no key at {} — create one with: {hint}",
            path.display()
        )));
    }
    key::load_secret_file(path)
}

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

    /// Hex Ed25519 seed file giving this caller a stable key on the wire, for
    /// servers that whitelist their clients. Unrelated to the identity keys
    /// that issue service keys.
    #[arg(long, value_name = "FILE", global = true)]
    client_key: Option<PathBuf>,

    /// Connection timeout in seconds.
    #[arg(long, default_value_t = 10, global = true)]
    timeout: u64,

    /// Ask each server only for what it holds itself, without letting it
    /// forward the question upstream. Answers the question "is this server
    /// serving it, or relaying it?".
    #[arg(long, global = true)]
    no_recurse: bool,
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
        /// Hex Ed25519 seed file for the service key that signs this record.
        /// Defaults to ~/.sqns/service.key.
        #[arg(short, long, value_name = "FILE")]
        key_file: Option<PathBuf>,
        /// Delegation file from `sqns delegate`. The identity key stays
        /// offline; only the service key and this file live on the node.
        /// Defaults to ~/.sqns/service.deleg.
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
    /// Withdraw a key: publish a record with no endpoints. The key stays
    /// alive and can be published again later.
    Withdraw {
        /// Defaults to ~/.sqns/service.key.
        #[arg(short, long, value_name = "FILE")]
        key_file: Option<PathBuf>,
        /// Delegation file from `sqns delegate`. Defaults to
        /// ~/.sqns/service.deleg.
        #[arg(short = 'D', long, value_name = "FILE")]
        delegation: Option<PathBuf>,
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
        /// Hex Ed25519 seed file for the identity key. Defaults to
        /// ~/.sqns/identity.key.
        #[arg(short, long, value_name = "FILE")]
        identity_key: Option<PathBuf>,
        /// The service key to delegate to: a base58 public key, or a path to
        /// its private seed file. Defaults to ~/.sqns/service.key.
        #[arg(long, value_name = "KEY|FILE")]
        service_key: Option<String>,
        /// Days the delegation stays valid.
        #[arg(long, default_value_t = DEFAULT_DELEGATION_LIFETIME / 86_400)]
        days: u64,
        /// Issue a delegation that never expires, with no renewal to forget.
        #[arg(long, conflicts_with = "days")]
        never_expires: bool,
        /// Where to write the delegation, for the node to publish with.
        /// Defaults to ~/.sqns/service.deleg.
        #[arg(short, long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Retire a service key and forward lookups to its replacement.
    Supersede {
        /// The service key being retired.
        #[arg(long, value_name = "KEY")]
        old_key: String,
        /// The service key that replaces it.
        #[arg(long, value_name = "KEY")]
        new_key: String,
        /// Identity key that issued the old service key. Defaults to
        /// ~/.sqns/identity.key.
        #[arg(short, long, value_name = "FILE")]
        identity_key: Option<PathBuf>,
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
        /// Identity key that issued the service key. Defaults to
        /// ~/.sqns/identity.key.
        #[arg(short, long, value_name = "FILE")]
        identity_key: Option<PathBuf>,
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
        /// Where to write the hex private seed (mode 0600). Defaults to
        /// ~/.sqns/service.key, or ~/.sqns/identity.key with --identity.
        #[arg(short, long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Generate an identity key rather than a service key.
        #[arg(long)]
        identity: bool,
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
        Command::Keygen {
            out,
            identity,
            force,
        } => {
            let name = if *identity { IDENTITY_KEY } else { SERVICE_KEY };
            let path = path_or_default(out.clone(), name)?;
            return keygen(&path, *identity, *force);
        }
        Command::Delegate {
            identity_key,
            service_key,
            days,
            never_expires,
            out,
        } => {
            let identity_path = path_or_default(identity_key.clone(), IDENTITY_KEY)?;
            let service = match service_key {
                Some(value) => value.clone(),
                None => path_or_default(None, SERVICE_KEY)?.display().to_string(),
            };
            let out_path = path_or_default(out.clone(), SERVICE_DELEGATION)?;
            return delegate(&identity_path, &service, *days, *never_expires, &out_path);
        }
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
            let key_path = path_or_default(key_file, SERVICE_KEY)?;
            let signing_key = load_key(&key_path, "sqns keygen")?;
            let parsed = endpoints
                .iter()
                .map(|e| e.parse::<Endpoint>())
                .collect::<Result<Vec<_>>>()?;
            let resolver = std::sync::Arc::new(build_resolver(&server)?);
            let file = load_delegation(&path_or_default(delegation, SERVICE_DELEGATION)?)?;
            let publisher =
                std::sync::Arc::new(Publisher::new(signing_key, file.delegation, parsed, ttl)?);

            let serial = publisher.publish(&resolver).await?;
            println!(
                "published {} serial {serial}, expires in {ttl}s",
                publisher.key()
            );
            println!("  issued by identity {}", publisher.identity());
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

        Command::Withdraw {
            key_file,
            delegation,
            ttl,
        } => {
            let signing_key = load_key(&path_or_default(key_file, SERVICE_KEY)?, "sqns keygen")?;
            let file = load_delegation(&path_or_default(delegation, SERVICE_DELEGATION)?)?;
            let resolver = build_resolver(&server)?;
            let publisher = Publisher::new(signing_key, file.delegation, Vec::new(), ttl)?;
            let serial = publisher.withdraw(&resolver).await?;
            println!("withdrew {} serial {serial}", publisher.key());
            Ok(())
        }

        Command::Status => {
            let resolver = build_resolver(&server)?;
            let info = resolver.status().await?;
            println!("version:   {}", info.version);
            println!("records:   {}", info.records);
            println!("peers:     {}", info.peers);
            if info.upstreams > 0 {
                println!("upstreams: {}", info.upstreams);
                println!("cached:    {} (relayed, not replicated)", info.cached);
            }
            println!("uptime:    {}", format_duration(info.uptime_secs));
            Ok(())
        }

        Command::Supersede {
            old_key,
            new_key,
            identity_key,
            reason,
        } => {
            let identity_path = path_or_default(identity_key, IDENTITY_KEY)?;
            supersede(&old_key, &new_key, &identity_path, &reason, &server).await
        }

        Command::Revoke {
            key,
            all,
            identity_key,
            reason,
            yes,
        } => {
            let identity_path = path_or_default(identity_key, IDENTITY_KEY)?;
            revoke(key.as_deref(), all, &identity_path, &reason, yes, &server).await
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

fn keygen(out: &Path, identity: bool, force: bool) -> Result<()> {
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
    if identity {
        println!();
        println!("This is your identity key: it issues service keys and is the only thing");
        println!("that can retire them. Keep it off the machines that run services.");
    }
    Ok(())
}

/// Issue a delegation. Offline: no network, no server needed.
fn delegate(
    identity_path: &Path,
    service_key: &str,
    days: u64,
    never_expires: bool,
    out: &Path,
) -> Result<()> {
    let identity = load_key(identity_path, "sqns keygen --identity")?;
    let service_pub = read_pubkey(service_key)?;
    if service_pub == key::public_of(&identity) {
        return Err(Error::Delegation(
            "a key cannot be its own identity: generate a separate service key".into(),
        ));
    }

    let not_after = if never_expires {
        NEVER_EXPIRES
    } else {
        let lifetime = days.saturating_mul(86_400);
        if lifetime == 0 || lifetime > MAX_DELEGATION_LIFETIME {
            return Err(Error::Delegation(format!(
                "delegation must last 1..={} days, or pass --never-expires",
                MAX_DELEGATION_LIFETIME / 86_400
            )));
        }
        now_unix() + lifetime
    };
    let delegation = Delegation::issue(&identity, &service_pub, not_after);
    std::fs::write(out, DelegationFile::new(service_pub, delegation).encode())?;

    println!("delegation:  {}", out.display());
    println!("identity:    {}", key::public_of(&identity));
    println!("service key: {service_pub}");
    if never_expires {
        println!("valid for:   forever");
    } else {
        println!("valid for:   {days} days");
    }
    println!();
    println!(
        "Publish with: sqns publish --key-file <service seed> --delegation {}",
        out.display()
    );
    Ok(())
}

fn load_delegation(path: &Path) -> Result<DelegationFile> {
    let bytes = std::fs::read(path).map_err(|_| {
        Error::Delegation(format!(
            "no delegation at {} — create one with: sqns delegate",
            path.display()
        ))
    })?;
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

/// The delegation that carries an identity's authority to retire `service_key`.
///
/// Minted fresh rather than reusing the node's copy: the identity is the
/// authority here, so all that matters is that this delegation names the same
/// identity the server already bound the key to.
fn retirement_delegation(identity: &ed25519_dalek::SigningKey, service_key: &PubKey) -> Delegation {
    Delegation::issue(
        identity,
        service_key,
        now_unix() + DEFAULT_DELEGATION_LIFETIME,
    )
}

/// Retire a service key, forwarding lookups to its replacement.
async fn supersede(
    old_key: &str,
    new_key: &str,
    identity_path: &Path,
    reason: &str,
    server: &ServerArgs,
) -> Result<()> {
    let old = read_pubkey(old_key)?;
    let new = read_pubkey(new_key)?;
    let identity = load_key(identity_path, "sqns keygen --identity")?;
    let delegation = retirement_delegation(&identity, &old);

    let record = Record::superseded(old, delegation, now_unix(), new, reason).sign(&identity)?;
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
    identity_path: &Path,
    reason: &str,
    yes: bool,
    server: &ServerArgs,
) -> Result<()> {
    let resolver = build_resolver(server)?;
    let identity = load_key(identity_path, "sqns keygen --identity")?;

    let targets: Vec<PubKey> = if all {
        resolver
            .lookup_identity(&key::public_of(&identity))
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
        let delegation = retirement_delegation(&identity, &target);
        let record = Record::revoked(target, delegation, now_unix(), reason).sign(&identity)?;
        resolver.publish(&record).await?;
        println!("revoked {target}");
    }
    Ok(())
}

/// Server addresses from `~/.sqns/config`: one `sqc://` URL per line, with
/// `#` comments and blank lines ignored.
///
/// A missing file is not an error — it just means nothing is configured.
pub fn servers_from_config(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
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
    let config_path = key::sqns_dir()?.join(CONFIG_FILE);
    if specs.is_empty()
        && let Ok(text) = std::fs::read_to_string(&config_path)
    {
        specs = servers_from_config(&text);
    }
    if specs.is_empty() {
        return Err(Error::NoServer(format!(
            "no server given: pass --server sqc://host:port/<key>, set {SERVER_ENV}, \
             or list one per line in {}",
            config_path.display()
        )));
    }
    let servers = specs
        .iter()
        .map(|s| s.parse::<ServerAddr>())
        .collect::<Result<Vec<ServerAddr>>>()?;

    let client_key_hex = match &args.client_key {
        Some(path) => Some(sqns_client::hex_seed(&key::load_secret_file(path)?)),
        None => None,
    };

    Resolver::new(ResolverConfig {
        servers,
        client_key_hex,
        connect_timeout: Duration::from_secs(args.timeout),
        cache: false,
        recurse: if args.no_recurse {
            0
        } else {
            sqns_core::protocol::DEFAULT_RECURSE
        },
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
    println!("identity: {}", rec.identity());
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
            if rec.delegation.never_expires() {
                println!("delegation: never expires");
            } else {
                println!(
                    "delegation: valid for another {}",
                    format_duration(rec.delegation.not_after.saturating_sub(now))
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
            vec!["sqns", "lookup", "KEY", "--no-recurse"],
            vec!["sqns", "identity", "KEY"],
            vec!["sqns", "publish", "--key-file", "k", "-D", "d.bin", "-e", "1.2.3.4:5"],
            vec!["sqns", "withdraw", "--key-file", "k", "-D", "d.bin"],
            // Every path flag is optional now, so each command must also parse
            // with nothing but what it truly requires.
            vec!["sqns", "publish", "-e", "1.2.3.4:5"],
            vec!["sqns", "withdraw"],
            vec!["sqns", "keygen"],
            vec!["sqns", "keygen", "--identity"],
            vec!["sqns", "delegate"],
            vec!["sqns", "supersede", "--old-key", "A", "--new-key", "B"],
            vec!["sqns", "revoke", "--key", "A"],
            vec!["sqns", "revoke", "--all"],
            vec!["sqns", "status", "--client-key", "wire.key"],
            vec!["sqns", "keygen", "--out", "k"],
            vec!["sqns", "delegate", "--identity-key", "i", "--service-key", "s", "--out", "d"],
            vec![
                "sqns",
                "delegate",
                "--identity-key",
                "i",
                "--service-key",
                "s",
                "--never-expires",
                "--out",
                "d",
            ],
            vec!["sqns", "supersede", "--old-key", "A", "--new-key", "B", "--identity-key", "i"],
            vec!["sqns", "revoke", "--key", "A", "--identity-key", "i"],
            vec!["sqns", "revoke", "--all", "--identity-key", "i"],
        ];
        for args in cases {
            let cli = Cli::try_parse_from(&args)
                .unwrap_or_else(|e| panic!("{args:?} did not parse: {e}"));
            // Reading the arguments back is what trips an id collision.
            let _ = format!("{:?}", cli.server.servers);
            let _ = format!("{:?}", cli.server.client_key);
            let _ = cli.server.no_recurse;
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
            Command::Withdraw {
                key_file,
                delegation,
                ttl,
            } => format!("{key_file:?}{delegation:?}{ttl}"),
            Command::Status => "status".into(),
            Command::Keygen {
                out,
                identity,
                force,
            } => format!("{out:?}{identity}{force}"),
            Command::Delegate {
                identity_key,
                service_key,
                days,
                never_expires,
                out,
            } => format!("{identity_key:?}{service_key:?}{days}{never_expires}{out:?}"),
            Command::Supersede {
                old_key,
                new_key,
                identity_key,
                reason,
            } => format!("{old_key}{new_key}{identity_key:?}{reason}"),
            Command::Revoke {
                key,
                all,
                identity_key,
                reason,
                yes,
            } => format!("{key:?}{all}{identity_key:?}{reason}{yes}"),
        }
    }

    #[test]
    fn the_config_file_lists_servers_one_per_line() {
        let text = "\
# my servers
sqc://ns1.example.com:5300/EFj2

   sqc://ns2.example.com:5300/AbCd   # the standby
";
        assert_eq!(
            super::servers_from_config(text),
            vec![
                "sqc://ns1.example.com:5300/EFj2".to_string(),
                "sqc://ns2.example.com:5300/AbCd".to_string(),
            ]
        );
        assert!(super::servers_from_config("# nothing but a comment\n\n").is_empty());
    }
}
