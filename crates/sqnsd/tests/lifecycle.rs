//! Process lifecycle: the real `sqnsd` binary, started and stopped the way a
//! service manager would.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sqns_client::{Resolver, ResolverConfig};
use sqns_core::addr::ServerAddr;
use sqns_core::key;
use sqns_core::record::{Delegation, Endpoint, Host, Record, now_unix};
use sqnsd::Store;

/// Read the log until the daemon announces where it is listening.
fn wait_for_address(log: &Path, child: &mut Child) -> ServerAddr {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("sqnsd exited early with {status}: {}", read(log));
        }
        let text = read(log);
        if let Some(rest) = text.split("connection string: ").nth(1)
            && let Some(line) = rest.lines().next()
        {
            return line.trim().parse().expect("connection string");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("sqnsd never reported an address: {}", read(log));
}

fn read(path: &Path) -> String {
    let mut buf = String::new();
    if let Ok(mut f) = fs::File::open(path) {
        let _ = f.read_to_string(&mut buf);
    }
    buf
}

fn spawn(key_file: &Path, state_file: &Path, log: &Path) -> Child {
    let out = fs::File::create(log).expect("log file");
    Command::new(env!("CARGO_BIN_EXE_sqnsd"))
        .args(["--key-file", key_file.to_str().unwrap()])
        .args(["--listen", "127.0.0.1:0"])
        .args(["--state-file", state_file.to_str().unwrap()])
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .expect("sqnsd binary")
}

/// A service manager stops a daemon with SIGTERM, not ctrl-C. If that path
/// skipped the final snapshot, everything published since the last periodic
/// write would be lost — including retirement tombstones, which must never
/// evaporate.
#[test]
fn a_sigterm_writes_the_final_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("server.key");
    let state_file = dir.path().join("records.db");
    let log = dir.path().join("sqnsd.log");
    key::save_secret_file(&key_file, &key::generate()).unwrap();

    let mut child = spawn(&key_file, &state_file, &log);
    let addr = wait_for_address(&log, &mut child);

    // Publish well inside the 30s snapshot interval, so only a shutdown write
    // can save this record.
    let node = key::generate();
    let identity = key::generate();
    let delegation = Delegation::issue(&identity, &key::public_of(&node), now_unix() + 86_400);
    let record = Record::live(
        key::public_of(&node),
        delegation,
        1,
        300,
        vec![Endpoint::new(Host::V4(std::net::Ipv4Addr::LOCALHOST), 5300)],
    )
    .sign(&node)
    .unwrap();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let resolver = Resolver::new(ResolverConfig {
            servers: vec![addr],
            connect_timeout: Duration::from_secs(5),
            cache: false,
            ..Default::default()
        })
        .unwrap();
        resolver.publish(&record).await.expect("publish");
    });

    // The snapshot on disk is the one written at startup: it does not have
    // this record, so only a shutdown write can save it.
    let before = Store::open(Some(state_file.clone())).expect("snapshot loads");
    assert_eq!(
        before.len(),
        0,
        "the periodic writer should not have run again this quickly"
    );

    // SIGTERM, the way `systemctl stop` would.
    Command::new("kill")
        .arg(child.id().to_string())
        .status()
        .expect("kill");
    let status = child.wait().expect("sqnsd exits");
    assert!(status.success(), "sqnsd should exit cleanly, got {status}");

    let reopened = Store::open(Some(state_file)).expect("snapshot loads");
    let held = reopened
        .get(&key::public_of(&node))
        .expect("the record survived the stop");
    assert_eq!(held, record);
}
