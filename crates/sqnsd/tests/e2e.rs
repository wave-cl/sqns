//! End-to-end tests over real sQUIC connections on loopback.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqns_client::{Resolver, ResolverConfig};
use sqns_core::addr::ServerAddr;
use sqns_core::key;
use sqns_core::record::{Endpoint, Host, Record, SignedRecord};
use sqnsd::config::Config;
use sqnsd::server;

/// A server running on an ephemeral loopback port.
struct TestServer {
    addr: ServerAddr,
    store: Arc<sqnsd::Store>,
}

fn test_config(peers: Vec<ServerAddr>) -> Config {
    Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        key_file: "unused".into(),
        state_file: None,
        peers,
        allowed_clients: Vec::new(),
        allow_sync: true,
        // Short enough that a test can wait for a pull.
        sync_interval: Duration::from_millis(300),
        persist_interval: Duration::from_secs(3600),
    }
}

async fn start_server(peers: Vec<ServerAddr>) -> TestServer {
    start_server_with(test_config(peers)).await
}

async fn start_server_with(config: Config) -> TestServer {
    let signing_key = key::generate();
    let bound = server::bind(config, signing_key).await.expect("bind");
    let addr = ServerAddr::new("127.0.0.1", bound.local_addr().port(), bound.public_key());
    let store = Arc::clone(bound.store());
    tokio::spawn(async move {
        let _ = server::serve(bound).await;
    });
    TestServer { addr, store }
}

fn client_for(servers: &[&TestServer]) -> Resolver {
    Resolver::new(ResolverConfig {
        servers: servers.iter().map(|s| s.addr.clone()).collect(),
        client_key_hex: None,
        connect_timeout: Duration::from_secs(5),
        // Tests assert on what the server holds, not on a local cache.
        cache: false,
    })
    .expect("resolver")
}

fn endpoints() -> Vec<Endpoint> {
    vec![
        Endpoint::new(Host::V4(Ipv4Addr::new(198, 51, 100, 4)), 443)
            .with_priority(10)
            .with_weight(100),
        Endpoint::new(Host::V6("2001:db8::5".parse().unwrap()), 443)
            .with_priority(10)
            .with_weight(1),
        Endpoint::new(Host::Name("backup.example.com".into()), 4433).with_priority(50),
    ]
}

fn signed(sk: &SigningKey, serial: u64, endpoints: Vec<Endpoint>) -> SignedRecord {
    Record::new(key::public_of(sk), serial, 300, endpoints)
        .sign(sk)
        .expect("sign")
}

/// Poll until `check` passes, or fail after `within`.
async fn eventually(within: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

#[tokio::test]
async fn publish_then_look_up_a_key() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = key::generate();

    let serial = client
        .publish(&signed(&node, 1, endpoints()))
        .await
        .expect("publish");
    assert_eq!(serial, 1);

    let record = client
        .lookup(&key::public_of(&node))
        .await
        .expect("lookup")
        .expect("a record is held");
    assert_eq!(record.record.key, key::public_of(&node));
    assert_eq!(record.record.endpoints.len(), 3);
    record.verify().expect("the answer is signed by the key");
}

#[tokio::test]
async fn resolve_orders_endpoints_by_priority() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = key::generate();
    client.publish(&signed(&node, 1, endpoints())).await.unwrap();

    let ordered = client.resolve(&key::public_of(&node)).await.expect("resolve");
    assert_eq!(ordered.len(), 3);
    assert!(
        ordered[0].priority <= ordered[1].priority,
        "priority 10 endpoints come before priority 50"
    );
    assert_eq!(ordered[2].host, Host::Name("backup.example.com".into()));

    // Both address families survive the round trip.
    assert!(ordered.iter().any(|e| matches!(e.host, Host::V4(_))));
    assert!(ordered.iter().any(|e| e.host.is_ipv6()));
}

#[tokio::test]
async fn an_unpublished_key_resolves_to_nothing() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let stranger = key::public_of(&key::generate());

    assert!(client.lookup(&stranger).await.unwrap().is_none());
    let err = client.resolve(&stranger).await.unwrap_err();
    assert!(matches!(err, sqns_core::Error::Unpublished(_)), "{err}");
}

#[tokio::test]
async fn a_forged_record_is_rejected_by_the_server() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = key::generate();

    let mut forged = signed(&node, 1, endpoints());
    forged.record.endpoints[0].port = 31337;

    let err = client.publish(&forged).await.unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
    assert_eq!(server.store.len(), 0);
}

#[tokio::test]
async fn republishing_updates_the_record() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = key::generate();

    client.publish(&signed(&node, 1, endpoints())).await.unwrap();
    let moved = vec![Endpoint::new(Host::V4(Ipv4Addr::new(203, 0, 113, 9)), 5300)];
    client.publish(&signed(&node, 2, moved)).await.unwrap();

    let record = client
        .lookup(&key::public_of(&node))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.record.serial, 2);
    assert_eq!(record.record.endpoints.len(), 1);
    assert_eq!(record.record.endpoints[0].port, 5300);
}

#[tokio::test]
async fn an_older_serial_cannot_roll_a_record_back() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = key::generate();

    client.publish(&signed(&node, 5, endpoints())).await.unwrap();
    let rollback = vec![Endpoint::new(Host::V4(Ipv4Addr::new(203, 0, 113, 9)), 5300)];
    let err = client.publish(&signed(&node, 4, rollback)).await.unwrap_err();
    assert!(
        matches!(err, sqns_core::Error::Server { code, .. }
            if code == sqns_core::protocol::ErrorCode::Stale as u16),
        "a rollback must be refused as stale, got: {err}"
    );

    let record = client
        .lookup(&key::public_of(&node))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.record.serial, 5);
}

#[tokio::test]
async fn a_withdrawn_key_resolves_to_no_endpoints() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = key::generate();

    client.publish(&signed(&node, 1, endpoints())).await.unwrap();
    client.publish(&signed(&node, 2, Vec::new())).await.unwrap();

    let record = client
        .lookup(&key::public_of(&node))
        .await
        .unwrap()
        .expect("the withdrawal itself is a record");
    assert!(record.record.is_withdrawal());
    assert!(client.resolve(&key::public_of(&node)).await.unwrap().is_empty());
}

#[tokio::test]
async fn status_reports_what_the_server_holds() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    client
        .publish(&signed(&key::generate(), 1, endpoints()))
        .await
        .unwrap();

    let status = client.status().await.expect("status");
    assert_eq!(status.records, 1);
    assert_eq!(status.peers, 0);
    assert_eq!(status.version, sqns_core::VERSION);
}

#[tokio::test]
async fn a_record_published_to_one_server_is_pushed_to_its_peer() {
    let follower = start_server(vec![]).await;
    let leader = start_server(vec![follower.addr.clone()]).await;

    let client = client_for(&[&leader]);
    let node = key::generate();
    client.publish(&signed(&node, 1, endpoints())).await.unwrap();

    let store = Arc::clone(&follower.store);
    let key = key::public_of(&node);
    assert!(
        eventually(Duration::from_secs(5), || store.get(&key).is_some()).await,
        "the peer never received the record"
    );

    // The follower can answer for it, and the answer still verifies.
    let follower_client = client_for(&[&follower]);
    let record = follower_client.lookup(&key).await.unwrap().unwrap();
    record.verify().unwrap();
    assert_eq!(record.record.endpoints.len(), 3);
}

#[tokio::test]
async fn a_new_server_pulls_existing_records_from_its_peer() {
    let seeded = start_server(vec![]).await;
    let client = client_for(&[&seeded]);
    let nodes: Vec<_> = (0..3).map(|_| key::generate()).collect();
    for (i, node) in nodes.iter().enumerate() {
        client
            .publish(&signed(node, i as u64 + 1, endpoints()))
            .await
            .unwrap();
    }

    // A server that starts later catches up by anti-entropy, with no push.
    let latecomer = start_server(vec![seeded.addr.clone()]).await;
    let store = Arc::clone(&latecomer.store);
    assert!(
        eventually(Duration::from_secs(5), || store.len() == 3).await,
        "expected 3 records after sync, found {}",
        store.len()
    );
    for node in &nodes {
        assert!(store.get(&key::public_of(node)).is_some());
    }
}

#[tokio::test]
async fn a_server_can_refuse_to_serve_its_whole_record_set() {
    let mut config = test_config(vec![]);
    config.allow_sync = false;
    let closed = start_server_with(config).await;

    let client = client_for(&[&closed]);
    client
        .publish(&signed(&key::generate(), 1, endpoints()))
        .await
        .unwrap();

    // A peer pointed at it gets nothing, while ordinary lookups still work.
    let latecomer = start_server(vec![closed.addr.clone()]).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(latecomer.store.len(), 0, "sync must have been refused");
    assert_eq!(client.status().await.unwrap().records, 1);
}

#[tokio::test]
async fn a_client_falls_back_to_the_next_server() {
    let live = start_server(vec![]).await;
    let node = key::generate();
    client_for(&[&live])
        .publish(&signed(&node, 1, endpoints()))
        .await
        .unwrap();

    // First server is a dead port; the resolver must move on to the live one.
    let dead = ServerAddr::new("127.0.0.1", 1, live.addr.key);
    let client = Resolver::new(ResolverConfig {
        servers: vec![dead, live.addr.clone()],
        client_key_hex: None,
        connect_timeout: Duration::from_millis(500),
        cache: false,
    })
    .unwrap();

    let record = client.lookup(&key::public_of(&node)).await.expect("lookup");
    assert!(record.is_some());
}

#[tokio::test]
async fn rapid_republishing_is_not_refused_as_stale() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let publisher = sqns_client::Publisher::new(key::generate(), endpoints(), 300);

    // Serials are seeded from the wall clock, so these all land in one second.
    let mut serials = Vec::new();
    for _ in 0..5 {
        serials.push(publisher.publish(&client).await.expect("republish"));
    }
    assert!(
        serials.windows(2).all(|w| w[1] > w[0]),
        "each publish must take a higher serial, got {serials:?}"
    );
    assert_eq!(server.store.len(), 1);
}

#[tokio::test]
async fn a_restarted_publisher_replaces_its_own_earlier_record() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = key::generate();

    sqns_client::Publisher::new(node.clone(), endpoints(), 300)
        .publish(&client)
        .await
        .expect("first publish");

    // A fresh Publisher for the same key, in the same second: its counter
    // starts from the same clock reading and must still take over.
    let moved = vec![Endpoint::new(Host::V4(Ipv4Addr::new(203, 0, 113, 9)), 5300)];
    let restarted = sqns_client::Publisher::new(node.clone(), moved, 300);
    restarted.publish(&client).await.expect("republish after restart");

    let record = client
        .lookup(&key::public_of(&node))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.record.endpoints.len(), 1);
    assert_eq!(record.record.endpoints[0].port, 5300);

    // And the same publisher can withdraw immediately afterwards.
    restarted.withdraw(&client).await.expect("withdraw");
    assert!(
        client
            .lookup(&key::public_of(&node))
            .await
            .unwrap()
            .unwrap()
            .record
            .is_withdrawal()
    );
}
