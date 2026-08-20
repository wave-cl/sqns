//! End-to-end tests over real sQUIC connections on loopback.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqns_client::{Resolver, ResolverConfig};
use sqns_core::addr::ServerAddr;
use sqns_core::key::{self, PubKey};
use sqns_core::record::{Delegation, Endpoint, Host, Record, RecordBody, SignedRecord};
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

/// A service key, the identity that issued it, and their delegation — the
/// smallest unit that can publish anything.
struct Service {
    identity: SigningKey,
    key: SigningKey,
    delegation: Delegation,
}

impl Service {
    fn new() -> Self {
        Self::under(key::generate())
    }

    fn under(identity: SigningKey) -> Self {
        let service = key::generate();
        let delegation = Delegation::issue(
            &identity,
            &key::public_of(&service),
            sqns_core::record::now_unix() + 86_400,
        );
        Self {
            identity,
            key: service,
            delegation,
        }
    }

    fn pubkey(&self) -> PubKey {
        key::public_of(&self.key)
    }

    fn identity_pubkey(&self) -> PubKey {
        key::public_of(&self.identity)
    }

    /// A live record, signed by the service key as its node would.
    fn live(&self, serial: u64, endpoints: Vec<Endpoint>) -> SignedRecord {
        Record::live(
            self.pubkey(),
            self.delegation.clone(),
            serial,
            300,
            endpoints,
        )
        .sign(&self.key)
        .expect("the service key signs its own live records")
    }

    /// A retirement, signed by the identity as only it can be.
    fn revoked(&self, serial: u64, reason: &str) -> SignedRecord {
        Record::revoked(self.pubkey(), self.delegation.clone(), serial, reason)
            .sign(&self.identity)
            .expect("the identity signs retirements")
    }

    fn superseded(&self, serial: u64, successor: PubKey) -> SignedRecord {
        Record::superseded(
            self.pubkey(),
            self.delegation.clone(),
            serial,
            successor,
            "rotated",
        )
        .sign(&self.identity)
        .expect("the identity signs retirements")
    }

    fn publisher(&self, endpoints: Vec<Endpoint>) -> sqns_client::Publisher {
        sqns_client::Publisher::new(self.key.clone(), self.delegation.clone(), endpoints, 300)
            .expect("publisher")
    }
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
    let node = Service::new();

    let serial = client
        .publish(&node.live(1, endpoints()))
        .await
        .expect("publish");
    assert_eq!(serial, 1);

    let record = client
        .lookup(&node.pubkey())
        .await
        .expect("lookup")
        .expect("a record is held");
    assert_eq!(record.record.key, node.pubkey());
    assert_eq!(record.record.endpoints().len(), 3);
    record.verify().expect("the answer is signed by the key");
}

#[tokio::test]
async fn resolve_orders_endpoints_by_priority() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = Service::new();
    client.publish(&node.live(1, endpoints())).await.unwrap();

    let ordered = client.resolve(&node.pubkey()).await.expect("resolve");
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
    let node = Service::new();

    let mut forged = node.live(1, endpoints());
    tamper_port(&mut forged, 31337);

    let err = client.publish(&forged).await.unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
    assert_eq!(server.store.len(), 0);
}

#[tokio::test]
async fn republishing_updates_the_record() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = Service::new();

    client.publish(&node.live(1, endpoints())).await.unwrap();
    let moved = vec![Endpoint::new(Host::V4(Ipv4Addr::new(203, 0, 113, 9)), 5300)];
    client.publish(&node.live(2, moved)).await.unwrap();

    let record = client
        .lookup(&node.pubkey())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.record.serial, 2);
    assert_eq!(record.record.endpoints().len(), 1);
    assert_eq!(record.record.endpoints()[0].port, 5300);
}

#[tokio::test]
async fn an_older_serial_cannot_roll_a_record_back() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = Service::new();

    client.publish(&node.live(5, endpoints())).await.unwrap();
    let rollback = vec![Endpoint::new(Host::V4(Ipv4Addr::new(203, 0, 113, 9)), 5300)];
    let err = client.publish(&node.live(4, rollback)).await.unwrap_err();
    assert!(
        matches!(err, sqns_core::Error::Server { code, .. }
            if code == sqns_core::protocol::ErrorCode::Stale as u16),
        "a rollback must be refused as stale, got: {err}"
    );

    let record = client
        .lookup(&node.pubkey())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.record.serial, 5);
}

#[tokio::test]
async fn a_withdrawn_key_resolves_to_no_endpoints() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let node = Service::new();

    client.publish(&node.live(1, endpoints())).await.unwrap();
    client.publish(&node.live(2, Vec::new())).await.unwrap();

    let record = client
        .lookup(&node.pubkey())
        .await
        .unwrap()
        .expect("the withdrawal itself is a record");
    assert!(record.record.is_withdrawal());
    assert!(client.resolve(&node.pubkey()).await.unwrap().is_empty());
}

#[tokio::test]
async fn status_reports_what_the_server_holds() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    client
        .publish(&Service::new().live(1, endpoints()))
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
    let node = Service::new();
    client.publish(&node.live(1, endpoints())).await.unwrap();

    let store = Arc::clone(&follower.store);
    let key = node.pubkey();
    assert!(
        eventually(Duration::from_secs(5), || store.get(&key).is_some()).await,
        "the peer never received the record"
    );

    // The follower can answer for it, and the answer still verifies.
    let follower_client = client_for(&[&follower]);
    let record = follower_client.lookup(&key).await.unwrap().unwrap();
    record.verify().unwrap();
    assert_eq!(record.record.endpoints().len(), 3);
}

#[tokio::test]
async fn a_new_server_pulls_existing_records_from_its_peer() {
    let seeded = start_server(vec![]).await;
    let client = client_for(&[&seeded]);
    let nodes: Vec<Service> = (0..3).map(|_| Service::new()).collect();
    for (i, node) in nodes.iter().enumerate() {
        client
            .publish(&node.live(i as u64 + 1, endpoints()))
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
        assert!(store.get(&node.pubkey()).is_some());
    }
}

#[tokio::test]
async fn a_server_can_refuse_to_serve_its_whole_record_set() {
    let mut config = test_config(vec![]);
    config.allow_sync = false;
    let closed = start_server_with(config).await;

    let client = client_for(&[&closed]);
    client
        .publish(&Service::new().live(1, endpoints()))
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
    let node = Service::new();
    client_for(&[&live])
        .publish(&node.live(1, endpoints()))
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

    let record = client.lookup(&node.pubkey()).await.expect("lookup");
    assert!(record.is_some());
}

#[tokio::test]
async fn rapid_republishing_is_not_refused_as_stale() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let publisher = Service::new().publisher(endpoints());

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
    let node = Service::new();

    node.publisher(endpoints())
        .publish(&client)
        .await
        .expect("first publish");

    // A fresh Publisher for the same key, in the same second: its counter
    // starts from the same clock reading and must still take over.
    let moved = vec![Endpoint::new(Host::V4(Ipv4Addr::new(203, 0, 113, 9)), 5300)];
    let restarted = node.publisher(moved);
    restarted.publish(&client).await.expect("republish after restart");

    let record = client
        .lookup(&node.pubkey())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.record.endpoints().len(), 1);
    assert_eq!(record.record.endpoints()[0].port, 5300);

    // And the same publisher can withdraw immediately afterwards.
    restarted.withdraw(&client).await.expect("withdraw");
    assert!(
        client
            .lookup(&node.pubkey())
            .await
            .unwrap()
            .unwrap()
            .record
            .is_withdrawal()
    );
}

/// Alter an endpoint after signing, the way an attacker on the wire would.
fn tamper_port(signed: &mut SignedRecord, port: u16) {
    match &mut signed.record.body {
        RecordBody::Live { endpoints } => endpoints[0].port = port,
        _ => panic!("no endpoints to tamper with"),
    }
}

// -- Many services under one identity --

fn moved_endpoints(last_octet: u8) -> Vec<Endpoint> {
    vec![Endpoint::new(
        Host::V4(Ipv4Addr::new(203, 0, 113, last_octet)),
        5300,
    )]
}

#[tokio::test]
async fn one_identity_runs_three_services_each_on_its_own_key() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);

    // Three nodes, three private keys, one identity that issued them all.
    let identity = key::generate();
    let nodes: Vec<Service> = (0..3).map(|_| Service::under(identity.clone())).collect();

    for (i, node) in nodes.iter().enumerate() {
        node.publisher(moved_endpoints(i as u8 + 1))
            .publish(&client)
            .await
            .expect("each node publishes for itself");
    }

    // Each resolves by its own public key, and names the identity behind it.
    for (i, node) in nodes.iter().enumerate() {
        let location = client.resolve_service(&node.pubkey()).await.expect("resolve");
        assert_eq!(location.key, node.pubkey());
        assert!(!location.is_stale());
        assert_eq!(location.identity, node.identity_pubkey());
        assert_eq!(location.endpoints, moved_endpoints(i as u8 + 1));
    }

    // The identity lists all three.
    let listed = client
        .lookup_identity(&key::public_of(&identity))
        .await
        .expect("identity lookup");
    assert_eq!(listed.len(), 3);
}

#[tokio::test]
async fn revoking_one_service_leaves_the_others_running() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let identity = key::generate();
    let nodes: Vec<Service> = (0..3).map(|_| Service::under(identity.clone())).collect();
    for node in &nodes {
        node.publisher(endpoints()).publish(&client).await.unwrap();
    }

    // Node 1's host is breached; the identity revokes just that key.
    let doomed = nodes[1].pubkey();
    client
        .publish(&nodes[1].revoked(99, "host breached"))
        .await
        .expect("revoke");

    let err = client.resolve_service(&doomed).await.unwrap_err();
    assert!(matches!(err, sqns_core::Error::Revoked { .. }), "{err}");
    assert!(
        client
            .publish(&nodes[1].live(u64::MAX, endpoints()))
            .await
            .is_err(),
        "the thief cannot republish the revoked key"
    );

    // The siblings never noticed.
    for i in [0, 2] {
        let location = client
            .resolve_service(&nodes[i].pubkey())
            .await
            .expect("sibling still resolves");
        assert_eq!(location.endpoints.len(), endpoints().len());
        nodes[i]
            .publisher(endpoints())
            .publish(&client)
            .await
            .expect("and still publishes");
    }
}

// -- Rotation: retiring a key and forwarding to its replacement --

#[tokio::test]
async fn a_rotated_key_forwards_to_its_replacement_in_one_exchange() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let identity = key::generate();
    let old = Service::under(identity.clone());
    let new = Service::under(identity);

    old.publisher(endpoints()).publish(&client).await.unwrap();
    new.publisher(moved_endpoints(9))
        .publish(&client)
        .await
        .unwrap();

    // The identity retires the old key, naming its replacement.
    client
        .publish(&old.superseded(99, new.pubkey()))
        .await
        .expect("supersede");

    // A client that only knows the old key still gets there, and learns what to
    // pin from now on.
    let location = client
        .resolve_service(&old.pubkey())
        .await
        .expect("resolve follows the forward");
    assert_eq!(location.requested, old.pubkey());
    assert_eq!(location.key, new.pubkey());
    assert!(location.is_stale(), "the caller's pinned key is out of date");
    assert_eq!(location.superseded_from, vec![old.pubkey()]);
    assert_eq!(location.endpoints, moved_endpoints(9));

    // The thief still holding the old key can publish nothing.
    let err = client
        .publish(&old.live(u64::MAX, endpoints()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("superseded"), "{err}");
}

#[tokio::test]
async fn a_chain_of_rotations_resolves_to_the_end() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let identity = key::generate();
    let keys: Vec<Service> = (0..3).map(|_| Service::under(identity.clone())).collect();

    keys[2]
        .publisher(moved_endpoints(3))
        .publish(&client)
        .await
        .unwrap();
    for hop in 0..2 {
        client
            .publish(&keys[hop].superseded(1, keys[hop + 1].pubkey()))
            .await
            .expect("supersede");
    }

    let location = client
        .resolve_service(&keys[0].pubkey())
        .await
        .expect("two hops resolve");
    assert_eq!(location.key, keys[2].pubkey());
    assert_eq!(location.superseded_from.len(), 2);
    assert_eq!(location.endpoints, moved_endpoints(3));
}

#[tokio::test]
async fn a_rotation_cycle_is_refused_rather_than_followed() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let identity = key::generate();
    let a = Service::under(identity.clone());
    let b = Service::under(identity);

    client.publish(&a.superseded(1, b.pubkey())).await.unwrap();
    client.publish(&b.superseded(1, a.pubkey())).await.unwrap();

    let err = client.resolve_service(&a.pubkey()).await.unwrap_err();
    assert!(
        matches!(err, sqns_core::Error::SupersedeChain(_)),
        "a cycle must error rather than spin: {err}"
    );
}

#[tokio::test]
async fn a_stranger_cannot_forward_someone_elses_key() {
    let server = start_server(vec![]).await;
    let client = client_for(&[&server]);
    let service = Service::new();
    service
        .publisher(endpoints())
        .publish(&client)
        .await
        .unwrap();

    // The attacker mints their own delegation over the key and tries to point
    // it at a key they hold.
    let attacker = key::generate();
    let forged = Record::superseded(
        service.pubkey(),
        Delegation::issue(
            &attacker,
            &service.pubkey(),
            sqns_core::record::now_unix() + 86_400,
        ),
        99,
        key::public_of(&key::generate()),
        "mine now",
    )
    .sign(&attacker)
    .expect("nothing stops them signing it");

    assert!(client.publish(&forged).await.is_err());
    let location = client
        .resolve_service(&service.pubkey())
        .await
        .expect("the real key still resolves");
    assert!(!location.is_stale());
    assert_eq!(location.endpoints.len(), endpoints().len());
}

#[tokio::test]
async fn a_retirement_replicates_to_peers() {
    let follower = start_server(vec![]).await;
    let leader = start_server(vec![follower.addr.clone()]).await;
    let client = client_for(&[&leader]);
    let service = Service::new();
    let key = service.pubkey();

    service
        .publisher(endpoints())
        .publish(&client)
        .await
        .unwrap();
    client
        .publish(&service.revoked(99, "host compromised"))
        .await
        .expect("revoke");

    let store = Arc::clone(&follower.store);
    assert!(
        eventually(Duration::from_secs(5), || store
            .get(&key)
            .is_some_and(|r| r.record.is_revoked()))
        .await,
        "the revocation never reached the peer"
    );
    assert!(
        client_for(&[&follower])
            .publish(&service.live(u64::MAX, endpoints()))
            .await
            .is_err(),
        "the peer must refuse publishes for a revoked key"
    );
}

