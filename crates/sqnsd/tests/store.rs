//! Store behaviour: what it accepts, what it refuses, what survives a restart.

use std::net::Ipv4Addr;

use ed25519_dalek::SigningKey;
use sqns_core::key::{self, PubKey};
use sqns_core::record::{Delegation, Endpoint, Host, Record, RecordBody, SignedRecord, now_unix};
use sqnsd::store::{PutOutcome, Store};

/// A service key, the identity that issued it, and the delegation binding them
/// — the smallest unit that can publish anything.
struct Service {
    identity: SigningKey,
    key: SigningKey,
    delegation: Delegation,
}

impl Service {
    /// A service under a fresh identity of its own.
    fn new() -> Self {
        Self::under(key::generate())
    }

    /// A service under an existing identity, for testing siblings.
    fn under(identity: SigningKey) -> Self {
        let service = key::generate();
        let delegation = Delegation::issue(
            &identity,
            &key::public_of(&service),
            now_unix() + 86_400,
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

    /// A live record, signed by the service key as the node would.
    fn live(&self, serial: u64, port: u16) -> SignedRecord {
        self.live_with(serial, vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), port)])
    }

    fn live_with(&self, serial: u64, endpoints: Vec<Endpoint>) -> SignedRecord {
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

    /// A revocation, signed by the identity as only it can be.
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
}

/// Alter an endpoint after signing, the way an attacker on the wire would.
fn tamper_port(signed: &mut SignedRecord, port: u16) {
    match &mut signed.record.body {
        RecordBody::Live { endpoints } => endpoints[0].port = port,
        _ => panic!("no endpoints to tamper with"),
    }
}

#[test]
fn a_record_can_be_stored_and_read_back() {
    let store = Store::new(None);
    let svc = Service::new();
    let record = svc.live(1, 5300);

    assert_eq!(store.put(record.clone()).unwrap(), PutOutcome::Stored);
    assert_eq!(store.get(&svc.pubkey()).expect("held"), record);
    assert_eq!(store.len(), 1);
}

#[test]
fn a_newer_serial_replaces_an_older_one() {
    let store = Store::new(None);
    let svc = Service::new();
    store.put(svc.live(1, 5300)).unwrap();

    assert_eq!(store.put(svc.live(2, 6000)).unwrap(), PutOutcome::Stored);
    let held = store.get(&svc.pubkey()).unwrap();
    assert_eq!(held.record.serial, 2);
    assert_eq!(held.record.endpoints()[0].port, 6000);
}

#[test]
fn an_older_serial_is_refused() {
    let store = Store::new(None);
    let svc = Service::new();
    store.put(svc.live(9, 5300)).unwrap();

    assert_eq!(store.put(svc.live(8, 6000)).unwrap(), PutOutcome::Stale);
    assert_eq!(store.get(&svc.pubkey()).unwrap().record.serial, 9);
}

#[test]
fn a_forged_record_is_refused() {
    let store = Store::new(None);
    let svc = Service::new();
    let mut record = svc.live(1, 5300);
    tamper_port(&mut record, 31337);

    let err = store.put(record).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
    assert_eq!(store.len(), 0);
}

#[test]
fn a_record_from_the_future_is_refused() {
    let store = Store::new(None);
    let svc = Service::new();
    let mut record = Record::live(
        svc.pubkey(),
        svc.delegation.clone(),
        1,
        300,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 5300)],
    );
    record.issued_at = now_unix() + 3600;

    let err = store.put(record.sign(&svc.key).unwrap()).unwrap_err();
    assert!(err.to_string().contains("future"), "{err}");
}

#[test]
fn an_already_expired_record_is_refused() {
    let store = Store::new(None);
    let svc = Service::new();
    let mut record = Record::live(
        svc.pubkey(),
        svc.delegation.clone(),
        1,
        60,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 5300)],
    );
    record.issued_at = now_unix() - 120;

    assert!(store.put(record.sign(&svc.key).unwrap()).is_err());
    assert_eq!(store.len(), 0);
}

#[test]
fn an_expired_delegation_cannot_publish() {
    let store = Store::new(None);
    let identity = key::generate();
    let service = key::generate();
    let lapsed = Delegation::issue(&identity, &key::public_of(&service), now_unix() - 60);

    let record = Record::live(
        key::public_of(&service),
        lapsed,
        1,
        300,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 5300)],
    )
    .sign(&service)
    .unwrap();

    let err = store.put(record).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
}

#[test]
fn sync_returns_records_from_a_watermark() {
    let store = Store::new(None);
    let services: Vec<Service> = (0..5).map(|_| Service::new()).collect();
    for (i, svc) in services.iter().enumerate() {
        store.put(svc.live(1, 5300 + i as u16)).unwrap();
    }

    let (all, complete) = store.since(0, 100);
    assert_eq!(all.len(), 5);
    assert!(complete);

    let (batch, complete) = store.since(0, 3);
    assert_eq!(batch.len(), 3);
    assert!(!complete, "a full batch reports there may be more");

    // Oldest first, so a watermark walk makes progress.
    let issued: Vec<u64> = all.iter().map(|r| r.record.issued_at).collect();
    assert!(issued.windows(2).all(|w| w[0] <= w[1]));

    let (none, _) = store.since(now_unix() + 60, 100);
    assert!(none.is_empty());
}

#[test]
fn the_revision_counter_tracks_changes() {
    let store = Store::new(None);
    let svc = Service::new();
    let before = store.revision();

    store.put(svc.live(1, 5300)).unwrap();
    let after = store.revision();
    assert!(after > before);

    store.put(svc.live(1, 5300)).ok();
    assert_eq!(store.revision(), after, "a stale put changes nothing");
}

// -- Identities, retirement and bindings --

#[test]
fn one_identity_can_hold_many_service_keys() {
    let store = Store::new(None);
    let identity = key::generate();
    let services: Vec<Service> = (0..3).map(|_| Service::under(identity.clone())).collect();

    for (i, svc) in services.iter().enumerate() {
        store.put(svc.live(1, 5300 + i as u16)).unwrap();
    }

    // Each key resolves on its own, and all three answer to the identity.
    assert_eq!(store.len(), 3);
    for svc in &services {
        assert!(store.get(&svc.pubkey()).is_some());
        assert_eq!(store.identity_of(&svc.pubkey()), Some(svc.identity_pubkey()));
    }
    assert_eq!(
        store
            .identity_records(&key::public_of(&identity), 100)
            .len(),
        3
    );
}

#[test]
fn revoking_one_service_key_leaves_its_siblings_alone() {
    let store = Store::new(None);
    let identity = key::generate();
    let doomed = Service::under(identity.clone());
    let survivor = Service::under(identity);
    store.put(doomed.live(1, 5300)).unwrap();
    store.put(survivor.live(1, 5301)).unwrap();

    store.put(doomed.revoked(2, "stolen")).unwrap();

    assert!(store.get(&doomed.pubkey()).unwrap().record.is_revoked());
    assert!(store.put(doomed.live(u64::MAX, 6000)).is_err());

    // The sibling is untouched and still publishing.
    assert_eq!(
        store.put(survivor.live(2, 5302)).unwrap(),
        PutOutcome::Stored
    );
}

#[test]
fn superseding_a_key_retires_it_and_points_onward() {
    let store = Store::new(None);
    let identity = key::generate();
    let old = Service::under(identity.clone());
    let new = Service::under(identity);
    store.put(old.live(1, 5300)).unwrap();

    store.put(old.superseded(2, new.pubkey())).unwrap();
    assert_eq!(
        store.get(&old.pubkey()).unwrap().record.successor(),
        Some(new.pubkey())
    );

    // The thief still holding the old key cannot publish over its retirement.
    let err = store.put(old.live(u64::MAX, 31337)).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Superseded { .. }), "{err}");

    // And the replacement publishes normally.
    store.put(new.live(1, 5301)).unwrap();
    assert!(store.get(&new.pubkey()).is_some());
}

#[test]
fn a_stranger_identity_cannot_retire_someone_elses_key() {
    let store = Store::new(None);
    let svc = Service::new();
    store.put(svc.live(1, 5300)).unwrap();

    // The attacker mints their own delegation over the key — nothing stops them
    // signing it — and tries to forward it at a key they control.
    let attacker = key::generate();
    let forged = Record::superseded(
        svc.pubkey(),
        Delegation::issue(&attacker, &svc.pubkey(), now_unix() + 86_400),
        2,
        key::public_of(&key::generate()),
        "mine now",
    )
    .sign(&attacker)
    .unwrap();

    let err = store.put(forged).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
    assert!(!store.get(&svc.pubkey()).unwrap().record.is_terminal());
}

#[test]
fn a_key_is_bound_to_its_identity_by_its_very_first_record() {
    let store = Store::new(None);
    let svc = Service::new();
    store.put(svc.live(1, 5300)).unwrap();

    // A second identity claiming the same key is refused, whatever it signs.
    let claimant = key::generate();
    let claimed = Record::live(
        svc.pubkey(),
        Delegation::issue(&claimant, &svc.pubkey(), now_unix() + 86_400),
        2,
        300,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 6000)],
    )
    .sign(&svc.key)
    .unwrap();

    let err = store.put(claimed).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
    assert_eq!(store.identity_of(&svc.pubkey()), Some(svc.identity_pubkey()));
}

#[test]
fn bindings_and_tombstones_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.db");
    let identity = key::generate();
    let live = Service::under(identity.clone());
    let dead = Service::under(identity.clone());

    {
        let store = Store::new(Some(path.clone()));
        store.put(live.live(1, 5300)).unwrap();
        store.put(dead.live(1, 5301)).unwrap();
        store.put(dead.revoked(2, "stolen")).unwrap();
        store.persist().unwrap();
    }

    let reopened = Store::open(Some(path)).unwrap();
    assert_eq!(
        reopened.identity_of(&live.pubkey()),
        Some(live.identity_pubkey()),
        "the binding travels in the snapshot"
    );
    assert!(reopened.get(&dead.pubkey()).unwrap().record.is_revoked());
    assert!(reopened.put(dead.live(u64::MAX, 6000)).is_err());
    assert_eq!(
        reopened
            .identity_records(&key::public_of(&identity), 100)
            .len(),
        2
    );
}

#[test]
fn a_snapshot_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.db");
    let services: Vec<Service> = (0..3).map(|_| Service::new()).collect();

    {
        let store = Store::new(Some(path.clone()));
        for (i, svc) in services.iter().enumerate() {
            store.put(svc.live(1, 5300 + i as u16)).unwrap();
        }
        store.persist().unwrap();
    }

    let reopened = Store::open(Some(path)).unwrap();
    assert_eq!(reopened.len(), 3);
    for (i, svc) in services.iter().enumerate() {
        let held = reopened.get(&svc.pubkey()).expect("record reloaded");
        assert_eq!(held.record.endpoints()[0].port, 5300 + i as u16);
        held.verify().expect("reloaded records are still signed");
    }
}

#[test]
fn a_tampered_snapshot_does_not_load_forged_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.db");
    let svc = Service::new();

    let store = Store::new(Some(path.clone()));
    store.put(svc.live(1, 5300)).unwrap();
    store.persist().unwrap();

    // Flip a byte in the middle of the file: whatever it lands on, the record
    // must not come back as a valid answer.
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    std::fs::write(&path, bytes).unwrap();

    // A structurally broken file failing to load outright is equally acceptable.
    if let Ok(store) = Store::open(Some(path)) {
        assert_eq!(store.len(), 0, "no forged record may load");
    }
}

#[test]
fn a_retirement_is_never_swept() {
    let store = Store::new(None);
    let svc = Service::new();
    let mut record = Record::revoked(svc.pubkey(), svc.delegation.clone(), 1, "stolen");
    record.issued_at = now_unix() - 3600;
    record.ttl = 60; // long lapsed, were it an ordinary record
    store.put(record.sign(&svc.identity).unwrap()).unwrap();

    assert_eq!(store.purge_expired(), 0, "a tombstone must not be swept");
    assert!(store.get(&svc.pubkey()).is_some());
}
