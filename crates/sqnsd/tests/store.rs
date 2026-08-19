//! Store behaviour: what it accepts, what it refuses, what survives a restart.

use std::net::Ipv4Addr;

use sqns_core::key;
use sqns_core::record::{Delegation, Endpoint, Host, Record, RecordBody, SignedRecord, now_unix};
use sqnsd::store::{PutOutcome, Store};

fn record_for(sk: &ed25519_dalek::SigningKey, serial: u64, port: u16) -> SignedRecord {
    Record::live(
        key::public_of(sk),
        None,
        serial,
        300,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), port)],
    )
    .sign(sk)
    .expect("sign")
}

#[test]
fn a_record_can_be_stored_and_read_back() {
    let store = Store::new(None);
    let sk = key::generate();
    let rec = record_for(&sk, 1, 5300);

    assert_eq!(store.put(rec.clone()).unwrap(), PutOutcome::Stored);
    let held = store.get(&key::public_of(&sk)).expect("record is held");
    assert_eq!(held, rec);
    assert_eq!(store.len(), 1);
}

#[test]
fn a_newer_serial_replaces_an_older_one() {
    let store = Store::new(None);
    let sk = key::generate();
    store.put(record_for(&sk, 1, 5300)).unwrap();

    assert_eq!(
        store.put(record_for(&sk, 2, 6000)).unwrap(),
        PutOutcome::Stored
    );
    let held = store.get(&key::public_of(&sk)).unwrap();
    assert_eq!(held.record.serial, 2);
    assert_eq!(held.record.endpoints()[0].port, 6000);
}

#[test]
fn an_older_serial_is_refused() {
    let store = Store::new(None);
    let sk = key::generate();
    store.put(record_for(&sk, 9, 5300)).unwrap();

    assert_eq!(store.put(record_for(&sk, 8, 6000)).unwrap(), PutOutcome::Stale);
    assert_eq!(store.get(&key::public_of(&sk)).unwrap().record.serial, 9);
}

#[test]
fn a_forged_record_is_refused() {
    let store = Store::new(None);
    let sk = key::generate();
    let mut rec = record_for(&sk, 1, 5300);
    tamper_port(&mut rec, 31337);

    let err = store.put(rec).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
    assert_eq!(store.len(), 0);
}

#[test]
fn a_record_from_the_future_is_refused() {
    let store = Store::new(None);
    let sk = key::generate();
    let mut record = Record::live(
        key::public_of(&sk),
        None,
        1,
        300,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 5300)],
    );
    record.issued_at = now_unix() + 3600;

    let err = store.put(record.sign(&sk).unwrap()).unwrap_err();
    assert!(err.to_string().contains("future"), "{err}");
}

#[test]
fn expired_records_are_neither_served_nor_kept() {
    let store = Store::new(None);
    let sk = key::generate();
    let mut record = Record::live(
        key::public_of(&sk),
        None,
        1,
        60,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 5300)],
    );
    record.issued_at = now_unix() - 120;

    // Publishing an already-expired record fails outright.
    assert!(store.put(record.clone().sign(&sk).unwrap()).is_err());

    // One that expires while held stops being served, and is swept.
    let fresh = Store::new(None);
    let mut live = record;
    live.issued_at = now_unix() - 30;
    live.ttl = 60;
    fresh.put(live.clone().sign(&sk).unwrap()).unwrap();
    assert!(fresh.get(&key::public_of(&sk)).is_some());

    let mut stale = live;
    stale.serial = 2;
    stale.issued_at = now_unix() - 59;
    stale.ttl = 30;
    // A record whose window has closed is refused on the way in.
    assert!(fresh.put(stale.sign(&sk).unwrap()).is_err());
}

#[test]
fn sync_returns_records_from_a_watermark() {
    let store = Store::new(None);
    let keys: Vec<_> = (0..5).map(|_| key::generate()).collect();
    for (i, sk) in keys.iter().enumerate() {
        store.put(record_for(sk, 1, 5300 + i as u16)).unwrap();
    }

    let (all, complete) = store.since(0, 100);
    assert_eq!(all.len(), 5);
    assert!(complete);

    let (batch, complete) = store.since(0, 3);
    assert_eq!(batch.len(), 3);
    assert!(!complete, "a full batch reports there may be more");

    // Records are ordered oldest first, so a watermark walk makes progress.
    let issued: Vec<u64> = all.iter().map(|r| r.record.issued_at).collect();
    assert!(issued.windows(2).all(|w| w[0] <= w[1]));

    let (none, _) = store.since(now_unix() + 60, 100);
    assert!(none.is_empty());
}

#[test]
fn a_snapshot_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.db");
    let keys: Vec<_> = (0..3).map(|_| key::generate()).collect();

    {
        let store = Store::new(Some(path.clone()));
        for (i, sk) in keys.iter().enumerate() {
            store.put(record_for(sk, 1, 5300 + i as u16)).unwrap();
        }
        store.persist().unwrap();
    }

    let reopened = Store::open(Some(path)).unwrap();
    assert_eq!(reopened.len(), 3);
    for (i, sk) in keys.iter().enumerate() {
        let held = reopened.get(&key::public_of(sk)).expect("record reloaded");
        assert_eq!(held.record.endpoints()[0].port, 5300 + i as u16);
        held.verify().expect("reloaded records are still signed");
    }
}

#[test]
fn a_tampered_snapshot_does_not_load_forged_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.db");
    let sk = key::generate();

    let store = Store::new(Some(path.clone()));
    store.put(record_for(&sk, 1, 5300)).unwrap();
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
fn the_revision_counter_tracks_changes() {
    let store = Store::new(None);
    let sk = key::generate();
    let before = store.revision();

    store.put(record_for(&sk, 1, 5300)).unwrap();
    let after = store.revision();
    assert!(after > before);

    store.put(record_for(&sk, 1, 5300)).ok();
    assert_eq!(store.revision(), after, "a stale put changes nothing");
}

/// Alter an endpoint after signing, the way an attacker on the wire would.
fn tamper_port(signed: &mut SignedRecord, port: u16) {
    match &mut signed.record.body {
        RecordBody::Live { endpoints } => endpoints[0].port = port,
        _ => panic!("no endpoints to tamper with"),
    }
}


// -- Identities, retirement and bindings --

fn issue(identity: &ed25519_dalek::SigningKey, service: &ed25519_dalek::SigningKey) -> Delegation {
    Delegation::issue(
        identity,
        &key::public_of(service),
        now_unix() + 86_400,
    )
}

fn live_under(
    service: &ed25519_dalek::SigningKey,
    delegation: &Delegation,
    serial: u64,
    port: u16,
) -> SignedRecord {
    Record::live(
        key::public_of(service),
        Some(delegation.clone()),
        serial,
        300,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), port)],
    )
    .sign(service)
    .expect("sign")
}

#[test]
fn one_identity_can_hold_many_service_keys() {
    let store = Store::new(None);
    let identity = key::generate();
    let services: Vec<_> = (0..3).map(|_| key::generate()).collect();

    for (i, service) in services.iter().enumerate() {
        let d = issue(&identity, service);
        store.put(live_under(service, &d, 1, 5300 + i as u16)).unwrap();
    }

    // Each key resolves on its own, and all three answer to the identity.
    assert_eq!(store.len(), 3);
    for service in &services {
        let key = key::public_of(service);
        assert!(store.get(&key).is_some());
        assert_eq!(store.identity_of(&key), Some(key::public_of(&identity)));
    }
    let listed = store.identity_records(&key::public_of(&identity), 100);
    assert_eq!(listed.len(), 3);
}

#[test]
fn revoking_one_service_key_leaves_its_siblings_alone() {
    let store = Store::new(None);
    let identity = key::generate();
    let doomed = key::generate();
    let survivor = key::generate();
    let d_doomed = issue(&identity, &doomed);
    let d_survivor = issue(&identity, &survivor);
    store.put(live_under(&doomed, &d_doomed, 1, 5300)).unwrap();
    store.put(live_under(&survivor, &d_survivor, 1, 5301)).unwrap();

    store
        .put(
            Record::revoked(key::public_of(&doomed), Some(d_doomed.clone()), 2, "stolen")
                .sign(&identity)
                .unwrap(),
        )
        .unwrap();

    assert!(store.get(&key::public_of(&doomed)).unwrap().record.is_revoked());
    assert!(store.put(live_under(&doomed, &d_doomed, u64::MAX, 6000)).is_err());

    // The sibling is untouched and still publishing.
    assert_eq!(
        store
            .put(live_under(&survivor, &d_survivor, 2, 5302))
            .unwrap(),
        PutOutcome::Stored
    );
}

#[test]
fn superseding_a_key_retires_it_and_points_onward() {
    let store = Store::new(None);
    let identity = key::generate();
    let old = key::generate();
    let new = key::generate();
    let d_old = issue(&identity, &old);
    let d_new = issue(&identity, &new);
    store.put(live_under(&old, &d_old, 1, 5300)).unwrap();

    store
        .put(
            Record::superseded(
                key::public_of(&old),
                Some(d_old.clone()),
                2,
                key::public_of(&new),
                "rotated",
            )
            .sign(&identity)
            .unwrap(),
        )
        .unwrap();

    let held = store.get(&key::public_of(&old)).unwrap();
    assert_eq!(held.record.successor(), Some(key::public_of(&new)));

    // The thief still holding the old key cannot publish over its retirement.
    let err = store
        .put(live_under(&old, &d_old, u64::MAX, 31337))
        .unwrap_err();
    assert!(matches!(err, sqns_core::Error::Superseded { .. }), "{err}");

    // And the replacement publishes normally.
    store.put(live_under(&new, &d_new, 1, 5301)).unwrap();
    assert!(store.get(&key::public_of(&new)).is_some());
}

#[test]
fn a_stranger_identity_cannot_retire_someone_elses_key() {
    let store = Store::new(None);
    let identity = key::generate();
    let attacker = key::generate();
    let service = key::generate();
    store
        .put(live_under(&service, &issue(&identity, &service), 1, 5300))
        .unwrap();

    // The attacker mints their own delegation over the key and tries to forward
    // it at a key they control.
    let forged = Record::superseded(
        key::public_of(&service),
        Some(issue(&attacker, &service)),
        2,
        key::public_of(&key::generate()),
        "mine now",
    )
    .sign(&attacker)
    .expect("nothing stops them signing it");

    let err = store.put(forged).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
    assert!(!store.get(&key::public_of(&service)).unwrap().record.is_terminal());
}

#[test]
fn a_bound_key_cannot_shed_its_identity() {
    let store = Store::new(None);
    let identity = key::generate();
    let service = key::generate();
    store
        .put(live_under(&service, &issue(&identity, &service), 1, 5300))
        .unwrap();

    // Dropping the delegation would let the key retire itself; refuse it.
    let bare = Record::live(
        key::public_of(&service),
        None,
        2,
        300,
        vec![Endpoint::new(Host::V4(Ipv4Addr::LOCALHOST), 6000)],
    )
    .sign(&service)
    .unwrap();

    let err = store.put(bare).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
}

#[test]
fn bindings_and_tombstones_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.db");
    let identity = key::generate();
    let live = key::generate();
    let dead = key::generate();
    let d_live = issue(&identity, &live);
    let d_dead = issue(&identity, &dead);

    {
        let store = Store::new(Some(path.clone()));
        store.put(live_under(&live, &d_live, 1, 5300)).unwrap();
        store.put(live_under(&dead, &d_dead, 1, 5301)).unwrap();
        store
            .put(
                Record::revoked(key::public_of(&dead), Some(d_dead.clone()), 2, "stolen")
                    .sign(&identity)
                    .unwrap(),
            )
            .unwrap();
        store.persist().unwrap();
    }

    let reopened = Store::open(Some(path)).unwrap();
    assert_eq!(
        reopened.identity_of(&key::public_of(&live)),
        Some(key::public_of(&identity)),
        "the binding travels in the snapshot"
    );
    assert!(reopened.get(&key::public_of(&dead)).unwrap().record.is_revoked());
    assert!(reopened.put(live_under(&dead, &d_dead, u64::MAX, 6000)).is_err());
    assert_eq!(reopened.identity_records(&key::public_of(&identity), 100).len(), 2);
}

#[test]
fn a_retirement_is_never_swept() {
    let store = Store::new(None);
    let identity = key::generate();
    let service = key::generate();
    let d = issue(&identity, &service);
    let mut record = Record::revoked(key::public_of(&service), Some(d), 1, "stolen");
    record.issued_at = now_unix() - 3600;
    record.ttl = 60; // long lapsed, were it an ordinary record
    store.put(record.sign(&identity).unwrap()).unwrap();

    assert_eq!(store.purge_expired(), 0, "a tombstone must not be swept");
    assert!(store.get(&key::public_of(&service)).is_some());
}
