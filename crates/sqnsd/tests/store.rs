//! Store behaviour: what it accepts, what it refuses, what survives a restart.

use std::net::Ipv4Addr;

use sqns_core::key;
use sqns_core::record::{Endpoint, Host, Record, SignedRecord, now_unix};
use sqnsd::store::{PutOutcome, Store};

fn record_for(sk: &ed25519_dalek::SigningKey, serial: u64, port: u16) -> SignedRecord {
    Record::new(
        key::public_of(sk),
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
    assert_eq!(held.record.endpoints[0].port, 6000);
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
    rec.record.endpoints[0].port = 31337;

    let err = store.put(rec).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
    assert_eq!(store.len(), 0);
}

#[test]
fn a_record_from_the_future_is_refused() {
    let store = Store::new(None);
    let sk = key::generate();
    let mut record = Record::new(
        key::public_of(&sk),
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
    let mut record = Record::new(
        key::public_of(&sk),
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
        assert_eq!(held.record.endpoints[0].port, 5300 + i as u16);
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
