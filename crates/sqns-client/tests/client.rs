//! Cache expiry and endpoint ordering.

use std::net::Ipv4Addr;

use sqns_client::Cache;
use rand::SeedableRng;
use sqns_client::select::order_with;
use sqns_core::key;
use sqns_core::record::{Endpoint, Host, Record, SignedRecord, now_unix};

fn record_with(ttl: u32, age: u64, endpoints: Vec<Endpoint>) -> SignedRecord {
    let sk = key::generate();
    let mut record = Record::live(key::public_of(&sk), None, 1, ttl, endpoints);
    record.issued_at = now_unix() - age;
    record.sign(&sk).expect("sign")
}

fn ep(last_octet: u8, priority: u16, weight: u16) -> Endpoint {
    Endpoint::new(Host::V4(Ipv4Addr::new(198, 51, 100, last_octet)), 443)
        .with_priority(priority)
        .with_weight(weight)
}

#[test]
fn the_cache_serves_a_live_record() {
    let cache = Cache::new();
    let rec = record_with(300, 0, vec![ep(1, 0, 1)]);
    cache.put(rec.clone());

    assert_eq!(cache.get(&rec.key()), Some(Some(rec)));
}

#[test]
fn the_cache_drops_a_record_at_its_expiry() {
    let cache = Cache::new();
    let stale = record_with(60, 120, vec![ep(1, 0, 1)]);
    cache.put(stale.clone());

    assert!(
        cache.get(&stale.key()).is_none(),
        "an expired record must not be served from cache"
    );
    assert_eq!(cache.purge(), 0, "the failed lookup already evicted it");
}

#[test]
fn the_cache_remembers_a_negative_answer() {
    let cache = Cache::new();
    let missing = key::public_of(&key::generate());
    cache.put_missing(missing);

    assert_eq!(cache.get(&missing), Some(None));
    cache.invalidate(&missing);
    assert_eq!(cache.get(&missing), None);
}

#[test]
fn purge_clears_what_has_lapsed() {
    let cache = Cache::new();
    cache.put(record_with(300, 0, vec![ep(1, 0, 1)]));
    cache.put(record_with(60, 120, vec![ep(2, 0, 1)]));
    assert_eq!(cache.len(), 2);

    assert_eq!(cache.purge(), 1);
    assert_eq!(cache.len(), 1);
    cache.clear();
    assert!(cache.is_empty());
}

#[test]
fn ordering_keeps_priority_bands_intact() {
    let sk = key::generate();
    let record = Record::live(
        key::public_of(&sk),
        None,
        1,
        300,
        vec![ep(1, 20, 1), ep(2, 10, 1), ep(3, 10, 1), ep(4, 30, 1)],
    );

    for seed in 0..32u64 {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let ordered = order_with(&record, &mut rng);
        let priorities: Vec<u16> = ordered.iter().map(|e| e.priority).collect();
        assert_eq!(priorities, vec![10, 10, 20, 30], "seed {seed}");
        assert_eq!(ordered.len(), 4);
    }
}

#[test]
fn weight_decides_the_order_within_a_band() {
    let sk = key::generate();
    let record = Record::live(
        key::public_of(&sk),
        None,
        1,
        300,
        // Same priority: the heavy endpoint should usually come first.
        vec![ep(1, 10, 1), ep(2, 10, 999)],
    );

    let heavy = Host::V4(Ipv4Addr::new(198, 51, 100, 2));
    let mut heavy_first = 0;
    for seed in 0..200u64 {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        if order_with(&record, &mut rng)[0].host == heavy {
            heavy_first += 1;
        }
    }
    assert!(
        heavy_first > 180,
        "a 999:1 weight should lead in nearly every draw, led in {heavy_first}/200"
    );
}

#[test]
fn every_endpoint_appears_exactly_once() {
    let sk = key::generate();
    let record = Record::live(
        key::public_of(&sk),
        None,
        1,
        300,
        vec![ep(1, 10, 0), ep(2, 10, 5), ep(3, 10, 5), ep(4, 20, 0)],
    );

    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let ordered = order_with(&record, &mut rng);
    assert_eq!(ordered.len(), 4);
    let mut seen: Vec<_> = ordered.iter().map(|e| e.host.clone()).collect();
    seen.sort_by_key(|h| h.to_string());
    seen.dedup();
    assert_eq!(seen.len(), 4, "zero-weight endpoints must still be listed");
}
