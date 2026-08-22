//! Encoding, signing and protocol round trips.

use std::net::{Ipv4Addr, Ipv6Addr};

use sqns_core::addr::ServerAddr;
use ed25519_dalek::SigningKey;
use sqns_core::key::{self, PubKey};
use sqns_core::protocol::{ErrorCode, Request, Response, StatusInfo};
use sqns_core::record::{
    Delegation, Endpoint, Host, Record, RecordBody, SignedRecord, now_unix,
};

fn sample_endpoints() -> Vec<Endpoint> {
    vec![
        Endpoint::new(Host::V4(Ipv4Addr::new(203, 0, 113, 7)), 5300)
            .with_priority(10)
            .with_weight(100),
        Endpoint::new(Host::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()), 5300)
            .with_priority(10)
            .with_weight(50),
        Endpoint::new(Host::Name("gateway.example.com".into()), 4433).with_priority(20),
    ]
}

/// A delegation over `service` from a throwaway identity — for tests about
/// something other than who issued the key.
fn any_delegation(service: &SigningKey) -> Delegation {
    Delegation::issue(
        &key::generate(),
        &key::public_of(service),
        now_unix() + 86_400,
    )
}

fn signed_sample() -> (ed25519_dalek::SigningKey, SignedRecord) {
    let sk = key::generate();
    let record = Record::live(key::public_of(&sk), any_delegation(&sk), 7, 300, sample_endpoints());
    let signed = record.sign(&sk).expect("sign");
    (sk, signed)
}

#[test]
fn record_survives_a_round_trip() {
    let (_, signed) = signed_sample();
    let decoded = Record::decode(&signed.record.encode()).expect("decode");
    assert_eq!(decoded, signed.record);
    assert_eq!(decoded.endpoints().len(), 3);
}

#[test]
fn record_encoding_is_deterministic() {
    let (_, signed) = signed_sample();
    assert_eq!(signed.record.encode(), signed.record.encode());
}

#[test]
fn signed_record_survives_a_round_trip() {
    let (_, signed) = signed_sample();
    let decoded = SignedRecord::decode(&signed.encode()).expect("decode");
    assert_eq!(decoded, signed);
    decoded.verify().expect("signature still valid");
}

#[test]
fn a_valid_signature_verifies() {
    let (_, signed) = signed_sample();
    signed.verify().expect("verify");
    signed
        .verify_answer(&signed.key(), now_unix())
        .expect("verify_answer");
}

#[test]
fn tampering_with_an_endpoint_breaks_the_signature() {
    let (_, mut signed) = signed_sample();
    tamper_port(&mut signed, 9999);
    assert!(signed.verify().is_err(), "altered record must not verify");
}

#[test]
fn tampering_with_the_serial_breaks_the_signature() {
    let (_, mut signed) = signed_sample();
    signed.record.serial += 1;
    assert!(signed.verify().is_err());
}

#[test]
fn signing_for_someone_elses_key_is_refused() {
    let mine = key::generate();
    let theirs = key::generate();
    let record = Record::live(key::public_of(&theirs), any_delegation(&theirs), 1, 300, sample_endpoints());
    assert!(
        record.sign(&mine).is_err(),
        "must not sign a record for a key we do not hold"
    );
}

#[test]
fn an_answer_for_the_wrong_key_is_rejected() {
    let (_, signed) = signed_sample();
    let other = key::public_of(&key::generate());
    let err = signed.verify_answer(&other, now_unix()).unwrap_err();
    assert!(matches!(err, sqns_core::Error::KeyMismatch { .. }), "{err}");
}

#[test]
fn an_expired_answer_is_rejected() {
    let sk = key::generate();
    let mut record = Record::live(key::public_of(&sk), any_delegation(&sk), 1, 60, sample_endpoints());
    record.issued_at = now_unix() - 120;
    let signed = record.sign(&sk).unwrap();
    let err = signed.verify_answer(&signed.key(), now_unix()).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Expired(_)), "{err}");
}

#[test]
fn serial_decides_which_record_wins() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    let old = Record::live(key, any_delegation(&sk), 4, 300, sample_endpoints());
    let new = Record::live(key, any_delegation(&sk), 5, 300, sample_endpoints());
    assert!(new.supersedes(&old));
    assert!(!old.supersedes(&new));
    assert!(!old.supersedes(&old));
}

#[test]
fn a_refresh_at_the_same_serial_still_wins_on_time() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    let mut old = Record::live(key, any_delegation(&sk), 4, 300, sample_endpoints());
    old.issued_at -= 10;
    let new = Record::live(key, any_delegation(&sk), 4, 300, sample_endpoints());
    assert!(new.supersedes(&old));
}

#[test]
fn an_empty_record_is_a_withdrawal() {
    let sk = key::generate();
    let record = Record::live(key::public_of(&sk), any_delegation(&sk), 1, 300, Vec::new());
    assert!(record.is_withdrawal());
    let signed = record.sign(&sk).unwrap();
    signed.verify().expect("withdrawals are signed like any record");
}

#[test]
fn ttl_bounds_are_enforced() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    assert!(Record::live(key, any_delegation(&sk), 1, 5, sample_endpoints()).validate().is_err());
    assert!(
        Record::live(key, any_delegation(&sk), 1, 999_999, sample_endpoints())
            .validate()
            .is_err()
    );
    assert!(Record::live(key, any_delegation(&sk), 1, 300, sample_endpoints()).validate().is_ok());
}

#[test]
fn endpoints_parse_from_the_command_line_forms() {
    let ep: Endpoint = "203.0.113.7:5300,priority=10,weight=5".parse().unwrap();
    assert_eq!(ep.host, Host::V4(Ipv4Addr::new(203, 0, 113, 7)));
    assert_eq!((ep.port, ep.priority, ep.weight), (5300, 10, 5));

    let v6: Endpoint = "[2001:db8::1]:443".parse().unwrap();
    assert_eq!(v6.host, Host::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(v6.port, 443);

    let named: Endpoint = "gw.example.com:5300,p=1".parse().unwrap();
    assert_eq!(named.host, Host::Name("gw.example.com".into()));
    assert_eq!(named.priority, 1);

    assert!("203.0.113.7:5300,colour=red".parse::<Endpoint>().is_err());
}

#[test]
fn endpoints_sort_by_priority_then_weight() {
    let sk = key::generate();
    let record = Record::live(key::public_of(&sk), any_delegation(&sk), 1, 300, sample_endpoints());
    let ordered = record.by_priority();
    assert_eq!(ordered[0].weight, 100);
    assert_eq!(ordered[1].weight, 50);
    assert_eq!(ordered[2].priority, 20);
}

#[test]
fn public_keys_round_trip_through_base58_and_hex() {
    let key = key::public_of(&key::generate());
    assert_eq!(key.to_base58().parse::<PubKey>().unwrap(), key);
    assert_eq!(key.to_hex().parse::<PubKey>().unwrap(), key);
    assert_eq!(key.to_string(), key.to_base58());
}

#[test]
fn server_addresses_parse() {
    let key = key::public_of(&key::generate());
    let addr: ServerAddr = format!("sqc://ns1.example.com:5300/{key}").parse().unwrap();
    assert_eq!(addr.host, "ns1.example.com");
    assert_eq!(addr.port, 5300);
    assert_eq!(addr.key, key);

    let defaulted: ServerAddr = format!("sqc://ns1.example.com/{key}").parse().unwrap();
    assert_eq!(defaulted.port, sqns_core::DEFAULT_PORT);

    let v6: ServerAddr = format!("sqc://[2001:db8::1]:5300/{key}").parse().unwrap();
    assert_eq!(v6.host, "2001:db8::1");
    assert_eq!(v6.authority(), "[2001:db8::1]:5300");
    assert_eq!(v6.to_string().parse::<ServerAddr>().unwrap(), v6);

    assert!("sqc://ns1.example.com:5300".parse::<ServerAddr>().is_err());
    assert!(format!("sqc://ns1.example.com:99999/{key}")
        .parse::<ServerAddr>()
        .is_err());
}

#[test]
fn requests_round_trip() {
    let (_, signed) = signed_sample();
    let cases = vec![
        Request::Lookup {
            key: signed.key(),
            recurse: 4,
        },
        Request::LookupIdentity { identity: signed.key() },
        Request::Publish {
            record: Box::new(signed.clone()),
        },
        Request::Status,
        Request::Sync {
            since: 1_700_000_000,
            limit: 64,
        },
    ];
    for req in cases {
        let payload = req.encode_payload();
        let frame_type = match &req {
            Request::Lookup { .. } => 0x01,
            Request::LookupIdentity { .. } => 0x05,
            Request::Publish { .. } => 0x02,
            Request::Status => 0x03,
            Request::Sync { .. } => 0x04,
        };
        assert_eq!(Request::decode(frame_type, &payload).unwrap(), req);
    }
}

#[test]
fn responses_round_trip() {
    let (_, signed) = signed_sample();
    let cases = vec![
        (
            0x81,
            Response::Answer {
                record: Some(Box::new(signed.clone())),
                successor: None,
            },
        ),
        (
            0x81,
            Response::Answer {
                record: None,
                successor: None,
            },
        ),
        (
            0x82,
            Response::Published {
                serial: 42,
                expires_at: 1_700_000_300,
            },
        ),
        (
            0x83,
            Response::Status(StatusInfo {
                records: 3,
                cached: 7,
                peers: 2,
                upstreams: 1,
                uptime_secs: 900,
                version: "0.1.0".into(),
            }),
        ),
        (
            0x84,
            Response::Records {
                records: vec![signed.clone(), signed.clone()],
                complete: false,
            },
        ),
        (
            0xff,
            Response::error(ErrorCode::Stale, "already have serial 9"),
        ),
    ];
    for (frame_type, resp) in cases {
        let payload = resp.encode_payload();
        assert_eq!(Response::decode(frame_type, &payload).unwrap(), resp);
    }
}

#[test]
fn truncated_input_is_an_error_not_a_panic() {
    let (_, signed) = signed_sample();
    let bytes = signed.encode();
    for cut in 1..bytes.len() {
        assert!(SignedRecord::decode(&bytes[..cut]).is_err());
    }
    assert!(Request::decode(0x01, b"short").is_err());
    assert!(Request::decode(0x7f, b"").is_err());
}

/// Alter an endpoint after signing, the way an attacker on the wire would.
fn tamper_port(signed: &mut SignedRecord, port: u16) {
    match &mut signed.record.body {
        RecordBody::Live { endpoints } => endpoints[0].port = port,
        _ => panic!("no endpoints to tamper with"),
    }
}


// -- Delegations: an identity's authority over a service key --

/// A service key and the identity that issued it, as a node would hold them.
fn issued(lifetime: u64) -> (SigningKey, SigningKey, Delegation) {
    let identity = key::generate();
    let service = key::generate();
    let delegation = Delegation::issue(&identity, &key::public_of(&service), now_unix() + lifetime);
    (identity, service, delegation)
}

fn live_under(service: &SigningKey, delegation: &Delegation, serial: u64) -> SignedRecord {
    Record::live(
        key::public_of(service),
        delegation.clone(),
        serial,
        300,
        sample_endpoints(),
    )
    .sign(service)
    .expect("the service key signs its own live records")
}

#[test]
fn a_delegated_record_is_looked_up_by_its_service_key() {
    let (identity, service, delegation) = issued(86_400);
    let signed = live_under(&service, &delegation, 1);

    signed.verify().expect("both signatures check out");
    signed
        .verify_answer(&key::public_of(&service), now_unix())
        .expect("verify_answer");

    // The lookup index is the service key; the identity rides along.
    assert_eq!(signed.key(), key::public_of(&service));
    assert_eq!(signed.identity(), key::public_of(&identity));
}

#[test]
fn a_delegated_record_survives_a_round_trip() {
    let (identity, service, delegation) = issued(86_400);
    let signed = live_under(&service, &delegation, 7);

    let decoded = SignedRecord::decode(&signed.encode()).expect("decode");
    assert_eq!(decoded, signed);
    decoded.verify().expect("signatures survive the round trip");
    assert_eq!(decoded.identity(), key::public_of(&identity));
}

#[test]
fn a_delegation_over_a_different_key_does_not_verify() {
    let (_, _, delegation) = issued(86_400);
    let stranger = key::public_of(&key::generate());

    assert!(delegation.verify(&stranger).is_err());
}

#[test]
fn a_record_signed_by_the_wrong_key_is_rejected() {
    let (identity, service, delegation) = issued(86_400);
    let stranger = key::generate();

    // A live record must be signed by the service key it names.
    for wrong in [&identity, &stranger] {
        let err = Record::live(
            key::public_of(&service),
            delegation.clone(),
            1,
            300,
            sample_endpoints(),
        )
        .sign(wrong)
        .unwrap_err();
        assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
    }
}

#[test]
fn a_swapped_delegation_breaks_verification() {
    let (_, service, delegation) = issued(86_400);
    let mut signed = live_under(&service, &delegation, 1);

    // Re-point the record at an identity of the attacker's choosing.
    signed.record.delegation.identity = key::public_of(&key::generate());
    assert!(signed.verify().is_err(), "a swapped identity must not verify");
}

#[test]
fn an_expired_delegation_is_rejected_for_a_live_record() {
    let identity = key::generate();
    let service = key::generate();
    let lapsed = Delegation::issue(&identity, &key::public_of(&service), now_unix() - 60);
    let signed = live_under(&service, &lapsed, 1);

    signed.verify().expect("signatures are valid");
    let err = signed
        .verify_answer(&key::public_of(&service), now_unix())
        .unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
}

// -- Retirement: superseding and revoking a service key --

#[test]
fn only_the_identity_may_retire_a_delegated_key() {
    let (identity, service, delegation) = issued(86_400);
    let successor = key::public_of(&key::generate());
    let service_pub = key::public_of(&service);

    // The identity can, and the record verifies against the key that was asked
    // for even though the identity signed it.
    let signed = Record::superseded(service_pub, delegation.clone(), 1, successor, "rotated")
    .sign(&identity)
    .expect("the identity retires the keys it issued");
    signed
        .verify_answer(&service_pub, now_unix())
        .expect("verify_answer");
    assert_eq!(signed.record.successor(), Some(successor));

    // The service key itself cannot — this is the whole point of the split.
    let err = Record::superseded(service_pub, delegation, 2, successor, "mine now")
        .sign(&service)
        .unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
}

#[test]
fn a_key_cannot_be_its_own_identity() {
    // Otherwise the key would be its own authority again, by the back door:
    // whoever held it could retire it.
    let sk = key::generate();
    let pubkey = key::public_of(&sk);
    let self_issued = Delegation::issue(&sk, &pubkey, now_unix() + 86_400);

    let record = Record::live(pubkey, self_issued, 1, 300, sample_endpoints());
    let err = record.validate().unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
}

#[test]
fn a_revocation_reports_itself_and_has_no_successor() {
    let (identity, service, delegation) = issued(86_400);
    let signed = Record::revoked(key::public_of(&service), delegation, 1, "laptop stolen")
    .sign(&identity)
    .expect("sign");

    signed.verify().expect("verify");
    assert!(signed.record.is_revoked());
    assert!(signed.record.is_terminal());
    assert_eq!(signed.record.successor(), None);

    match signed.revocation_error().expect("reports as revoked") {
        sqns_core::Error::Revoked { reason, .. } => assert_eq!(reason, "laptop stolen"),
        other => panic!("expected Revoked, got {other}"),
    }
}

#[test]
fn a_key_cannot_be_superseded_by_itself() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    assert!(
        Record::superseded(key, any_delegation(&sk), 1, key, "loop")
            .validate()
            .is_err()
    );
}

#[test]
fn retirement_never_expires_and_outranks_everything() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    let successor = key::public_of(&key::generate());

    let d = any_delegation(&sk);
    for retired in [
        Record::superseded(key, d.clone(), 1, successor, "rotated"),
        Record::revoked(key, d.clone(), 1, "stolen"),
    ] {
        let mut aged = retired.clone();
        aged.issued_at = now_unix() - 10 * 365 * 86_400;
        assert!(!aged.is_expired(now_unix()), "tombstones do not lapse");

        let later = Record::live(key, any_delegation(&sk), u64::MAX, 300, sample_endpoints());
        assert!(retired.supersedes(&later));
        assert!(!later.supersedes(&retired), "nothing supersedes a retirement");
    }
}

#[test]
fn retirement_records_survive_a_round_trip() {
    let (identity, service, delegation) = issued(86_400);
    let successor = key::public_of(&key::generate());
    let service_pub = key::public_of(&service);

    for record in [
        Record::superseded(service_pub, delegation.clone(), 4, successor, "rotated"),
        Record::revoked(service_pub, delegation, 5, "stolen"),
    ] {
        let signed = record.sign(&identity).unwrap();
        let decoded = SignedRecord::decode(&signed.encode()).unwrap();
        assert_eq!(decoded, signed);
        decoded.verify().unwrap();
    }
}

// -- Delegation files --

#[test]
fn a_delegation_file_survives_a_round_trip() {
    let (identity, service, delegation) = issued(86_400);
    let file = sqns_core::record::DelegationFile::new(key::public_of(&service), delegation);

    let decoded = sqns_core::record::DelegationFile::decode(&file.encode()).expect("decode");
    assert_eq!(decoded, file);
    assert_eq!(decoded.identity(), key::public_of(&identity));
    assert_eq!(decoded.service_key, key::public_of(&service));
}

#[test]
fn a_tampered_delegation_file_is_refused() {
    let (_, service, delegation) = issued(86_400);
    let mut bytes =
        sqns_core::record::DelegationFile::new(key::public_of(&service), delegation).encode();

    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    assert!(sqns_core::record::DelegationFile::decode(&bytes).is_err());
    assert!(sqns_core::record::DelegationFile::decode(b"not a delegation").is_err());
}

#[test]
fn a_lookup_carries_a_recursion_budget() {
    let (_, signed) = signed_sample();

    for recurse in [0u8, 1, sqns_core::protocol::DEFAULT_RECURSE] {
        let req = Request::Lookup {
            key: signed.key(),
            recurse,
        };
        assert_eq!(Request::decode(0x01, &req.encode_payload()).unwrap(), req);
    }

    // A caller does not get to spend an unbounded amount of someone else's
    // network on one question.
    let greedy = Request::Lookup {
        key: signed.key(),
        recurse: 255,
    };
    let decoded = Request::decode(0x01, &greedy.encode_payload()).unwrap();
    assert_eq!(
        decoded,
        Request::Lookup {
            key: signed.key(),
            recurse: sqns_core::protocol::MAX_RECURSE,
        }
    );
}
