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

fn signed_sample() -> (ed25519_dalek::SigningKey, SignedRecord) {
    let sk = key::generate();
    let record = Record::live(key::public_of(&sk), 7, 300, sample_endpoints());
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
    let record = Record::live(key::public_of(&theirs), 1, 300, sample_endpoints());
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
    let mut record = Record::live(key::public_of(&sk), 1, 60, sample_endpoints());
    record.issued_at = now_unix() - 120;
    let signed = record.sign(&sk).unwrap();
    let err = signed.verify_answer(&signed.key(), now_unix()).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Expired(_)), "{err}");
}

#[test]
fn serial_decides_which_record_wins() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    let old = Record::live(key, 4, 300, sample_endpoints());
    let new = Record::live(key, 5, 300, sample_endpoints());
    assert!(new.supersedes(&old));
    assert!(!old.supersedes(&new));
    assert!(!old.supersedes(&old));
}

#[test]
fn a_refresh_at_the_same_serial_still_wins_on_time() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    let mut old = Record::live(key, 4, 300, sample_endpoints());
    old.issued_at -= 10;
    let new = Record::live(key, 4, 300, sample_endpoints());
    assert!(new.supersedes(&old));
}

#[test]
fn an_empty_record_is_a_withdrawal() {
    let sk = key::generate();
    let record = Record::live(key::public_of(&sk), 1, 300, Vec::new());
    assert!(record.is_withdrawal());
    let signed = record.sign(&sk).unwrap();
    signed.verify().expect("withdrawals are signed like any record");
}

#[test]
fn ttl_bounds_are_enforced() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    assert!(Record::live(key, 1, 5, sample_endpoints()).validate().is_err());
    assert!(
        Record::live(key, 1, 999_999, sample_endpoints())
            .validate()
            .is_err()
    );
    assert!(Record::live(key, 1, 300, sample_endpoints()).validate().is_ok());
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
    let record = Record::live(key::public_of(&sk), 1, 300, sample_endpoints());
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
        Request::Lookup { key: signed.key() },
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
            },
        ),
        (0x81, Response::Answer { record: None }),
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
                peers: 2,
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
        RecordBody::Live { endpoints, .. } => endpoints[0].port = port,
        RecordBody::Revoked { .. } => panic!("no endpoints to tamper with"),
    }
}

// -- Delegations: identity keys, service keys, and rotation --

/// An identity that has delegated to a service key, as a node would hold it.
fn delegated_pair(serial: u64, lifetime: u64) -> (SigningKey, SigningKey, Delegation) {
    let identity = key::generate();
    let service = key::generate();
    let delegation = Delegation::issue(
        &identity,
        key::public_of(&service),
        serial,
        now_unix() + lifetime,
    )
    .expect("issue");
    (identity, service, delegation)
}

fn delegated_record(
    identity: &SigningKey,
    service: &SigningKey,
    delegation: Delegation,
    serial: u64,
) -> SignedRecord {
    Record::delegated(
        key::public_of(identity),
        serial,
        300,
        delegation,
        sample_endpoints(),
    )
    .sign(service)
    .expect("sign with the delegated service key")
}

#[test]
fn a_delegated_record_verifies_and_names_the_key_to_dial() {
    let (identity, service, delegation) = delegated_pair(1, 86_400);
    let signed = delegated_record(&identity, &service, delegation, 1);

    signed.verify().expect("both signatures check out");
    signed
        .verify_answer(&key::public_of(&identity), now_unix())
        .expect("verify_answer");

    // The identity is what was looked up; the service key is what gets dialed.
    assert_eq!(signed.key(), key::public_of(&identity));
    assert_eq!(signed.service_key(), key::public_of(&service));
    assert_ne!(signed.key(), signed.service_key());
}

#[test]
fn a_delegated_record_survives_a_round_trip() {
    let (identity, service, delegation) = delegated_pair(3, 86_400);
    let signed = delegated_record(&identity, &service, delegation, 7);

    let decoded = SignedRecord::decode(&signed.encode()).expect("decode");
    assert_eq!(decoded, signed);
    decoded.verify().expect("signatures survive the round trip");
    assert_eq!(decoded.record.delegation_serial(), 3);
}

#[test]
fn a_delegation_from_the_wrong_identity_is_rejected() {
    let (_, service, delegation) = delegated_pair(1, 86_400);
    let impostor = key::generate();

    // The delegation is real, but it was not issued by this identity.
    assert!(delegation.verify(&key::public_of(&impostor)).is_err());

    let signed = Record::delegated(
        key::public_of(&impostor),
        1,
        300,
        delegation,
        sample_endpoints(),
    )
    .sign(&service)
    .expect("signing succeeds; verification is what must fail");
    let err = signed.verify().unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
}

#[test]
fn only_the_delegated_service_key_can_sign_the_record() {
    let (identity, _, delegation) = delegated_pair(1, 86_400);
    let stranger = key::generate();

    // The identity itself cannot sign once it has delegated.
    let err = Record::delegated(
        key::public_of(&identity),
        1,
        300,
        delegation.clone(),
        sample_endpoints(),
    )
    .sign(&identity)
    .unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");

    let err = Record::delegated(
        key::public_of(&identity),
        1,
        300,
        delegation,
        sample_endpoints(),
    )
    .sign(&stranger)
    .unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
}

#[test]
fn a_tampered_delegation_breaks_verification() {
    let (identity, service, delegation) = delegated_pair(1, 86_400);
    let mut signed = delegated_record(&identity, &service, delegation, 1);

    // Point the delegation at an attacker's key.
    let attacker = key::public_of(&key::generate());
    if let RecordBody::Live {
        delegation: Some(d),
        ..
    } = &mut signed.record.body
    {
        d.service_key = attacker;
    }
    assert!(signed.verify().is_err(), "a swapped service key must not verify");
}

#[test]
fn an_expired_delegation_is_rejected() {
    let identity = key::generate();
    let service = key::generate();
    let delegation = Delegation::issue(
        &identity,
        key::public_of(&service),
        1,
        now_unix() - 60, // already lapsed
    )
    .unwrap();
    let signed = delegated_record(&identity, &service, delegation, 1);

    // The signatures are fine; the authority has simply run out.
    signed.verify().expect("signatures are valid");
    let err = signed
        .verify_answer(&key::public_of(&identity), now_unix())
        .unwrap_err();
    assert!(matches!(err, sqns_core::Error::Delegation(_)), "{err}");
}

#[test]
fn a_newer_delegation_outranks_any_serial_under_an_older_one() {
    let identity = key::generate();
    let stolen = key::generate();
    let fresh = key::generate();
    let d1 = Delegation::issue(&identity, key::public_of(&stolen), 1, now_unix() + 86_400).unwrap();
    let d2 = Delegation::issue(&identity, key::public_of(&fresh), 2, now_unix() + 86_400).unwrap();

    // The thief pushes the record serial as high as it will go.
    let attacker = Record::delegated(
        key::public_of(&identity),
        u64::MAX,
        300,
        d1,
        sample_endpoints(),
    );
    let owner = Record::delegated(key::public_of(&identity), 1, 300, d2, sample_endpoints());

    assert!(owner.supersedes(&attacker), "delegation 2 must win outright");
    assert!(!attacker.supersedes(&owner));
}

#[test]
fn an_undelegated_record_ranks_below_every_delegation() {
    let identity = key::generate();
    let service = key::generate();
    let d = Delegation::issue(&identity, key::public_of(&service), 1, now_unix() + 86_400).unwrap();

    let plain = Record::live(key::public_of(&identity), u64::MAX, 300, sample_endpoints());
    let delegated = Record::delegated(key::public_of(&identity), 1, 300, d, sample_endpoints());

    assert!(delegated.supersedes(&plain));
    assert!(!plain.supersedes(&delegated));
}

// -- Revocation --

#[test]
fn a_revocation_verifies_and_reports_itself() {
    let identity = key::generate();
    let successor = key::public_of(&key::generate());
    let signed = Record::revoked(
        key::public_of(&identity),
        1,
        Some(successor),
        "laptop stolen",
    )
    .sign(&identity)
    .expect("the identity signs its own revocation");

    signed.verify().expect("verify");
    assert!(signed.record.is_revoked());
    assert!(!signed.record.is_withdrawal());

    let err = signed.revocation_error().expect("reports as revoked");
    match err {
        sqns_core::Error::Revoked {
            successor: hint,
            reason,
            ..
        } => {
            assert_eq!(hint, Some(successor.to_string()));
            assert_eq!(reason, "laptop stolen");
        }
        other => panic!("expected Revoked, got {other}"),
    }
}

#[test]
fn a_delegated_service_key_cannot_revoke_its_identity() {
    let (identity, service, _) = delegated_pair(1, 86_400);

    // A revocation carries no delegation, so only the identity key can sign it.
    let err = Record::revoked(key::public_of(&identity), 1, None, "not mine to give")
        .sign(&service)
        .unwrap_err();
    assert!(matches!(err, sqns_core::Error::Signature(_)), "{err}");
}

#[test]
fn a_revocation_never_expires_and_outranks_everything() {
    let identity = key::generate();
    let mut record = Record::revoked(key::public_of(&identity), 1, None, "compromised");
    record.issued_at = now_unix() - 10 * 365 * 86_400;

    assert!(!record.is_expired(now_unix()), "tombstones do not lapse");

    let later = Record::live(key::public_of(&identity), u64::MAX, 300, sample_endpoints());
    assert!(record.supersedes(&later));
    assert!(!later.supersedes(&record), "nothing supersedes a revocation");
}

#[test]
fn a_revocation_survives_a_round_trip() {
    let identity = key::generate();
    let signed = Record::revoked(key::public_of(&identity), 4, None, "rotated out")
        .sign(&identity)
        .unwrap();
    let decoded = SignedRecord::decode(&signed.encode()).unwrap();
    assert_eq!(decoded, signed);
    decoded.verify().unwrap();
}

// -- Delegation files --

#[test]
fn a_delegation_file_survives_a_round_trip() {
    let (identity, _, delegation) = delegated_pair(2, 86_400);
    let file = sqns_core::record::DelegationFile::new(key::public_of(&identity), delegation);

    let decoded = sqns_core::record::DelegationFile::decode(&file.encode()).expect("decode");
    assert_eq!(decoded, file);
    assert_eq!(decoded.identity, key::public_of(&identity));
}

#[test]
fn a_tampered_delegation_file_is_refused() {
    let (identity, _, delegation) = delegated_pair(2, 86_400);
    let mut bytes =
        sqns_core::record::DelegationFile::new(key::public_of(&identity), delegation).encode();

    // Flip a byte inside the delegation body.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    assert!(sqns_core::record::DelegationFile::decode(&bytes).is_err());

    assert!(sqns_core::record::DelegationFile::decode(b"not a delegation").is_err());
}
