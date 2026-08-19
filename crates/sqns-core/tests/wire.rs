//! Encoding, signing and protocol round trips.

use std::net::{Ipv4Addr, Ipv6Addr};

use sqns_core::addr::ServerAddr;
use sqns_core::key::{self, PubKey};
use sqns_core::protocol::{ErrorCode, Request, Response, StatusInfo};
use sqns_core::record::{Endpoint, Host, Record, SignedRecord, now_unix};

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
    let record = Record::new(key::public_of(&sk), 7, 300, sample_endpoints());
    let signed = record.sign(&sk).expect("sign");
    (sk, signed)
}

#[test]
fn record_survives_a_round_trip() {
    let (_, signed) = signed_sample();
    let decoded = Record::decode(&signed.record.encode()).expect("decode");
    assert_eq!(decoded, signed.record);
    assert_eq!(decoded.endpoints.len(), 3);
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
    signed.record.endpoints[0].port = 9999;
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
    let record = Record::new(key::public_of(&theirs), 1, 300, sample_endpoints());
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
    let mut record = Record::new(key::public_of(&sk), 1, 60, sample_endpoints());
    record.issued_at = now_unix() - 120;
    let signed = record.sign(&sk).unwrap();
    let err = signed.verify_answer(&signed.key(), now_unix()).unwrap_err();
    assert!(matches!(err, sqns_core::Error::Expired(_)), "{err}");
}

#[test]
fn serial_decides_which_record_wins() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    let old = Record::new(key, 4, 300, sample_endpoints());
    let new = Record::new(key, 5, 300, sample_endpoints());
    assert!(new.supersedes(&old));
    assert!(!old.supersedes(&new));
    assert!(!old.supersedes(&old));
}

#[test]
fn a_refresh_at_the_same_serial_still_wins_on_time() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    let mut old = Record::new(key, 4, 300, sample_endpoints());
    old.issued_at -= 10;
    let new = Record::new(key, 4, 300, sample_endpoints());
    assert!(new.supersedes(&old));
}

#[test]
fn an_empty_record_is_a_withdrawal() {
    let sk = key::generate();
    let record = Record::new(key::public_of(&sk), 1, 300, Vec::new());
    assert!(record.is_withdrawal());
    let signed = record.sign(&sk).unwrap();
    signed.verify().expect("withdrawals are signed like any record");
}

#[test]
fn ttl_bounds_are_enforced() {
    let sk = key::generate();
    let key = key::public_of(&sk);
    assert!(Record::new(key, 1, 5, sample_endpoints()).validate().is_err());
    assert!(
        Record::new(key, 1, 999_999, sample_endpoints())
            .validate()
            .is_err()
    );
    assert!(Record::new(key, 1, 300, sample_endpoints()).validate().is_ok());
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
    let record = Record::new(key::public_of(&sk), 1, 300, sample_endpoints());
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
