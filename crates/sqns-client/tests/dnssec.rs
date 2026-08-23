//! Live DNSSEC resolution.
//!
//! These talk to the real DNS, so they are `#[ignore]`d to keep CI hermetic
//! and offline builds quiet. Run them deliberately:
//!
//! ```text
//! cargo test -p sqns-client --test dnssec -- --ignored --nocapture
//! ```

use sqns_client::dns;
use sqns_core::addr::ServerAddr;
use sqns_core::key;

fn addr(text: &str) -> ServerAddr {
    let key = key::public_of(&key::generate());
    format!("{text}/{key}").parse().expect("address")
}

#[tokio::test]
#[ignore = "needs the real DNS"]
async fn a_signed_zone_resolves() {
    // squic.org is signed (DS at the parent, algorithm 13).
    let resolved = dns::resolve(&addr("sqns://ns.squic.org"), true)
        .await
        .expect("a signed zone must resolve under sqns://");
    assert!(!resolved.is_empty());
    assert!(
        resolved.iter().all(|a| a.port() == 5300),
        "sqns:// carries the default port through resolution: {resolved:?}"
    );
    println!("ns.squic.org -> {resolved:?}");
}

/// The public server should answer on both families.
///
/// Only presence is asserted here. Whether an address actually *works* cannot
/// be checked from a machine without IPv6, and most CI has none — the way the
/// broken record was found was by connecting from a v6-capable host and
/// watching it stall for the full handshake timeout, which no unit test can
/// stand in for.
///
/// Note that ns.squic.org publishes `2a01:4f8:1c16:b6b6::`, the base address of
/// its /64. That looks like the classic dropped-suffix typo and originally was
/// one, but the registrar refused `…::1`, so the host now claims the published
/// address instead. It is the subnet-router anycast address, which is
/// unconventional for a host and fine here because nothing else is on that /64.
#[tokio::test]
#[ignore = "needs the real DNS"]
async fn the_public_server_is_dual_stack() {
    let resolved = dns::resolve(&addr("sqns://ns.squic.org"), true)
        .await
        .expect("resolve");
    println!("ns.squic.org -> {resolved:?}");

    assert!(
        resolved.iter().any(|a| a.is_ipv4()),
        "no A record: {resolved:?}"
    );
    assert!(
        resolved.iter().any(|a| a.is_ipv6()),
        "no AAAA record, so IPv6-only clients cannot reach it: {resolved:?}"
    );
}

/// google.com carries no DS record, so DNSSEC calls it Insecure — a perfectly
/// valid outcome, and exactly the case that would sail through if the code
/// only checked for validation *errors*.
const UNSIGNED: &str = "google.com";

/// Signed with deliberately broken signatures.
const BOGUS: &str = "dnssec-failed.org";

#[tokio::test]
#[ignore = "needs the real DNS"]
async fn an_unsigned_zone_is_refused() {
    let err = dns::resolve(&addr(&format!("sqns://{UNSIGNED}")), true)
        .await
        .expect_err("an unsigned zone must not satisfy sqns://");
    let text = err.to_string();
    println!("unsigned refused with: {text}");
    assert!(
        text.contains("not signed"),
        "the error should name the reason, not just fail: {text}"
    );
}

#[tokio::test]
#[ignore = "needs the real DNS"]
async fn a_bogus_zone_is_refused() {
    let err = dns::resolve(&addr(&format!("sqns://{BOGUS}")), true)
        .await
        .expect_err("a broken signature must not satisfy sqns://");
    println!("bogus refused with: {err}");
}

#[tokio::test]
#[ignore = "needs the real DNS"]
async fn the_opt_out_allows_an_unsigned_zone() {
    let resolved = dns::resolve(&addr(&format!("sqns://{UNSIGNED}")), false)
        .await
        .expect("the opt-out exists for exactly this");
    assert!(!resolved.is_empty());
}

#[tokio::test]
#[ignore = "needs the real DNS"]
async fn sqc_addresses_do_not_ask_for_dnssec() {
    // The same unsigned name is fine under sqc://, which promises nothing.
    let resolved = dns::resolve(&addr(&format!("sqc://{UNSIGNED}:5300")), true)
        .await
        .expect("sqc:// makes no DNS promise");
    assert!(!resolved.is_empty());
}

#[tokio::test]
#[ignore = "needs the real DNS"]
async fn an_ip_literal_needs_no_dns_at_all() {
    let resolved = dns::resolve(&addr("sqns://192.0.2.7"), true)
        .await
        .expect("there is no name here to validate");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].to_string(), "192.0.2.7:5300");
}
