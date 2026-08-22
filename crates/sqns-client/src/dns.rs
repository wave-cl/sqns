//! Resolving hostnames, with DNSSEC where the address demands it.
//!
//! An `sqns://` address promises its host was resolved through a validated
//! DNSSEC chain. That validation happens here rather than being taken on trust
//! from the system resolver: the resolvers in `/etc/resolv.conf` are used as
//! transport, and the signatures are checked locally against the root anchor.
//! A resolver that lies, or a network that tampers on the way to one, is
//! caught either way.
//!
//! What this is not: the thing that makes a connection safe. The server's key
//! is in the address and sQUIC pins it, so a forged answer leads to a host
//! that cannot complete a handshake. DNSSEC protects the pointer.

use std::net::SocketAddr;

use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use tokio::net::lookup_host;

/// Resolve an address to the socket addresses worth trying.
///
/// `require_dnssec` is the caller's policy; the address's scheme is what asks
/// for validation in the first place. An IP literal short-circuits: there is
/// no name, so there is nothing to validate.
pub async fn resolve(addr: &ServerAddr, require_dnssec: bool) -> Result<Vec<SocketAddr>> {
    if addr.is_ip_literal() {
        return system_resolve(addr).await;
    }

    if !addr.scheme.requires_dnssec() {
        return system_resolve(addr).await;
    }

    if !require_dnssec {
        tracing::warn!(
            host = %addr.host,
            "resolving an sqns:// address without DNSSEC because it was asked for"
        );
        return system_resolve(addr).await;
    }

    validated_resolve(&addr.host, addr.port).await
}

/// Whatever the operating system says, with no assurance attached.
async fn system_resolve(addr: &ServerAddr) -> Result<Vec<SocketAddr>> {
    let candidates: Vec<SocketAddr> = lookup_host(addr.authority())
        .await
        .map_err(|e| Error::Connection(format!("cannot resolve {}: {e}", addr.authority())))?
        .collect();
    if candidates.is_empty() {
        return Err(Error::Connection(format!(
            "{} resolved to no addresses",
            addr.authority()
        )));
    }
    Ok(candidates)
}

#[cfg(not(feature = "dnssec"))]
async fn validated_resolve(host: &str, _port: u16) -> Result<Vec<SocketAddr>> {
    Err(Error::Address(format!(
        "sqns://{host} needs DNSSEC validation, but this build has the 'dnssec' feature turned \
         off; use an sqc:// address, or an sqns:// one with DNSSEC not required"
    )))
}

#[cfg(feature = "dnssec")]
mod validating {
    use super::*;

    use hickory_resolver::proto::dnssec::Proof;
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::{Resolver, TokioResolver};
    use tokio::sync::OnceCell;

    /// Building a resolver reads the system configuration and sets up a cache,
    /// so it is done once and shared.
    static RESOLVER: OnceCell<TokioResolver> = OnceCell::const_new();

    async fn resolver() -> Result<&'static TokioResolver> {
        RESOLVER
            .get_or_try_init(|| async {
                let mut builder = Resolver::builder_tokio().map_err(|e| {
                    Error::Connection(format!("cannot read the system DNS configuration: {e}"))
                })?;
                // No trust anchor is set, so hickory's built-in root anchor is
                // used: the chain is checked here rather than taken on trust
                // from whoever answered.
                builder.options_mut().validate = true;
                builder.build().map_err(|e| {
                    Error::Connection(format!("cannot build a validating resolver: {e}"))
                })
            })
            .await
    }

    /// Resolve `host`, refusing anything that is not provably signed.
    pub(super) async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let resolver = resolver().await?;
        let lookup = resolver.lookup_ip(host).await.map_err(|e| {
            Error::Address(format!(
                "DNSSEC resolution of {host} failed: {e}. A bogus signature means the answer was \
                 tampered with; a resolver that strips DNSSEC records looks the same from here. \
                 Use sqc:// or allow insecure DNS if this network cannot carry DNSSEC."
            ))
        })?;

        // An unsigned zone is a perfectly valid DNSSEC outcome — Insecure, not
        // an error — so it has to be refused explicitly rather than relied on
        // to fail above.
        let mut addrs = Vec::new();
        let mut unproven = 0usize;
        for record in lookup.as_lookup().answers() {
            if !matches!(record.record_type(), RecordType::A | RecordType::AAAA) {
                continue;
            }
            if record.proof != Proof::Secure {
                unproven += 1;
                continue;
            }
            if let Some(ip) = record.data.ip_addr() {
                addrs.push(SocketAddr::new(ip, port));
            }
        }

        if addrs.is_empty() {
            if unproven > 0 {
                return Err(Error::Address(format!(
                    "{host} resolved, but the answer is not signed (DNSSEC proof was not Secure \
                     for {unproven} record(s)). An sqns:// address requires a signed zone: use \
                     sqc:// instead, or allow insecure DNS."
                )));
            }
            return Err(Error::Address(format!("{host} resolved to no addresses")));
        }
        if unproven > 0 {
            tracing::warn!(host, unproven, "ignoring answers without a DNSSEC proof");
        }
        Ok(addrs)
    }
}

#[cfg(feature = "dnssec")]
async fn validated_resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    validating::resolve(host, port).await
}
