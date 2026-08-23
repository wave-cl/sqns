//! Dialing sqns servers over sQUIC.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::protocol::{ALPN, Request, Response};

use tokio::task::JoinSet;

use crate::dns;

/// How long each candidate address gets before the next one is also tried.
///
/// The same idea as Happy Eyeballs (RFC 8305): enough of a head start that a
/// reachable address usually wins without a second connection being opened,
/// short enough that a dead one is not felt.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

/// Open an sQUIC connection to an sqns server.
///
/// `client_key_hex` is an Ed25519 seed giving this caller a stable identity —
/// required when the server whitelists client keys, since a whitelisted server
/// silently drops everyone else.
pub async fn connect(
    addr: &ServerAddr,
    client_key_hex: Option<String>,
    timeout: Duration,
) -> Result<quinn::Connection> {
    connect_with(addr, client_key_hex, timeout, true).await
}

/// As [`connect`], with control over whether an `sqns://` address really has
/// to resolve through DNSSEC.
pub async fn connect_with(
    addr: &ServerAddr,
    client_key_hex: Option<String>,
    timeout: Duration,
    require_dnssec: bool,
) -> Result<quinn::Connection> {
    let all = dns::resolve(addr, require_dnssec).await?;
    if all.is_empty() {
        return Err(Error::Connection(format!("{addr} resolved to no addresses")));
    }

    // Drop addresses this host has no route to, rather than handing them to
    // quinn and letting it fail noisily: a machine without IPv6 would log a
    // "No route to host" warning on every single lookup, for an attempt that
    // was never going to work. If the check rules everything out it is more
    // likely wrong than the network is, so fall back to trying them all and
    // let the real errors speak.
    let routable: Vec<SocketAddr> = all.iter().copied().filter(|a| is_routable(*a)).collect();
    let candidates = if routable.is_empty() {
        all.clone()
    } else {
        if routable.len() < all.len() {
            tracing::debug!(
                skipped = all.len() - routable.len(),
                "ignoring addresses with no route from here"
            );
        }
        routable
    };

    // Race the candidates instead of walking them.
    //
    // Trying them in turn means one dead address costs the whole handshake
    // timeout before the next is attempted, and that is the common case rather
    // than an exotic one: a host with no IPv6 route still gets the AAAA first,
    // and a v4-only client would wait out the full timeout on every single
    // lookup. Each attempt gets a small head start over the next, so a working
    // address answers in its own time and a dead one costs almost nothing.
    let mut attempts = JoinSet::new();
    for (i, sock_addr) in candidates.iter().copied().enumerate() {
        let key = *addr.key.as_bytes();
        let client_key_hex = client_key_hex.clone();
        let stagger = HAPPY_EYEBALLS_DELAY * i as u32;
        attempts.spawn(async move {
            if !stagger.is_zero() {
                tokio::time::sleep(stagger).await;
            }
            let config = squic::Config {
                alpn_protocols: vec![ALPN.to_vec()],
                client_key: client_key_hex,
                handshake_timeout: Some(timeout),
                max_idle_timeout: Duration::from_secs(30),
                keep_alive: Some(Duration::from_secs(10)),
                ..Default::default()
            };
            (sock_addr, squic::dial(sock_addr, &key, config).await)
        });
    }

    let mut errors = Vec::new();
    while let Some(joined) = attempts.join_next().await {
        match joined {
            Ok((sock_addr, Ok(conn))) => {
                tracing::debug!(%sock_addr, "connected");
                // Dropping the set aborts the attempts still in flight.
                return Ok(conn);
            }
            Ok((sock_addr, Err(e))) => errors.push(format!("{sock_addr}: {e}")),
            Err(e) => errors.push(format!("attempt panicked: {e}")),
        }
    }

    // Every address is worth reporting: "the last one failed" hides the fact
    // that the others did too, and which.
    Err(Error::Connection(format!(
        "could not reach {addr}: {}",
        errors.join("; ")
    )))
}

/// Whether this host has a route to `addr`.
///
/// `connect` on a UDP socket only performs a routing lookup — nothing is sent —
/// so the answer is local and immediate.
fn is_routable(addr: SocketAddr) -> bool {
    let bind: SocketAddr = if addr.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    std::net::UdpSocket::bind(bind).is_ok_and(|sock| sock.connect(addr).is_ok())
}

/// Run one request/response exchange on a fresh bidirectional stream.
pub async fn exchange(conn: &quinn::Connection, req: &Request) -> Result<Response> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::Connection(format!("cannot open stream: {e}")))?;
    req.write_to(&mut send).await?;
    send.finish()
        .map_err(|e| Error::Connection(format!("cannot finish stream: {e}")))?;
    Response::read_from(&mut recv).await
}
