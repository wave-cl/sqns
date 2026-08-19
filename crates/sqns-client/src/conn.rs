//! Dialing sqns servers over sQUIC.

use std::time::Duration;

use sqns_core::addr::ServerAddr;
use sqns_core::error::{Error, Result};
use sqns_core::protocol::{ALPN, Request, Response};
use tokio::net::lookup_host;

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
    let candidates: Vec<_> = lookup_host(addr.authority())
        .await
        .map_err(|e| Error::Connection(format!("cannot resolve {}: {e}", addr.authority())))?
        .collect();
    if candidates.is_empty() {
        return Err(Error::Connection(format!(
            "{} resolved to no addresses",
            addr.authority()
        )));
    }

    let mut last_err = None;
    for sock_addr in candidates {
        let config = squic::Config {
            alpn_protocols: vec![ALPN.to_vec()],
            client_key: client_key_hex.clone(),
            handshake_timeout: Some(timeout),
            max_idle_timeout: Duration::from_secs(30),
            keep_alive: Some(Duration::from_secs(10)),
            ..Default::default()
        };
        match squic::dial(sock_addr, addr.key.as_bytes(), config).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last_err = Some(format!("{sock_addr}: {e}")),
        }
    }
    Err(Error::Connection(format!(
        "could not reach {}: {}",
        addr,
        last_err.unwrap_or_else(|| "no candidate addresses".into())
    )))
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
