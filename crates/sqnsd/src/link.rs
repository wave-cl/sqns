//! A pooled connection to another sqns server.
//!
//! Both replication and upstream resolution talk to other servers the same
//! way: keep a connection open, and re-dial once if the pooled one has gone
//! stale rather than failing the request outright.

use std::time::Duration;

use sqns_client::conn;
use sqns_core::addr::ServerAddr;
use sqns_core::error::Result;
use sqns_core::protocol::{Request, Response};
use tokio::sync::Mutex;

/// A connection to one server, re-established on demand.
pub struct PeerLink {
    addr: ServerAddr,
    conn: Mutex<Option<quinn::Connection>>,
    /// This server's own key, used as the client identity toward the other end
    /// so a server that whitelists its clients can allow us.
    client_key_hex: String,
    connect_timeout: Duration,
}

impl PeerLink {
    pub fn new(addr: ServerAddr, client_key_hex: String, connect_timeout: Duration) -> Self {
        Self {
            addr,
            conn: Mutex::new(None),
            client_key_hex,
            connect_timeout,
        }
    }

    pub fn addr(&self) -> &ServerAddr {
        &self.addr
    }

    /// One exchange, re-dialing if the pooled connection is stale.
    pub async fn request(&self, req: &Request) -> Result<Response> {
        let mut slot = self.conn.lock().await;
        if let Some(conn) = slot.as_ref() {
            match conn::exchange(conn, req).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(peer = %self.addr, error = %e, "re-dialing");
                    *slot = None;
                }
            }
        }
        let conn = conn::connect(
            &self.addr,
            Some(self.client_key_hex.clone()),
            self.connect_timeout,
        )
        .await?;
        let resp = conn::exchange(&conn, req).await?;
        *slot = Some(conn);
        Ok(resp)
    }
}
