//! Server addresses — host, port and pinned server key in one string.
//!
//! ```text
//! sqns://ns.example.com/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5
//! sqc://ns1.example.com:5300/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5
//! sqc://[2001:db8::1]:5300/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5
//! ```
//!
//! `sqns://` is the sqns-specific form: the port defaults to 5300 and the
//! hostname must resolve through DNSSEC. `sqc://` is the generic sQUIC form
//! and promises nothing about how the name is resolved.
//!
//! Neither scheme is what makes a connection safe. The key is in the string
//! and sQUIC pins it, so a spoofed DNS answer reaches a host that cannot
//! complete the handshake. DNSSEC protects the pointer, not the identity.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::key::PubKey;
use crate::protocol::DEFAULT_PORT;

/// How an address was written, which decides how its host is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `sqc://` — generic sQUIC. The host is resolved however the system
    /// resolves names, with no assurance attached.
    Sqc,
    /// `sqns://` — an sqns server. The port defaults to 5300 and the host must
    /// resolve through a validated DNSSEC chain.
    Sqns,
}

impl Scheme {
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Sqc => "sqc://",
            Self::Sqns => "sqns://",
        }
    }

    /// Whether resolving this address demands a validated DNSSEC chain.
    pub fn requires_dnssec(&self) -> bool {
        matches!(self, Self::Sqns)
    }
}

/// An sqns server: where to reach it, and the key that proves it is the one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddr {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub key: PubKey,
}

impl ServerAddr {
    /// An `sqc://` address, which carries no promise about name resolution.
    pub fn new(host: impl Into<String>, port: u16, key: PubKey) -> Self {
        Self {
            scheme: Scheme::Sqc,
            host: host.into(),
            port,
            key,
        }
    }

    /// An `sqns://` address, whose host must resolve through DNSSEC.
    pub fn new_sqns(host: impl Into<String>, port: u16, key: PubKey) -> Self {
        Self {
            scheme: Scheme::Sqns,
            host: host.into(),
            port,
            key,
        }
    }

    /// True when this host is an IP literal, so no DNS is involved and there
    /// is nothing for DNSSEC to say.
    pub fn is_ip_literal(&self) -> bool {
        self.host.parse::<std::net::IpAddr>().is_ok()
    }

    /// `host:port`, with IPv6 literals bracketed — ready for DNS/socket lookup.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The authority as a human would write it, leaving out the port when it
    /// is the default. Both schemes parse a missing port as
    /// [`DEFAULT_PORT`](crate::protocol::DEFAULT_PORT), so this round-trips.
    fn written_authority(&self) -> String {
        if self.port != DEFAULT_PORT {
            return self.authority();
        }
        if self.host.contains(':') {
            // Keep IPv6 bracketed even without a port, so it stays unambiguous.
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}

impl fmt::Display for ServerAddr {
    /// Emits the scheme the address carries, so a round trip through a config
    /// file or a log line cannot quietly downgrade an `sqns://` address.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}/{}",
            self.scheme.prefix(),
            self.written_authority(),
            self.key
        )
    }
}

impl FromStr for ServerAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        let (scheme, rest) = match trimmed.strip_prefix("sqns://") {
            Some(rest) => (Scheme::Sqns, rest),
            // A bare host:port/key stays sqc://, as it always was.
            None => (
                Scheme::Sqc,
                trimmed.strip_prefix("sqc://").unwrap_or(trimmed),
            ),
        };
        let (authority, key_str) = rest.split_once('/').ok_or_else(|| {
            Error::Address(format!(
                "missing '/<base58 key>' in '{s}' (want sqns://host/<key>)"
            ))
        })?;
        if key_str.is_empty() {
            return Err(Error::Address(format!("no server key in '{s}'")));
        }
        let key = key_str
            .parse::<PubKey>()
            .map_err(|e| Error::Address(format!("bad server key in '{s}': {e}")))?;
        let (host, port) = split_authority(authority)?;
        Ok(Self {
            scheme,
            host,
            port,
            key,
        })
    }
}

/// Split `host`, `host:port`, `[v6]` or `[v6]:port` into its parts.
pub fn split_authority(authority: &str) -> Result<(String, u16)> {
    if authority.is_empty() {
        return Err(Error::Address("empty host".into()));
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| Error::Address(format!("unclosed '[' in '{authority}'")))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None => DEFAULT_PORT,
        };
        return Ok((host.to_string(), port));
    }
    // A bare IPv6 literal has more than one colon and no port.
    if authority.matches(':').count() > 1 {
        return Ok((authority.to_string(), DEFAULT_PORT));
    }
    match authority.split_once(':') {
        Some((host, p)) => Ok((host.to_string(), parse_port(p)?)),
        None => Ok((authority.to_string(), DEFAULT_PORT)),
    }
}

fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>()
        .map_err(|_| Error::Address(format!("invalid port '{s}'")))
}
