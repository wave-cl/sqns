//! `sqc://` addresses — host, port and pinned server key in one string.
//!
//! ```text
//! sqc://ns1.example.com:5300/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5
//! sqc://[2001:db8::1]:5300/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5
//! ```

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::key::PubKey;
use crate::protocol::DEFAULT_PORT;

/// An sqns server: where to reach it, and the key that proves it is the one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddr {
    pub host: String,
    pub port: u16,
    pub key: PubKey,
}

impl ServerAddr {
    pub fn new(host: impl Into<String>, port: u16, key: PubKey) -> Self {
        Self {
            host: host.into(),
            port,
            key,
        }
    }

    /// `host:port`, with IPv6 literals bracketed — ready for DNS/socket lookup.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sqc://{}/{}", self.authority(), self.key)
    }
}

impl FromStr for ServerAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let rest = s.trim().strip_prefix("sqc://").unwrap_or(s.trim());
        let (authority, key_str) = rest.split_once('/').ok_or_else(|| {
            Error::Address(format!(
                "missing '/<base58 key>' in '{s}' (want sqc://host:port/<key>)"
            ))
        })?;
        if key_str.is_empty() {
            return Err(Error::Address(format!("no server key in '{s}'")));
        }
        let key = key_str
            .parse::<PubKey>()
            .map_err(|e| Error::Address(format!("bad server key in '{s}': {e}")))?;
        let (host, port) = split_authority(authority)?;
        Ok(Self { host, port, key })
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
