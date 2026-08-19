//! Records: the signed mapping from a public key to an endpoint set.
//!
//! A record is signed by the very key it describes, so a client can verify an
//! answer end-to-end. An sqns server — or a peer replicating from one — can
//! withhold a record, but it cannot forge one, alter its endpoints, or replay
//! an older version past its expiry.
//!
//! Canonical encoding (big-endian, no padding):
//!
//! ```text
//! Record   := version:u8 key:[32] serial:u64 issued_at:u64 ttl:u32
//!             n:u8 endpoint*n
//! Endpoint := priority:u16 weight:u16 port:u16 host_type:u8 host
//! host     := [4]        when host_type = 1 (IPv4)
//!           | [16]       when host_type = 2 (IPv6)
//!           | len:u8 utf8 when host_type = 3 (DNS name)
//! Signed   := record_len:u16 record signature:[64]
//! ```
//!
//! The signature covers `SIG_CONTEXT || record_bytes`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

use crate::codec::{Reader, put_short_string};
use crate::error::{Error, Result};
use crate::key::PubKey;

/// Version byte of the record encoding.
pub const RECORD_VERSION: u8 = 1;

/// Domain separation prefix for record signatures.
pub const SIG_CONTEXT: &[u8] = b"sqns-record-v1";

/// A record may carry at most this many endpoints (the count is a u8).
pub const MAX_ENDPOINTS: usize = 255;

/// Shortest accepted TTL, in seconds.
pub const MIN_TTL: u32 = 30;

/// Longest accepted TTL, in seconds (7 days).
pub const MAX_TTL: u32 = 604_800;

/// How far into the future a record's `issued_at` may sit before a server
/// rejects it as clock skew, in seconds.
pub const MAX_CLOCK_SKEW: u64 = 300;

const HOST_V4: u8 = 1;
const HOST_V6: u8 = 2;
const HOST_NAME: u8 = 3;

/// Seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Where a key can be reached: an address literal or a name to resolve.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Name(String),
}

impl Host {
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::V6(_))
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::V4(a) => Some(IpAddr::V4(*a)),
            Self::V6(a) => Some(IpAddr::V6(*a)),
            Self::Name(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(a) => write!(f, "[{a}]"),
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

impl From<IpAddr> for Host {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(a) => Self::V4(a),
            IpAddr::V6(a) => Self::V6(a),
        }
    }
}

impl FromStr for Host {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let unbracketed = s.strip_prefix('[').and_then(|r| r.strip_suffix(']'));
        if let Some(inner) = unbracketed {
            return inner
                .parse::<Ipv6Addr>()
                .map(Self::V6)
                .map_err(|e| Error::Record(format!("bad IPv6 literal '{inner}': {e}")));
        }
        if let Ok(a) = s.parse::<Ipv4Addr>() {
            return Ok(Self::V4(a));
        }
        if let Ok(a) = s.parse::<Ipv6Addr>() {
            return Ok(Self::V6(a));
        }
        if s.is_empty() || s.len() > 255 {
            return Err(Error::Record(format!(
                "host name must be 1..=255 bytes, got {}",
                s.len()
            )));
        }
        if s.chars().any(|c| c.is_whitespace() || c == '/' || c == ':') {
            return Err(Error::Record(format!("invalid host name '{s}'")));
        }
        Ok(Self::Name(s.to_string()))
    }
}

/// One reachable address for a key.
///
/// `priority` is tried in ascending order; `weight` breaks ties within a
/// priority by weighted random choice (a zero-weight endpoint is only used if
/// every endpoint at that priority is zero-weight).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub host: Host,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

impl Endpoint {
    pub fn new(host: Host, port: u16) -> Self {
        Self {
            host,
            port,
            priority: 0,
            weight: 1,
        }
    }

    pub fn with_priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_weight(mut self, weight: u16) -> Self {
        self.weight = weight;
        self
    }

    /// `host:port` with IPv6 bracketed — suitable for a socket lookup.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.priority.to_be_bytes());
        buf.extend_from_slice(&self.weight.to_be_bytes());
        buf.extend_from_slice(&self.port.to_be_bytes());
        match &self.host {
            Host::V4(a) => {
                buf.push(HOST_V4);
                buf.extend_from_slice(&a.octets());
            }
            Host::V6(a) => {
                buf.push(HOST_V6);
                buf.extend_from_slice(&a.octets());
            }
            Host::Name(n) => {
                buf.push(HOST_NAME);
                put_short_string(buf, n);
            }
        }
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let priority = r.u16("endpoint priority")?;
        let weight = r.u16("endpoint weight")?;
        let port = r.u16("endpoint port")?;
        let host = match r.u8("endpoint host type")? {
            HOST_V4 => Host::V4(Ipv4Addr::from(r.array::<4>("IPv4 address")?)),
            HOST_V6 => Host::V6(Ipv6Addr::from(r.array::<16>("IPv6 address")?)),
            HOST_NAME => {
                let name = r.short_string("host name")?;
                if name.is_empty() {
                    return Err(Error::Record("empty host name".into()));
                }
                Host::Name(name)
            }
            other => {
                return Err(Error::Record(format!("unknown host type {other:#x}")));
            }
        };
        Ok(Self {
            host,
            port,
            priority,
            weight,
        })
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} priority={} weight={}",
            self.authority(),
            self.priority,
            self.weight
        )
    }
}

impl FromStr for Endpoint {
    type Err = Error;

    /// `host:port[,priority=N][,weight=N]`, e.g.
    /// `203.0.113.7:5300,priority=10,weight=5` or `[2001:db8::1]:5300`.
    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split(',');
        let authority = parts
            .next()
            .ok_or_else(|| Error::Record(format!("empty endpoint '{s}'")))?
            .trim();
        let (host_str, port) = crate::addr::split_authority(authority)
            .map_err(|e| Error::Record(format!("bad endpoint '{s}': {e}")))?;
        let mut ep = Endpoint::new(host_str.parse::<Host>()?, port);
        for opt in parts {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }
            let (name, value) = opt
                .split_once('=')
                .ok_or_else(|| Error::Record(format!("expected key=value, got '{opt}'")))?;
            let parsed = value
                .trim()
                .parse::<u16>()
                .map_err(|_| Error::Record(format!("'{value}' is not a 0..=65535 value")))?;
            match name.trim() {
                "priority" | "prio" | "p" => ep.priority = parsed,
                "weight" | "w" => ep.weight = parsed,
                other => {
                    return Err(Error::Record(format!(
                        "unknown endpoint option '{other}' (want priority= or weight=)"
                    )));
                }
            }
        }
        Ok(ep)
    }
}

/// The unsigned body of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The key this record speaks for.
    pub key: PubKey,
    /// Monotonic version counter; the highest serial wins on conflict.
    pub serial: u64,
    /// Publication time, seconds since the Unix epoch.
    pub issued_at: u64,
    /// Lifetime in seconds from `issued_at`.
    pub ttl: u32,
    /// Reachable addresses. Empty withdraws the key.
    pub endpoints: Vec<Endpoint>,
}

impl Record {
    pub fn new(key: PubKey, serial: u64, ttl: u32, endpoints: Vec<Endpoint>) -> Self {
        Self {
            key,
            serial,
            issued_at: now_unix(),
            ttl,
            endpoints,
        }
    }

    /// When this record stops being usable.
    pub fn expires_at(&self) -> u64 {
        self.issued_at.saturating_add(self.ttl as u64)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at()
    }

    /// Seconds until expiry, saturating at zero.
    pub fn remaining(&self, now: u64) -> u64 {
        self.expires_at().saturating_sub(now)
    }

    /// A record with no endpoints is a withdrawal: the key is deliberately
    /// unreachable, which is different from never having been published.
    pub fn is_withdrawal(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// True when `self` should replace `other` in a store.
    ///
    /// Serial decides; `issued_at` breaks ties so a republished record with an
    /// unchanged serial still refreshes.
    pub fn supersedes(&self, other: &Record) -> bool {
        (self.serial, self.issued_at) > (other.serial, other.issued_at)
    }

    /// Endpoints in preference order: priority ascending, heavier first.
    pub fn by_priority(&self) -> Vec<&Endpoint> {
        let mut out: Vec<&Endpoint> = self.endpoints.iter().collect();
        out.sort_by_key(|e| (e.priority, std::cmp::Reverse(e.weight)));
        out
    }

    /// Structural checks a server applies before storing.
    pub fn validate(&self) -> Result<()> {
        if self.endpoints.len() > MAX_ENDPOINTS {
            return Err(Error::Record(format!(
                "at most {MAX_ENDPOINTS} endpoints, got {}",
                self.endpoints.len()
            )));
        }
        if !(MIN_TTL..=MAX_TTL).contains(&self.ttl) {
            return Err(Error::Record(format!(
                "ttl must be {MIN_TTL}..={MAX_TTL} seconds, got {}",
                self.ttl
            )));
        }
        self.key.verifying_key()?;
        Ok(())
    }

    /// Canonical bytes — the signature input, and the on-wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(54 + self.endpoints.len() * 12);
        buf.push(RECORD_VERSION);
        buf.extend_from_slice(self.key.as_bytes());
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.push(self.endpoints.len() as u8);
        for ep in &self.endpoints {
            ep.encode_into(&mut buf);
        }
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let rec = Self::decode_from(&mut r)?;
        r.finish("record")?;
        Ok(rec)
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.u8("record version")?;
        if version != RECORD_VERSION {
            return Err(Error::Record(format!(
                "unsupported record version {version} (this build speaks {RECORD_VERSION})"
            )));
        }
        let key = PubKey::new(r.array::<32>("record key")?);
        let serial = r.u64("record serial")?;
        let issued_at = r.u64("record issued_at")?;
        let ttl = r.u32("record ttl")?;
        let count = r.u8("endpoint count")? as usize;
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            endpoints.push(Endpoint::decode_from(r)?);
        }
        Ok(Self {
            key,
            serial,
            issued_at,
            ttl,
            endpoints,
        })
    }

    /// Sign with the key this record speaks for.
    pub fn sign(self, sk: &SigningKey) -> Result<SignedRecord> {
        let signer_pub = crate::key::public_of(sk);
        if signer_pub != self.key {
            return Err(Error::Signature(format!(
                "record is for {} but was signed by {}",
                self.key, signer_pub
            )));
        }
        let body = self.encode();
        let sig = sk.sign(&signed_message(&body));
        Ok(SignedRecord {
            record: self,
            signature: sig.to_bytes(),
        })
    }
}

/// The bytes a record signature actually covers.
fn signed_message(record_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIG_CONTEXT.len() + record_bytes.len());
    msg.extend_from_slice(SIG_CONTEXT);
    msg.extend_from_slice(record_bytes);
    msg
}

/// A record plus the signature made by its own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecord {
    pub record: Record,
    pub signature: [u8; 64],
}

impl SignedRecord {
    pub fn key(&self) -> PubKey {
        self.record.key
    }

    /// Check the signature against the key the record claims.
    pub fn verify(&self) -> Result<()> {
        let vk = self.record.key.verifying_key()?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&signed_message(&self.record.encode()), &sig)
            .map_err(|_| {
                Error::Signature(format!("record for {} is not signed by it", self.record.key))
            })
    }

    /// Verify the signature, that the record answers the key that was asked
    /// for, that it is structurally sound, and that it has not expired.
    ///
    /// This is what a client runs on every answer; it is the reason a hostile
    /// server cannot lie about where a key lives.
    pub fn verify_answer(&self, asked: &PubKey, now: u64) -> Result<()> {
        if self.record.key != *asked {
            return Err(Error::KeyMismatch {
                asked: asked.to_string(),
                got: self.record.key.to_string(),
            });
        }
        self.verify()?;
        self.record.validate()?;
        if self.record.is_expired(now) {
            return Err(Error::Expired(now - self.record.expires_at()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let body = self.record.encode();
        let mut buf = Vec::with_capacity(2 + body.len() + 64);
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let rec = Self::decode_from(&mut r)?;
        r.finish("signed record")?;
        Ok(rec)
    }

    pub fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let len = r.u16("signed record length")? as usize;
        let body = r.bytes(len, "signed record body")?;
        let record = Record::decode(body)?;
        let signature = r.array::<64>("record signature")?;
        Ok(Self { record, signature })
    }

    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.encode());
    }
}
