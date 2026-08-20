//! Records: the signed mapping from a public key to an endpoint set.
//!
//! A record is signed under the authority of the key it describes, so a client
//! can verify an answer end-to-end. An sqns server — or a peer replicating from
//! one — can withhold a record, but it cannot forge one, alter its endpoints,
//! or replay an older version past its expiry.
//!
//! # Service keys and identities
//!
//! A record's `key` is a **service key**: the key in `sqc://host:port/<key>`,
//! the key sQUIC pins, and the key clients look up. The service key signs its
//! own records, so it can refresh them every few minutes on the host that holds
//! it.
//!
//! Every record carries a [`Delegation`] binding its service key to an
//! **identity key**, which is meant to live offline. The identity does one job,
//! and it is the one job the service key must not be able to do itself: retire
//! the service key. It can [`RecordBody::Superseded`] it — retiring it and
//! naming the replacement clients should move to — or [`RecordBody::Revoked`]
//! it outright.
//!
//! There is deliberately no way to publish without an identity. A key that
//! answered for itself would be its own authority, which means whoever stole it
//! would be too: they could retire it out of the owner's reach, and no server
//! could tell the two apart. Requiring a delegation makes retirement something
//! only a key kept elsewhere can do.
//!
//! One identity may issue any number of service keys. Each resolves
//! independently under its own public key, and each is rotated and revoked
//! without touching the others, so three nodes of the same service are three
//! service keys with three private keys on three hosts.
//!
//! Canonical encoding (big-endian, no padding):
//!
//! ```text
//! Record     := version:u8 key:[32] Delegation
//!               serial:u64 issued_at:u64 ttl:u32 body_kind:u8 body
//! body       := n:u8 endpoint*n                  when body_kind = 1 (Live)
//!             | successor:[32] reason_len:u16 utf8  when body_kind = 2 (Superseded)
//!             | reason_len:u16 utf8              when body_kind = 3 (Revoked)
//! Delegation := identity:[32] not_after:u64 signature:[64]
//! Endpoint   := priority:u16 weight:u16 port:u16 host_type:u8 host
//! host       := [4]         when host_type = 1 (IPv4)
//!             | [16]        when host_type = 2 (IPv6)
//!             | len:u8 utf8 when host_type = 3 (DNS name)
//! Signed     := record_len:u16 record signature:[64]
//! ```
//!
//! A record signature covers `SIG_CONTEXT || record_bytes`; a delegation
//! signature covers `DELEGATION_CONTEXT || identity || service_key ||
//! not_after`. The two contexts differ so neither signature can be replayed as
//! the other.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

use crate::codec::{Reader, put_short_string, put_string};
use crate::error::{Error, Result};
use crate::key::PubKey;

/// Version byte of the record encoding.
pub const RECORD_VERSION: u8 = 4;

/// Domain separation prefix for record signatures.
pub const SIG_CONTEXT: &[u8] = b"sqns-record-v4";

/// Domain separation prefix for delegation signatures.
pub const DELEGATION_CONTEXT: &[u8] = b"sqns-delegation-v2";

/// Longest a delegation may be valid for, in seconds (365 days).
pub const MAX_DELEGATION_LIFETIME: u64 = 31_536_000;

/// A `not_after` of this value means the delegation never expires — for
/// operators who would rather not have a renewal cadence to forget.
pub const NEVER_EXPIRES: u64 = u64::MAX;

/// Default delegation lifetime, in seconds (90 days).
pub const DEFAULT_DELEGATION_LIFETIME: u64 = 7_776_000;

/// Longest accepted revocation reason, in bytes.
pub const MAX_REASON_LEN: usize = 256;

/// A record may carry at most this many endpoints (the count is a u8).
pub const MAX_ENDPOINTS: usize = 255;

/// Shortest accepted TTL, in seconds.
pub const MIN_TTL: u32 = 30;

/// Longest accepted TTL, in seconds (7 days).
pub const MAX_TTL: u32 = 604_800;

/// How far into the future a record's `issued_at` may sit before a server
/// rejects it as clock skew, in seconds.
pub const MAX_CLOCK_SKEW: u64 = 300;

const BODY_LIVE: u8 = 1;
const BODY_SUPERSEDED: u8 = 2;
const BODY_REVOKED: u8 = 3;

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

/// An identity key's grant of authority over a service key.
///
/// Issued offline, wherever the identity key lives, and carried inside every
/// record the service key publishes. It binds the two keys together so that a
/// [`RecordBody::Superseded`] or [`RecordBody::Revoked`] record signed by the
/// identity can retire the service key — the one thing the service key cannot
/// do for itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The identity that issued this service key and may retire it.
    pub identity: PubKey,
    /// Absolute expiry, seconds since the Unix epoch.
    pub not_after: u64,
    /// Signature by the identity key.
    pub signature: [u8; 64],
}

impl Delegation {
    /// The bytes a delegation signature covers.
    fn signed_message(identity: &PubKey, service_key: &PubKey, not_after: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(DELEGATION_CONTEXT.len() + 72);
        msg.extend_from_slice(DELEGATION_CONTEXT);
        msg.extend_from_slice(identity.as_bytes());
        msg.extend_from_slice(service_key.as_bytes());
        msg.extend_from_slice(&not_after.to_be_bytes());
        msg
    }

    /// Issue a delegation over `service_key`. Run this offline.
    pub fn issue(identity: &SigningKey, service_key: &PubKey, not_after: u64) -> Self {
        let identity_pub = crate::key::public_of(identity);
        let msg = Self::signed_message(&identity_pub, service_key, not_after);
        Self {
            identity: identity_pub,
            not_after,
            signature: identity.sign(&msg).to_bytes(),
        }
    }

    /// Check that this delegation really covers `service_key`.
    pub fn verify(&self, service_key: &PubKey) -> Result<()> {
        let vk = self.identity.verifying_key()?;
        let sig = Signature::from_bytes(&self.signature);
        let msg = Self::signed_message(&self.identity, service_key, self.not_after);
        vk.verify(&msg, &sig).map_err(|_| {
            Error::Delegation(format!(
                "the delegation over {service_key} is not signed by {}",
                self.identity
            ))
        })
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.not_after != NEVER_EXPIRES && now >= self.not_after
    }

    pub fn never_expires(&self) -> bool {
        self.not_after == NEVER_EXPIRES
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.identity.as_bytes());
        buf.extend_from_slice(&self.not_after.to_be_bytes());
        buf.extend_from_slice(&self.signature);
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            identity: PubKey::new(r.array::<32>("delegation identity")?),
            not_after: r.u64("delegation not_after")?,
            signature: r.array::<64>("delegation signature")?,
        })
    }
}

/// What a record says about its service key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordBody {
    /// The key is in service at these endpoints. Empty withdraws it.
    Live { endpoints: Vec<Endpoint> },
    /// The key is retired and its identity issued `successor` in its place.
    /// Terminal: nothing is accepted for this key again, and lookups forward.
    Superseded { successor: PubKey, reason: String },
    /// The key is dead with no replacement. Terminal.
    Revoked { reason: String },
}

/// The unsigned body of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The service key this record speaks for — the lookup index.
    pub key: PubKey,
    /// Binding to the identity that issued this key. Every record has one:
    /// without it the key would be its own authority, and so would its thief.
    pub delegation: Delegation,
    /// Monotonic version counter; the highest serial wins.
    pub serial: u64,
    /// Publication time, seconds since the Unix epoch.
    pub issued_at: u64,
    /// Lifetime in seconds from `issued_at`. Ignored for terminal records,
    /// which never expire.
    pub ttl: u32,
    pub body: RecordBody,
}

impl Record {
    /// A record advertising endpoints for a service key.
    pub fn live(
        key: PubKey,
        delegation: Delegation,
        serial: u64,
        ttl: u32,
        endpoints: Vec<Endpoint>,
    ) -> Self {
        Self {
            key,
            delegation,
            serial,
            issued_at: now_unix(),
            ttl,
            body: RecordBody::Live { endpoints },
        }
    }

    /// Retire `key`, forwarding lookups to `successor`. Signed by its identity.
    pub fn superseded(
        key: PubKey,
        delegation: Delegation,
        serial: u64,
        successor: PubKey,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            key,
            delegation,
            serial,
            issued_at: now_unix(),
            ttl: MAX_TTL,
            body: RecordBody::Superseded {
                successor,
                reason: reason.into(),
            },
        }
    }

    /// Retire `key` with no replacement. Signed by its identity.
    pub fn revoked(
        key: PubKey,
        delegation: Delegation,
        serial: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            key,
            delegation,
            serial,
            issued_at: now_unix(),
            ttl: MAX_TTL,
            body: RecordBody::Revoked {
                reason: reason.into(),
            },
        }
    }

    /// The identity that issued this service key.
    pub fn identity(&self) -> PubKey {
        self.delegation.identity
    }

    /// The key whose signature this record must carry.
    ///
    /// A live record is signed by the service key itself, so publishing stays
    /// on the host. Retiring it takes the identity — which is exactly what a
    /// thief who stole the service key does not have.
    pub fn expected_signer(&self) -> PubKey {
        match self.body {
            RecordBody::Live { .. } => self.key,
            RecordBody::Superseded { .. } | RecordBody::Revoked { .. } => self.identity(),
        }
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        match &self.body {
            RecordBody::Live { endpoints } => endpoints,
            _ => &[],
        }
    }

    /// The key this record forwards to, if it was superseded.
    pub fn successor(&self) -> Option<PubKey> {
        match &self.body {
            RecordBody::Superseded { successor, .. } => Some(*successor),
            _ => None,
        }
    }

    pub fn is_superseded(&self) -> bool {
        matches!(self.body, RecordBody::Superseded { .. })
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.body, RecordBody::Revoked { .. })
    }

    /// True for a record that retires its key: nothing is ever accepted for
    /// that key afterwards, and the record itself never expires.
    pub fn is_terminal(&self) -> bool {
        self.is_superseded() || self.is_revoked()
    }

    /// A live record with no endpoints is a withdrawal: deliberately
    /// unreachable for now, and free to come back.
    pub fn is_withdrawal(&self) -> bool {
        matches!(&self.body, RecordBody::Live { endpoints } if endpoints.is_empty())
    }

    /// When this record stops being usable. Terminal records never do.
    pub fn expires_at(&self) -> u64 {
        if self.is_terminal() {
            return u64::MAX;
        }
        self.issued_at.saturating_add(self.ttl as u64)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        !self.is_terminal() && now >= self.expires_at()
    }

    /// Seconds until expiry, saturating at zero.
    pub fn remaining(&self, now: u64) -> u64 {
        self.expires_at().saturating_sub(now)
    }

    /// Endpoints in preference order: priority ascending, heavier first.
    pub fn by_priority(&self) -> Vec<&Endpoint> {
        let mut out: Vec<&Endpoint> = self.endpoints().iter().collect();
        out.sort_by_key(|e| (e.priority, std::cmp::Reverse(e.weight)));
        out
    }

    /// True when `self` should replace `other` in a store.
    ///
    /// Retiring a key is final: a terminal record beats any live one, and
    /// nothing at all beats a terminal record — which is what stops a thief
    /// still holding the key from publishing over its own retirement.
    pub fn supersedes(&self, other: &Record) -> bool {
        if other.is_terminal() {
            return false;
        }
        if self.is_terminal() {
            return true;
        }
        (self.serial, self.issued_at) > (other.serial, other.issued_at)
    }

    /// Structural checks a server applies before storing.
    pub fn validate(&self) -> Result<()> {
        self.key.verifying_key()?;
        self.delegation.identity.verifying_key()?;
        if self.delegation.identity == self.key {
            return Err(Error::Delegation(
                "a service key cannot be its own identity".to_string(),
            ));
        }
        match &self.body {
            RecordBody::Live { endpoints } => {
                if endpoints.len() > MAX_ENDPOINTS {
                    return Err(Error::Record(format!(
                        "at most {MAX_ENDPOINTS} endpoints, got {}",
                        endpoints.len()
                    )));
                }
                if !(MIN_TTL..=MAX_TTL).contains(&self.ttl) {
                    return Err(Error::Record(format!(
                        "ttl must be {MIN_TTL}..={MAX_TTL} seconds, got {}",
                        self.ttl
                    )));
                }
            }
            RecordBody::Superseded { successor, reason } => {
                successor.verifying_key()?;
                if *successor == self.key {
                    return Err(Error::Record(
                        "a key cannot be superseded by itself".to_string(),
                    ));
                }
                check_reason(reason)?;
            }
            RecordBody::Revoked { reason } => check_reason(reason)?,
        }
        Ok(())
    }

    /// Canonical bytes — the signature input, and the on-wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80 + self.endpoints().len() * 12);
        buf.push(RECORD_VERSION);
        buf.extend_from_slice(self.key.as_bytes());
        self.delegation.encode_into(&mut buf);
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        match &self.body {
            RecordBody::Live { endpoints } => {
                buf.push(BODY_LIVE);
                buf.push(endpoints.len() as u8);
                for ep in endpoints {
                    ep.encode_into(&mut buf);
                }
            }
            RecordBody::Superseded { successor, reason } => {
                buf.push(BODY_SUPERSEDED);
                buf.extend_from_slice(successor.as_bytes());
                put_string(&mut buf, reason);
            }
            RecordBody::Revoked { reason } => {
                buf.push(BODY_REVOKED);
                put_string(&mut buf, reason);
            }
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
        let delegation = Delegation::decode_from(r)?;
        let serial = r.u64("record serial")?;
        let issued_at = r.u64("record issued_at")?;
        let ttl = r.u32("record ttl")?;
        let body = match r.u8("record body kind")? {
            BODY_LIVE => {
                let count = r.u8("endpoint count")? as usize;
                let mut endpoints = Vec::with_capacity(count);
                for _ in 0..count {
                    endpoints.push(Endpoint::decode_from(r)?);
                }
                RecordBody::Live { endpoints }
            }
            BODY_SUPERSEDED => RecordBody::Superseded {
                successor: PubKey::new(r.array::<32>("successor key")?),
                reason: r.string("supersede reason")?,
            },
            BODY_REVOKED => RecordBody::Revoked {
                reason: r.string("revocation reason")?,
            },
            other => {
                return Err(Error::Record(format!("unknown record body kind {other:#x}")));
            }
        };
        Ok(Self {
            key,
            delegation,
            serial,
            issued_at,
            ttl,
            body,
        })
    }

    /// Sign with the key this record's authority calls for: the service key for
    /// a live record, the issuing identity to retire one.
    pub fn sign(self, sk: &SigningKey) -> Result<SignedRecord> {
        let signer = crate::key::public_of(sk);
        let expected = self.expected_signer();
        if signer != expected {
            return Err(Error::Signature(match &self.body {
                RecordBody::Live { .. } => format!(
                    "a live record for {} must be signed by it, not by {signer}",
                    self.key
                ),
                _ => format!(
                    "retiring {} takes its identity {}, but it was signed by {signer}",
                    self.key,
                    self.identity()
                ),
            }));
        }
        let body = self.encode();
        let sig = sk.sign(&signed_message(&body));
        Ok(SignedRecord {
            record: self,
            signature: sig.to_bytes(),
        })
    }
}

fn check_reason(reason: &str) -> Result<()> {
    if reason.len() > MAX_REASON_LEN {
        return Err(Error::Record(format!(
            "reason must be at most {MAX_REASON_LEN} bytes, got {}",
            reason.len()
        )));
    }
    Ok(())
}

/// The bytes a record signature actually covers.
fn signed_message(record_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIG_CONTEXT.len() + record_bytes.len());
    msg.extend_from_slice(SIG_CONTEXT);
    msg.extend_from_slice(record_bytes);
    msg
}

/// A record plus the signature made under its key's authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecord {
    pub record: Record,
    pub signature: [u8; 64],
}

impl SignedRecord {
    /// The service key this record speaks for — what was looked up, and what a
    /// client pins when dialing its endpoints.
    pub fn key(&self) -> PubKey {
        self.record.key
    }

    pub fn identity(&self) -> PubKey {
        self.record.identity()
    }

    /// Check the record's signature and the delegation behind it.
    pub fn verify(&self) -> Result<()> {
        self.record.delegation.verify(&self.record.key)?;
        let signer = self.record.expected_signer();
        let vk = signer.verifying_key()?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&signed_message(&self.record.encode()), &sig)
            .map_err(|_| {
                Error::Signature(format!(
                    "the record for {} is not signed by {signer}",
                    self.record.key
                ))
            })
    }

    /// Verify the signature, that the record answers the key that was asked
    /// for, that it is structurally sound, and that neither it nor its
    /// delegation has expired.
    ///
    /// This is what a client runs on every answer, and on every hop of a
    /// supersede chain.
    pub fn verify_answer(&self, asked: &PubKey, now: u64) -> Result<()> {
        if self.record.key != *asked {
            return Err(Error::KeyMismatch {
                asked: asked.to_string(),
                got: self.record.key.to_string(),
            });
        }
        self.verify()?;
        self.record.validate()?;
        let d = &self.record.delegation;
        if d.is_expired(now) && !self.record.is_terminal() {
            return Err(Error::Delegation(format!(
                "the delegation over {} from {} expired {}s ago",
                self.record.key,
                d.identity,
                now - d.not_after
            )));
        }
        if self.record.is_expired(now) {
            return Err(Error::Expired(now - self.record.expires_at()));
        }
        Ok(())
    }

    /// The error a retired key should be reported as, if it is one.
    ///
    /// A supersede is not an error to a caller that follows it, so this returns
    /// `None` for that case; see [`Record::successor`].
    pub fn revocation_error(&self) -> Option<Error> {
        match &self.record.body {
            RecordBody::Revoked { reason } => Some(Error::Revoked {
                key: self.record.key.to_string(),
                successor: None,
                reason: if reason.is_empty() {
                    "no reason given".to_string()
                } else {
                    reason.clone()
                },
            }),
            _ => None,
        }
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

/// A delegation as it is carried on disk, between the offline identity key that
/// issues it and the node that publishes under it.
///
/// A record embeds the delegation next to the service key it covers. A
/// standalone file has no such context, so it names that service key too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationFile {
    pub service_key: PubKey,
    pub delegation: Delegation,
}

const DELEGATION_FILE_MAGIC: &[u8; 7] = b"SQNSDEL";
const DELEGATION_FILE_VERSION: u8 = 2;

impl DelegationFile {
    pub fn new(service_key: PubKey, delegation: Delegation) -> Self {
        Self {
            service_key,
            delegation,
        }
    }

    pub fn identity(&self) -> PubKey {
        self.delegation.identity
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(DELEGATION_FILE_MAGIC);
        buf.push(DELEGATION_FILE_VERSION);
        buf.extend_from_slice(self.service_key.as_bytes());
        self.delegation.encode_into(&mut buf);
        buf
    }

    /// Decode and check the signature, so a tampered file fails here rather
    /// than at publish time.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.bytes(DELEGATION_FILE_MAGIC.len(), "delegation magic")?;
        if magic != DELEGATION_FILE_MAGIC {
            return Err(Error::Delegation("not an sqns delegation file".into()));
        }
        let version = r.u8("delegation file version")?;
        if version != DELEGATION_FILE_VERSION {
            return Err(Error::Delegation(format!(
                "unsupported delegation file version {version}"
            )));
        }
        let service_key = PubKey::new(r.array::<32>("delegation service key")?);
        let delegation = Delegation::decode_from(&mut r)?;
        r.finish("delegation file")?;
        delegation.verify(&service_key)?;
        Ok(Self {
            service_key,
            delegation,
        })
    }
}
