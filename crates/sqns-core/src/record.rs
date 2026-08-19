//! Records: the signed mapping from a public key to an endpoint set.
//!
//! A record is signed under the authority of the key it describes, so a client
//! can verify an answer end-to-end. An sqns server — or a peer replicating from
//! one — can withhold a record, but it cannot forge one, alter its endpoints,
//! or replay an older version past its expiry.
//!
//! # Identity keys and service keys
//!
//! The record's `key` is an **identity key**, and it is meant to live offline.
//! It signs a [`Delegation`] naming the **service key** that the running node
//! holds, and clients pin that service key when they dial. The service key
//! signs the records themselves, which is what lets it refresh them every few
//! minutes while the identity key stays in a safe.
//!
//! Stealing the service key therefore does not let an attacker publish: records
//! are only accepted under a delegation, and only the identity key can issue
//! one. Recovery is the operator signing a delegation with a higher serial,
//! which retires every record made under the old one. A record with no
//! delegation is signed by its own key and is dialed directly — the original
//! single-key arrangement, still supported.
//!
//! If the identity key itself is lost, [`RecordBody::Revoked`] kills it
//! permanently: the store never accepts another record for that key.
//!
//! Canonical encoding (big-endian, no padding):
//!
//! ```text
//! Record     := version:u8 key:[32] serial:u64 issued_at:u64 ttl:u32
//!               body_kind:u8 body
//! body       := delegated:u8 [Delegation] n:u8 endpoint*n   when body_kind = 1 (Live)
//!             | successor:u8 [[32]] reason_len:u16 utf8     when body_kind = 2 (Revoked)
//! Delegation := service_key:[32] serial:u64 not_after:u64 signature:[64]
//! Endpoint   := priority:u16 weight:u16 port:u16 host_type:u8 host
//! host       := [4]         when host_type = 1 (IPv4)
//!             | [16]        when host_type = 2 (IPv6)
//!             | len:u8 utf8 when host_type = 3 (DNS name)
//! Signed     := record_len:u16 record signature:[64]
//! ```
//!
//! A record signature covers `SIG_CONTEXT || record_bytes`; a delegation
//! signature covers `DELEGATION_CONTEXT || identity || service_key || serial ||
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
pub const RECORD_VERSION: u8 = 2;

/// Domain separation prefix for record signatures.
pub const SIG_CONTEXT: &[u8] = b"sqns-record-v2";

/// Domain separation prefix for delegation signatures.
pub const DELEGATION_CONTEXT: &[u8] = b"sqns-delegation-v1";

/// Longest a delegation may be valid for, in seconds (365 days).
pub const MAX_DELEGATION_LIFETIME: u64 = 31_536_000;

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
const BODY_REVOKED: u8 = 2;

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

/// An identity key's grant of authority to a service key.
///
/// The identity key signs this offline; the service key named here is what the
/// node holds, what signs its records, and what clients pin when dialing.
/// Raising `serial` retires every earlier delegation and every record made
/// under one, which is how a stolen service key is taken out of service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The key clients pin, and the only key whose signature this delegation
    /// makes valid on the identity's records.
    pub service_key: PubKey,
    /// Monotonic counter, starting at 1. Higher retires lower.
    pub serial: u64,
    /// Absolute expiry, seconds since the Unix epoch.
    pub not_after: u64,
    /// Signature by the identity key.
    pub signature: [u8; 64],
}

impl Delegation {
    /// The bytes a delegation signature covers.
    fn signed_message(identity: &PubKey, service_key: &PubKey, serial: u64, not_after: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(DELEGATION_CONTEXT.len() + 80);
        msg.extend_from_slice(DELEGATION_CONTEXT);
        msg.extend_from_slice(identity.as_bytes());
        msg.extend_from_slice(service_key.as_bytes());
        msg.extend_from_slice(&serial.to_be_bytes());
        msg.extend_from_slice(&not_after.to_be_bytes());
        msg
    }

    /// Issue a delegation. Run this offline, wherever the identity key lives.
    pub fn issue(
        identity: &SigningKey,
        service_key: PubKey,
        serial: u64,
        not_after: u64,
    ) -> Result<Self> {
        if serial == 0 {
            return Err(Error::Delegation("delegation serial must be 1 or more".into()));
        }
        let identity_pub = crate::key::public_of(identity);
        let msg = Self::signed_message(&identity_pub, &service_key, serial, not_after);
        Ok(Self {
            service_key,
            serial,
            not_after,
            signature: identity.sign(&msg).to_bytes(),
        })
    }

    /// Check that `identity` really issued this delegation.
    pub fn verify(&self, identity: &PubKey) -> Result<()> {
        let vk = identity.verifying_key()?;
        let sig = Signature::from_bytes(&self.signature);
        let msg = Self::signed_message(identity, &self.service_key, self.serial, self.not_after);
        vk.verify(&msg, &sig).map_err(|_| {
            Error::Delegation(format!(
                "delegation to {} is not signed by {identity}",
                self.service_key
            ))
        })
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.not_after
    }

    fn validate(&self) -> Result<()> {
        if self.serial == 0 {
            return Err(Error::Delegation("delegation serial must be 1 or more".into()));
        }
        self.service_key.verifying_key()?;
        Ok(())
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.service_key.as_bytes());
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.not_after.to_be_bytes());
        buf.extend_from_slice(&self.signature);
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            service_key: PubKey::new(r.array::<32>("delegation service key")?),
            serial: r.u64("delegation serial")?,
            not_after: r.u64("delegation not_after")?,
            signature: r.array::<64>("delegation signature")?,
        })
    }
}

/// What a record says about its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordBody {
    /// The key is in service at these endpoints.
    Live {
        /// Authority under which this record is signed. `None` means the
        /// identity key signed it itself and is dialed directly.
        delegation: Option<Delegation>,
        /// Reachable addresses. Empty withdraws the key.
        endpoints: Vec<Endpoint>,
    },
    /// The key is permanently dead. A store that holds this never accepts
    /// another record for the key, at any serial.
    Revoked {
        /// The operator's new identity, if the revocation named one.
        ///
        /// **Untrusted.** Whoever stole the identity key could have written
        /// this. Surface it to a human; never dial it on the strength of the
        /// revocation alone.
        successor: Option<PubKey>,
        reason: String,
    },
}

/// The unsigned body of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The identity this record speaks for, and the lookup index.
    pub key: PubKey,
    /// Monotonic version counter; the highest serial wins within a delegation.
    pub serial: u64,
    /// Publication time, seconds since the Unix epoch.
    pub issued_at: u64,
    /// Lifetime in seconds from `issued_at`. Ignored for revocations, which
    /// never expire.
    pub ttl: u32,
    pub body: RecordBody,
}

impl Record {
    /// A record advertising endpoints, signed directly by its own key.
    pub fn live(key: PubKey, serial: u64, ttl: u32, endpoints: Vec<Endpoint>) -> Self {
        Self {
            key,
            serial,
            issued_at: now_unix(),
            ttl,
            body: RecordBody::Live {
                delegation: None,
                endpoints,
            },
        }
    }

    /// A record advertising endpoints under a delegation, to be signed by the
    /// delegated service key.
    pub fn delegated(
        key: PubKey,
        serial: u64,
        ttl: u32,
        delegation: Delegation,
        endpoints: Vec<Endpoint>,
    ) -> Self {
        Self {
            key,
            serial,
            issued_at: now_unix(),
            ttl,
            body: RecordBody::Live {
                delegation: Some(delegation),
                endpoints,
            },
        }
    }

    /// A revocation, which only the identity key can sign.
    pub fn revoked(
        key: PubKey,
        serial: u64,
        successor: Option<PubKey>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            key,
            serial,
            issued_at: now_unix(),
            ttl: MAX_TTL,
            body: RecordBody::Revoked {
                successor,
                reason: reason.into(),
            },
        }
    }

    /// The delegation this record was published under, if any.
    pub fn delegation(&self) -> Option<&Delegation> {
        match &self.body {
            RecordBody::Live { delegation, .. } => delegation.as_ref(),
            RecordBody::Revoked { .. } => None,
        }
    }

    /// Ordering rank of the record's authority. A record with no delegation
    /// ranks 0, below every delegation, whose serials start at 1.
    pub fn delegation_serial(&self) -> u64 {
        self.delegation().map(|d| d.serial).unwrap_or(0)
    }

    /// The key a client pins when dialing: the delegated service key, or the
    /// identity itself when there is no delegation.
    pub fn service_key(&self) -> PubKey {
        self.delegation().map(|d| d.service_key).unwrap_or(self.key)
    }

    /// The key whose signature this record must carry.
    fn expected_signer(&self) -> PubKey {
        self.service_key()
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        match &self.body {
            RecordBody::Live { endpoints, .. } => endpoints,
            RecordBody::Revoked { .. } => &[],
        }
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.body, RecordBody::Revoked { .. })
    }

    /// A live record with no endpoints is a withdrawal: the key is deliberately
    /// unreachable, which is different from never having been published, and
    /// different again from being revoked.
    pub fn is_withdrawal(&self) -> bool {
        matches!(&self.body, RecordBody::Live { endpoints, .. } if endpoints.is_empty())
    }

    /// When this record stops being usable. Revocations never do.
    pub fn expires_at(&self) -> u64 {
        if self.is_revoked() {
            return u64::MAX;
        }
        self.issued_at.saturating_add(self.ttl as u64)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        !self.is_revoked() && now >= self.expires_at()
    }

    /// Seconds until expiry, saturating at zero.
    pub fn remaining(&self, now: u64) -> u64 {
        self.expires_at().saturating_sub(now)
    }

    /// True when `self` should replace `other` in a store.
    ///
    /// A newer delegation outranks anything published under an older one, no
    /// matter how high that record's serial was pushed — which is what takes a
    /// stolen service key out of service. Below that, the record serial
    /// decides, and `issued_at` breaks ties so a republish at an unchanged
    /// serial still refreshes.
    pub fn supersedes(&self, other: &Record) -> bool {
        // A revocation is terminal: nothing supersedes it, and it supersedes
        // everything.
        if other.is_revoked() {
            return false;
        }
        if self.is_revoked() {
            return true;
        }
        (self.delegation_serial(), self.serial, self.issued_at)
            > (other.delegation_serial(), other.serial, other.issued_at)
    }

    /// Endpoints in preference order: priority ascending, heavier first.
    pub fn by_priority(&self) -> Vec<&Endpoint> {
        let mut out: Vec<&Endpoint> = self.endpoints().iter().collect();
        out.sort_by_key(|e| (e.priority, std::cmp::Reverse(e.weight)));
        out
    }

    /// Structural checks a server applies before storing.
    pub fn validate(&self) -> Result<()> {
        self.key.verifying_key()?;
        match &self.body {
            RecordBody::Live {
                delegation,
                endpoints,
            } => {
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
                if let Some(d) = delegation {
                    d.validate()?;
                }
            }
            RecordBody::Revoked { successor, reason } => {
                if reason.len() > MAX_REASON_LEN {
                    return Err(Error::Record(format!(
                        "revocation reason must be at most {MAX_REASON_LEN} bytes, got {}",
                        reason.len()
                    )));
                }
                if let Some(s) = successor {
                    s.verifying_key()?;
                }
            }
        }
        Ok(())
    }

    /// Canonical bytes — the signature input, and the on-wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.endpoints().len() * 12);
        buf.push(RECORD_VERSION);
        buf.extend_from_slice(self.key.as_bytes());
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        match &self.body {
            RecordBody::Live {
                delegation,
                endpoints,
            } => {
                buf.push(BODY_LIVE);
                match delegation {
                    Some(d) => {
                        buf.push(1);
                        d.encode_into(&mut buf);
                    }
                    None => buf.push(0),
                }
                buf.push(endpoints.len() as u8);
                for ep in endpoints {
                    ep.encode_into(&mut buf);
                }
            }
            RecordBody::Revoked { successor, reason } => {
                buf.push(BODY_REVOKED);
                match successor {
                    Some(s) => {
                        buf.push(1);
                        buf.extend_from_slice(s.as_bytes());
                    }
                    None => buf.push(0),
                }
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
        let serial = r.u64("record serial")?;
        let issued_at = r.u64("record issued_at")?;
        let ttl = r.u32("record ttl")?;
        let body = match r.u8("record body kind")? {
            BODY_LIVE => {
                let delegation = match r.u8("delegation presence")? {
                    0 => None,
                    1 => Some(Delegation::decode_from(r)?),
                    other => {
                        return Err(Error::Record(format!(
                            "invalid delegation presence byte {other:#x}"
                        )));
                    }
                };
                let count = r.u8("endpoint count")? as usize;
                let mut endpoints = Vec::with_capacity(count);
                for _ in 0..count {
                    endpoints.push(Endpoint::decode_from(r)?);
                }
                RecordBody::Live {
                    delegation,
                    endpoints,
                }
            }
            BODY_REVOKED => {
                let successor = match r.u8("successor presence")? {
                    0 => None,
                    1 => Some(PubKey::new(r.array::<32>("successor key")?)),
                    other => {
                        return Err(Error::Record(format!(
                            "invalid successor presence byte {other:#x}"
                        )));
                    }
                };
                RecordBody::Revoked {
                    successor,
                    reason: r.string("revocation reason")?,
                }
            }
            other => {
                return Err(Error::Record(format!("unknown record body kind {other:#x}")));
            }
        };
        Ok(Self {
            key,
            serial,
            issued_at,
            ttl,
            body,
        })
    }

    /// Sign with the key this record's authority names: the delegated service
    /// key, or the identity key when there is no delegation.
    pub fn sign(self, sk: &SigningKey) -> Result<SignedRecord> {
        let signer = crate::key::public_of(sk);
        let expected = self.expected_signer();
        if signer != expected {
            return Err(Error::Signature(match self.delegation() {
                Some(d) => format!(
                    "record for {} is delegated to {}, but was signed by {signer}",
                    self.key, d.service_key
                ),
                None => format!("record is for {} but was signed by {signer}", self.key),
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
    pub fn key(&self) -> PubKey {
        self.record.key
    }

    /// The key to pin when dialing this record's endpoints.
    pub fn service_key(&self) -> PubKey {
        self.record.service_key()
    }

    /// Check every signature in the record's chain of authority.
    ///
    /// For a delegated record that is two checks: the identity key really
    /// issued the delegation, and the delegated service key really signed the
    /// record. A revocation carries no delegation, so it can only ever be
    /// signed by the identity key itself.
    pub fn verify(&self) -> Result<()> {
        if let Some(delegation) = self.record.delegation() {
            delegation.verify(&self.record.key)?;
        }
        let signer = self.record.expected_signer();
        let vk = signer.verifying_key()?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&signed_message(&self.record.encode()), &sig)
            .map_err(|_| {
                Error::Signature(format!(
                    "record for {} is not signed by {signer}",
                    self.record.key
                ))
            })
    }

    /// Verify the signature chain, that the record answers the key that was
    /// asked for, that it is structurally sound, and that neither it nor its
    /// delegation has expired.
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
        if let Some(d) = self.record.delegation()
            && d.is_expired(now)
        {
            return Err(Error::Delegation(format!(
                "delegation to {} expired {}s ago",
                d.service_key,
                now - d.not_after
            )));
        }
        if self.record.is_expired(now) {
            return Err(Error::Expired(now - self.record.expires_at()));
        }
        Ok(())
    }

    /// The error a revoked record should be reported as, if it is one.
    pub fn revocation_error(&self) -> Option<Error> {
        match &self.record.body {
            RecordBody::Revoked { successor, reason } => Some(Error::Revoked {
                key: self.record.key.to_string(),
                successor: successor.map(|s| s.to_string()),
                reason: if reason.is_empty() {
                    "no reason given".to_string()
                } else {
                    reason.clone()
                },
            }),
            RecordBody::Live { .. } => None,
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
/// A record embeds the delegation alone, because the identity is already the
/// record's key. A standalone file has no such context, so it names the
/// identity too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationFile {
    pub identity: PubKey,
    pub delegation: Delegation,
}

const DELEGATION_FILE_MAGIC: &[u8; 7] = b"SQNSDEL";
const DELEGATION_FILE_VERSION: u8 = 1;

impl DelegationFile {
    pub fn new(identity: PubKey, delegation: Delegation) -> Self {
        Self {
            identity,
            delegation,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(DELEGATION_FILE_MAGIC);
        buf.push(DELEGATION_FILE_VERSION);
        buf.extend_from_slice(self.identity.as_bytes());
        self.delegation.encode_into(&mut buf);
        buf
    }

    /// Decode and check that the identity named really issued the delegation,
    /// so a tampered file fails here rather than at publish time.
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
        let identity = PubKey::new(r.array::<32>("delegation identity")?);
        let delegation = Delegation::decode_from(&mut r)?;
        r.finish("delegation file")?;
        delegation.verify(&identity)?;
        Ok(Self {
            identity,
            delegation,
        })
    }
}
