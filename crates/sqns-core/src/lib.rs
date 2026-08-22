//! sqns — resolution of sQUIC public keys to endpoints.
//!
//! sqns answers one question: *given a base58 Ed25519 public key, where on the
//! network does it live?* An answer is a set of endpoints — IPv4, IPv6 or a
//! name, each with a port, a priority and a weight — signed by the key it
//! describes, so callers verify answers end-to-end rather than trusting the
//! server that handed them over.
//!
//! - [`record`] — records, delegations, revocations, signing and verification
//! - [`protocol`] — the request/response wire format spoken over sQUIC
//! - [`key`] — base58 public keys and on-disk private seeds
//! - [`addr`] — `sqns://` and `sqc://` server addresses

pub mod addr;
pub mod codec;
pub mod error;
pub mod key;
pub mod protocol;
pub mod record;

pub use addr::{Scheme, ServerAddr};
pub use error::{Error, Result};
pub use key::PubKey;
pub use protocol::{ALPN, DEFAULT_PORT, Request, Response};
pub use record::{Delegation, DelegationFile, Endpoint, Host, Record, RecordBody, SignedRecord, now_unix};

/// Crate version, reported by `Status`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
