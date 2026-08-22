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

/// The public sqns server, used by the `sqns` CLI when nothing else names one.
///
/// This is data, not policy: a library never contacts it on its own. Only the
/// command line falls back to it, so that `sqns resolve <key>` works before any
/// configuration exists.
pub const DEFAULT_SERVER: &str = "sqns://ns.squic.org/9Yb1A35fjEVVxphy5sGKfqC9fhTD9etoJQ4gVSa1jEKb";

/// Crate version, reported by `Status`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
