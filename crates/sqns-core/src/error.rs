use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid key: {0}")]
    Key(String),

    #[error("base58 decode error: {0}")]
    Base58Decode(#[from] bs58::decode::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("malformed record: {0}")]
    Record(String),

    #[error("signature verification failed: {0}")]
    Signature(String),

    #[error("record has expired (expired {0}s ago)")]
    Expired(u64),

    #[error("record key mismatch: asked for {asked}, server answered for {got}")]
    KeyMismatch { asked: String, got: String },

    #[error("address error: {0}")]
    Address(String),

    #[error("key {key} is revoked: {reason}")]
    Revoked {
        key: String,
        /// Untrusted hint at the operator's new identity, if the revocation
        /// named one. Never act on it without out-of-band confirmation.
        successor: Option<String>,
        reason: String,
    },

    #[error("refusing a downgrade for {0}: a newer authority for this key was already seen")]
    Downgrade(String),

    #[error("key {key} was superseded by {successor}")]
    Superseded { key: String, successor: String },

    #[error("supersede chain: {0}")]
    SupersedeChain(String),

    #[error("delegation error: {0}")]
    Delegation(String),

    #[error("no record published for {0}")]
    Unpublished(String),

    #[error("connection error: {0}")]
    Connection(String),

    /// Nothing usable came back from any configured server — including there
    /// being none configured. The message says which; it needs no prefix.
    #[error("{0}")]
    NoServer(String),

    #[error("server error {code}: {message}")]
    Server { code: u16, message: String },
}

pub type Result<T> = std::result::Result<T, Error>;
