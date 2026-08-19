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

    #[error("invalid sqc:// address: {0}")]
    Address(String),

    #[error("no record published for {0}")]
    Unpublished(String),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("no sqns server answered: {0}")]
    NoServer(String),

    #[error("server error {code}: {message}")]
    Server { code: u16, message: String },
}

pub type Result<T> = std::result::Result<T, Error>;
