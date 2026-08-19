//! The sqns wire protocol.
//!
//! One request/response exchange per sQUIC bidirectional stream. Every message
//! is a frame: `[type:u8][length:u32][payload]`. The transport already provides
//! confidentiality, server identity pinning and — where the server whitelists
//! keys — caller authentication, so the protocol itself carries no handshake.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::codec::{Reader, put_string};
use crate::error::{Error, Result};
use crate::key::PubKey;
use crate::record::SignedRecord;

/// ALPN protocol identifier.
pub const ALPN: &[u8] = b"sqns/1";

/// Default sqns port (UDP, since sQUIC rides QUIC).
pub const DEFAULT_PORT: u16 = 5300;

/// Hard cap on a single frame's payload.
pub const MAX_MESSAGE_LEN: u32 = 1 << 20;

/// Most records a single `Sync` response will carry.
pub const MAX_SYNC_BATCH: u16 = 512;

// Request frame types.
const REQ_LOOKUP: u8 = 0x01;
const REQ_PUBLISH: u8 = 0x02;
const REQ_STATUS: u8 = 0x03;
const REQ_SYNC: u8 = 0x04;

// Response frame types.
const RESP_ANSWER: u8 = 0x81;
const RESP_PUBLISHED: u8 = 0x82;
const RESP_STATUS: u8 = 0x83;
const RESP_RECORDS: u8 = 0x84;
const RESP_ERROR: u8 = 0xff;

/// Why a request failed, as sent on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    Malformed = 1,
    Unsupported = 2,
    BadSignature = 3,
    /// The submitted record is not newer than the one already held.
    Stale = 4,
    RateLimited = 5,
    Internal = 6,
    /// Operation restricted to configured replication peers.
    NotAuthorized = 7,
    /// The key is revoked; nothing will ever be accepted for it again.
    Revoked = 8,
    /// The record's delegation is missing, expired, or has been retired by a
    /// newer one.
    BadDelegation = 9,
}

impl ErrorCode {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::Malformed,
            2 => Self::Unsupported,
            3 => Self::BadSignature,
            4 => Self::Stale,
            5 => Self::RateLimited,
            7 => Self::NotAuthorized,
            8 => Self::Revoked,
            9 => Self::BadDelegation,
            _ => Self::Internal,
        }
    }
}

/// A request from a client or a replication peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Resolve one public key to its endpoint set.
    Lookup { key: PubKey },
    /// Publish or refresh a record. Only the record's own key can sign it.
    Publish { record: Box<SignedRecord> },
    /// Server counters, for health checks.
    Status,
    /// Anti-entropy pull: every record issued at or after `since`.
    Sync { since: u64, limit: u16 },
}

impl Request {
    fn frame_type(&self) -> u8 {
        match self {
            Self::Lookup { .. } => REQ_LOOKUP,
            Self::Publish { .. } => REQ_PUBLISH,
            Self::Status => REQ_STATUS,
            Self::Sync { .. } => REQ_SYNC,
        }
    }

    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Lookup { key } => buf.extend_from_slice(key.as_bytes()),
            Self::Publish { record } => record.encode_into(&mut buf),
            Self::Status => {}
            Self::Sync { since, limit } => {
                buf.extend_from_slice(&since.to_be_bytes());
                buf.extend_from_slice(&limit.to_be_bytes());
            }
        }
        buf
    }

    pub fn decode(frame_type: u8, payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        let req = match frame_type {
            REQ_LOOKUP => Self::Lookup {
                key: PubKey::new(r.array::<32>("lookup key")?),
            },
            REQ_PUBLISH => Self::Publish {
                record: Box::new(SignedRecord::decode_from(&mut r)?),
            },
            REQ_STATUS => Self::Status,
            REQ_SYNC => Self::Sync {
                since: r.u64("sync since")?,
                limit: r.u16("sync limit")?,
            },
            other => {
                return Err(Error::Protocol(format!(
                    "unknown request type {other:#x}"
                )));
            }
        };
        r.finish("request")?;
        Ok(req)
    }

    pub async fn write_to(&self, w: &mut (impl AsyncWriteExt + Unpin)) -> Result<()> {
        write_frame(w, self.frame_type(), &self.encode_payload()).await
    }

    pub async fn read_from(r: &mut (impl AsyncReadExt + Unpin)) -> Result<Self> {
        let (typ, payload) = read_frame(r).await?;
        Self::decode(typ, &payload)
    }
}

/// Counters returned by [`Request::Status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusInfo {
    pub records: u64,
    pub peers: u32,
    pub uptime_secs: u64,
    pub version: String,
}

/// A server's reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The record for the requested key, or `None` if the server holds none.
    Answer { record: Option<Box<SignedRecord>> },
    /// The record was accepted; `expires_at` is when the server will drop it.
    Published { serial: u64, expires_at: u64 },
    Status(StatusInfo),
    /// Records from an anti-entropy pull. `complete` is false when the batch
    /// hit `limit` and the caller should pull again from the last `issued_at`.
    Records {
        records: Vec<SignedRecord>,
        complete: bool,
    },
    Error { code: ErrorCode, message: String },
}

impl Response {
    fn frame_type(&self) -> u8 {
        match self {
            Self::Answer { .. } => RESP_ANSWER,
            Self::Published { .. } => RESP_PUBLISHED,
            Self::Status(_) => RESP_STATUS,
            Self::Records { .. } => RESP_RECORDS,
            Self::Error { .. } => RESP_ERROR,
        }
    }

    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }

    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Answer { record } => match record {
                Some(rec) => {
                    buf.push(1);
                    rec.encode_into(&mut buf);
                }
                None => buf.push(0),
            },
            Self::Published { serial, expires_at } => {
                buf.extend_from_slice(&serial.to_be_bytes());
                buf.extend_from_slice(&expires_at.to_be_bytes());
            }
            Self::Status(info) => {
                buf.extend_from_slice(&info.records.to_be_bytes());
                buf.extend_from_slice(&info.peers.to_be_bytes());
                buf.extend_from_slice(&info.uptime_secs.to_be_bytes());
                put_string(&mut buf, &info.version);
            }
            Self::Records { records, complete } => {
                buf.extend_from_slice(&(records.len() as u32).to_be_bytes());
                buf.push(u8::from(*complete));
                for rec in records {
                    rec.encode_into(&mut buf);
                }
            }
            Self::Error { code, message } => {
                buf.extend_from_slice(&(*code as u16).to_be_bytes());
                put_string(&mut buf, message);
            }
        }
        buf
    }

    pub fn decode(frame_type: u8, payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        let resp = match frame_type {
            RESP_ANSWER => {
                let present = r.u8("answer presence")?;
                let record = match present {
                    0 => None,
                    1 => Some(Box::new(SignedRecord::decode_from(&mut r)?)),
                    other => {
                        return Err(Error::Protocol(format!(
                            "invalid answer presence byte {other:#x}"
                        )));
                    }
                };
                Self::Answer { record }
            }
            RESP_PUBLISHED => Self::Published {
                serial: r.u64("published serial")?,
                expires_at: r.u64("published expires_at")?,
            },
            RESP_STATUS => Self::Status(StatusInfo {
                records: r.u64("status records")?,
                peers: r.u32("status peers")?,
                uptime_secs: r.u64("status uptime")?,
                version: r.string("status version")?,
            }),
            RESP_RECORDS => {
                let count = r.u32("sync count")? as usize;
                if count > MAX_SYNC_BATCH as usize {
                    return Err(Error::Protocol(format!(
                        "sync batch of {count} exceeds the {MAX_SYNC_BATCH} cap"
                    )));
                }
                let complete = r.u8("sync complete")? != 0;
                let mut records = Vec::with_capacity(count);
                for _ in 0..count {
                    records.push(SignedRecord::decode_from(&mut r)?);
                }
                Self::Records { records, complete }
            }
            RESP_ERROR => Self::Error {
                code: ErrorCode::from_u16(r.u16("error code")?),
                message: r.string("error message")?,
            },
            other => {
                return Err(Error::Protocol(format!(
                    "unknown response type {other:#x}"
                )));
            }
        };
        r.finish("response")?;
        Ok(resp)
    }

    pub async fn write_to(&self, w: &mut (impl AsyncWriteExt + Unpin)) -> Result<()> {
        write_frame(w, self.frame_type(), &self.encode_payload()).await
    }

    pub async fn read_from(r: &mut (impl AsyncReadExt + Unpin)) -> Result<Self> {
        let (typ, payload) = read_frame(r).await?;
        Self::decode(typ, &payload)
    }

    /// Turn a wire-level `Error` response into a local error.
    pub fn into_server_error(self) -> Error {
        match self {
            Self::Error { code, message } => Error::Server {
                code: code as u16,
                message,
            },
            other => Error::Protocol(format!("unexpected response: {other:?}")),
        }
    }
}

/// Write `[type][len][payload]`.
pub async fn write_frame(
    w: &mut (impl AsyncWriteExt + Unpin),
    frame_type: u8,
    payload: &[u8],
) -> Result<()> {
    if payload.len() as u64 > MAX_MESSAGE_LEN as u64 {
        return Err(Error::Protocol(format!(
            "message of {} bytes exceeds the {MAX_MESSAGE_LEN} byte cap",
            payload.len()
        )));
    }
    let mut header = [0u8; 5];
    header[0] = frame_type;
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&header).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read one `[type][len][payload]` frame.
pub async fn read_frame(r: &mut (impl AsyncReadExt + Unpin)) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if len > MAX_MESSAGE_LEN {
        return Err(Error::Protocol(format!(
            "peer announced a {len} byte message, over the {MAX_MESSAGE_LEN} byte cap"
        )));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}
