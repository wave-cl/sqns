//! Key handling: base58 public keys, hex seeds, on-disk private keys.
//!
//! An sqns identity is an Ed25519 keypair — the same identity sQUIC pins for
//! the transport. The public key is written as base58 (as in `sqc://` strings);
//! private seeds are stored hex-encoded so they interchange with
//! `squic::load_keypair`.

use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::error::{Error, Result};

/// An Ed25519 public key: the thing sqns resolves to an endpoint set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PubKey([u8; 32]);

impl PubKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Base58 form, as used in `sqc://host:port/<key>` strings.
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First 8 base58 characters — for logs, never for identity decisions.
    pub fn short(&self) -> String {
        self.to_base58().chars().take(8).collect()
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0)
            .map_err(|e| Error::Key(format!("not a valid Ed25519 public key: {e}")))
    }

    pub fn from_base58(s: &str) -> Result<Self> {
        let raw = bs58::decode(s).into_vec()?;
        Self::from_slice(&raw)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s).map_err(|e| Error::Key(format!("bad hex: {e}")))?;
        Self::from_slice(&raw)
    }

    fn from_slice(raw: &[u8]) -> Result<Self> {
        if raw.len() != 32 {
            return Err(Error::Key(format!(
                "public key must be 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        Ok(Self(out))
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl FromStr for PubKey {
    type Err = Error;

    /// Accepts base58 (the canonical form) or 64 hex characters.
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Self::from_hex(s)
        } else {
            Self::from_base58(s)
        }
    }
}

impl From<VerifyingKey> for PubKey {
    fn from(vk: VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }
}

/// Environment variable that relocates the sqns directory, for tests and for
/// running several identities side by side.
pub const HOME_ENV: &str = "SQNS_HOME";

/// Where sqns keeps keys and configuration: `$SQNS_HOME`, else `~/.sqns`.
pub fn sqns_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(HOME_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    dirs::home_dir()
        .map(|home| home.join(".sqns"))
        .ok_or_else(|| Error::Key("could not determine your home directory".into()))
}

/// The sqns directory, created if absent and forced to mode 0700.
///
/// The permissions are re-applied even when the directory already existed:
/// private keys live here, and a directory someone left group-readable is
/// exactly the case worth correcting.
pub fn ensure_sqns_dir() -> Result<PathBuf> {
    let dir = sqns_dir()?;
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// A path inside the sqns directory, e.g. `default_path("identity.key")`.
pub fn default_path(name: &str) -> Result<PathBuf> {
    Ok(sqns_dir()?.join(name))
}

/// Generate a fresh identity from the operating system's CSPRNG.
pub fn generate() -> SigningKey {
    SigningKey::generate(&mut rand_core::OsRng)
}

/// Derive the public key of a signing key.
pub fn public_of(sk: &SigningKey) -> PubKey {
    PubKey(sk.verifying_key().to_bytes())
}

/// Load a private key from a file holding a 64-character hex seed.
///
/// Refuses group/world-readable files — the seed is the identity.
pub fn load_secret_file(path: &Path) -> Result<SigningKey> {
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o077;
    if mode != 0 {
        return Err(Error::Key(format!(
            "{} is group/world accessible (mode {:o}); run: chmod 600 {}",
            path.display(),
            meta.permissions().mode() & 0o777,
            path.display()
        )));
    }
    let text = fs::read_to_string(path)?;
    secret_from_hex(text.trim())
}

/// Parse a 64-character hex Ed25519 seed.
pub fn secret_from_hex(seed_hex: &str) -> Result<SigningKey> {
    let raw = hex::decode(seed_hex.trim())
        .map_err(|e| Error::Key(format!("private seed is not valid hex: {e}")))?;
    if raw.len() != 32 {
        return Err(Error::Key(format!(
            "private seed must be 32 bytes (64 hex chars), got {}",
            raw.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    Ok(SigningKey::from_bytes(&seed))
}

/// Write a private key as a hex seed with 0600 permissions.
pub fn save_secret_file(path: &Path, sk: &SigningKey) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", hex::encode(sk.to_bytes())))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
