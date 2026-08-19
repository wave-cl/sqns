//! Big-endian primitives shared by the record encoding and the wire protocol.
//!
//! Every multi-byte integer in sqns is big-endian. Record encoding must be
//! byte-for-byte reproducible: it is the input to the Ed25519 signature.

use crate::error::{Error, Result};

/// Cursor over a byte slice with bounds-checked reads.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Record(format!(
                "truncated while reading {what}: need {n} bytes, {} left",
                self.remaining()
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    pub fn u16(&mut self, what: &str) -> Result<u16> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self, what: &str) -> Result<u32> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self, what: &str) -> Result<u64> {
        let b = self.take(8, what)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn bytes(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        self.take(n, what)
    }

    pub fn array<const N: usize>(&mut self, what: &str) -> Result<[u8; N]> {
        let b = self.take(N, what)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    /// Length-prefixed UTF-8 string (u8 length).
    pub fn short_string(&mut self, what: &str) -> Result<String> {
        let len = self.u8(what)? as usize;
        let b = self.take(len, what)?;
        String::from_utf8(b.to_vec())
            .map_err(|e| Error::Record(format!("{what} is not valid UTF-8: {e}")))
    }

    /// Length-prefixed UTF-8 string (u16 length).
    pub fn string(&mut self, what: &str) -> Result<String> {
        let len = self.u16(what)? as usize;
        let b = self.take(len, what)?;
        String::from_utf8(b.to_vec())
            .map_err(|e| Error::Record(format!("{what} is not valid UTF-8: {e}")))
    }

    /// Error unless the whole buffer has been consumed.
    pub fn finish(&self, what: &str) -> Result<()> {
        if self.remaining() != 0 {
            return Err(Error::Record(format!(
                "{what}: {} trailing bytes",
                self.remaining()
            )));
        }
        Ok(())
    }
}

/// Append a u8-length-prefixed string.
pub fn put_short_string(buf: &mut Vec<u8>, s: &str) {
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

/// Append a u16-length-prefixed string.
pub fn put_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}
