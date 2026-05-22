//! Invoice URI scheme (spec §6.3).

#![allow(clippy::cast_lossless)]
//!
//! Format:
//! ```text
//! tardus://<recipient_pk_hex64>?denom=<lamports>&relay=<url>&memo=<b64>
//! ```
//!
//! The `relay` parameter may appear multiple times. `memo` is
//! optional and base64-encoded (URL-safe alphabet, no padding); its
//! decoded length must be ≤ 128 bytes.

use crate::error::{Error, InvoiceParseError, Result};

/// Scheme prefix that every TARDUS invoice URI MUST start with.
pub const INVOICE_SCHEME: &str = "tardus://";

/// Maximum decoded memo size (§6.3).
pub const MEMO_MAX_BYTES: usize = 128;

/// A parsed TARDUS payment invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invoice {
    pub recipient_pubkey: [u8; 32],
    pub denom: u64,
    pub relays: Vec<String>,
    pub memo: Option<Vec<u8>>,
}

impl Invoice {
    /// Parse a `tardus://` URI string.
    ///
    /// # Errors
    /// Returns [`Error::InvalidInvoice`] with a specific
    /// [`InvoiceParseError`] sub-variant on malformed input.
    pub fn parse(uri: &str) -> Result<Self> {
        let body = uri
            .strip_prefix(INVOICE_SCHEME)
            .ok_or(Error::InvalidInvoice(InvoiceParseError::WrongScheme))?;
        let (recipient_hex, query) = match body.split_once('?') {
            Some((host, q)) => (host, q),
            None => (body, ""),
        };

        if recipient_hex.is_empty() {
            return Err(Error::InvalidInvoice(InvoiceParseError::MissingRecipient));
        }
        let recipient_pubkey =
            decode_hex_32(recipient_hex).ok_or(Error::InvalidInvoice(InvoiceParseError::InvalidRecipientHex))?;

        let mut denom_opt: Option<u64> = None;
        let mut relays: Vec<String> = Vec::new();
        let mut memo: Option<Vec<u8>> = None;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair
                .split_once('=')
                .ok_or(Error::InvalidInvoice(InvoiceParseError::WrongScheme))?;
            match k {
                "denom" => {
                    let d = v
                        .parse::<u64>()
                        .map_err(|_| Error::InvalidInvoice(InvoiceParseError::InvalidDenom))?;
                    denom_opt = Some(d);
                }
                "relay" => {
                    let decoded = url_decode(v)
                        .ok_or(Error::InvalidInvoice(InvoiceParseError::InvalidRelayUrl))?;
                    if decoded.is_empty() {
                        return Err(Error::InvalidInvoice(InvoiceParseError::InvalidRelayUrl));
                    }
                    relays.push(decoded);
                }
                "memo" => {
                    let decoded = b64url_decode(v)
                        .ok_or(Error::InvalidInvoice(InvoiceParseError::MemoNotBase64))?;
                    if decoded.len() > MEMO_MAX_BYTES {
                        return Err(Error::InvalidInvoice(InvoiceParseError::MemoTooLong));
                    }
                    memo = Some(decoded);
                }
                _ => {
                    // Unknown key — silently ignore for forward-compat.
                }
            }
        }

        let denom = denom_opt.ok_or(Error::InvalidInvoice(InvoiceParseError::MissingDenom))?;

        Ok(Self {
            recipient_pubkey,
            denom,
            relays,
            memo,
        })
    }

    /// Serialise the invoice as a `tardus://` URI string.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut out = String::with_capacity(128);
        out.push_str(INVOICE_SCHEME);
        out.push_str(&encode_hex_32(&self.recipient_pubkey));
        out.push('?');
        let mut params: Vec<String> = Vec::with_capacity(2 + self.relays.len());
        params.push(format!("denom={}", self.denom));
        for relay in &self.relays {
            params.push(format!("relay={}", url_encode(relay)));
        }
        if let Some(memo) = &self.memo {
            params.push(format!("memo={}", b64url_encode(memo)));
        }
        out.push_str(&params.join("&"));
        out
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[2 * i])?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(*b >> 4) as usize] as char);
        s.push(HEX[(*b & 0x0f) as usize] as char);
    }
    s
}

/// Percent-decode a URL-encoded string. Restricted alphabet: ASCII
/// printable + `%HH` escapes. Returns `None` on malformed input.
fn url_decode(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            let decoded = (hi << 4) | lo;
            // Only allow printable ASCII to keep the URI scheme well-formed.
            if !decoded.is_ascii() {
                return None;
            }
            out.push(decoded as char);
            i += 3;
        } else if c == b'+' {
            out.push(' ');
            i += 1;
        } else if c.is_ascii() {
            out.push(c as char);
            i += 1;
        } else {
            return None;
        }
    }
    Some(out)
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b':' => {
                out.push(b as char);
            }
            _ => {
                use core::fmt::Write;
                let _ = write!(&mut out, "%{b:02X}");
            }
        }
    }
    out
}

const B64URL: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 6) & 0x3f) as usize] as char);
        out.push(B64URL[(n & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
            out.push(B64URL[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => unreachable!(),
    }
    out
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();
    let chunks = bytes.chunks(4);
    for chunk in chunks {
        let mut value: u32 = 0;
        let mut chunk_len = 0;
        for &c in chunk {
            let idx = b64url_index(c)?;
            value = (value << 6) | (idx as u32);
            chunk_len += 1;
        }
        // Pad to 4 conceptual chars.
        let shift = (4 - chunk_len) * 6;
        value <<= shift;
        match chunk_len {
            2 => {
                out.push(((value >> 16) & 0xff) as u8);
            }
            3 => {
                out.push(((value >> 16) & 0xff) as u8);
                out.push(((value >> 8) & 0xff) as u8);
            }
            4 => {
                out.push(((value >> 16) & 0xff) as u8);
                out.push(((value >> 8) & 0xff) as u8);
                out.push((value & 0xff) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

fn b64url_index(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}
