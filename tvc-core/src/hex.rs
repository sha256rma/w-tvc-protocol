//! Minimal lowercase hexadecimal codec.
//!
//! `tvc-core` carries its own hex implementation rather than pulling a
//! dependency. The protocol moves 32-byte digests and 64-byte signatures across
//! a Nostr relay boundary, so hex is on the trust path: every byte a wallet acts
//! on passes through [`decode`]. Keeping roughly forty auditable lines in-tree is
//! preferred over widening the supply chain for a trivial transformation.
//!
//! [`decode`] is strict by construction. It rejects uppercase input, odd-length
//! input, and any non-hex byte, so a digest string has exactly one valid
//! encoding. Accepting mixed case would let the same digest travel under two
//! spellings, and relay-level deduplication of commitments is easier to reason
//! about when the encoding is canonical.

use crate::error::{Result, TvcError};

const TABLE: &[u8; 16] = b"0123456789abcdef";

/// Encodes bytes as a lowercase hexadecimal string.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[usize::from(byte >> 4)] as char);
        out.push(TABLE[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Decodes a strict lowercase hexadecimal string into bytes.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err(TvcError::MalformedHex(format!(
            "expected even length, got {}",
            text.len()
        )));
    }
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Decodes a strict lowercase hexadecimal string into a fixed-size array.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = decode(text)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| {
        TvcError::MalformedHex(format!("expected {} bytes, got {}", N, bytes.len()))
    })
}

fn nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(TvcError::MalformedHex(format!(
            "invalid lowercase hex byte: {:?}",
            byte as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_arbitrary_bytes() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn rejects_uppercase_and_odd_length() {
        assert!(decode("AB").is_err());
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }

    #[test]
    fn decode_array_enforces_width() {
        assert!(decode_array::<32>(&encode(&[0u8; 32])).is_ok());
        assert!(decode_array::<32>(&encode(&[0u8; 31])).is_err());
    }
}
