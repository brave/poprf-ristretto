//! Shared serde helpers: fixed-length byte arrays as raw bytes (binary) or
//! lowercase hex (human-readable).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serialize, Serializer};

/// Serialize a fixed-length byte array. Human-readable formats get a hex
/// string; binary formats get raw bytes via `serde_bytes`.
pub(crate) fn ser_fixed<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        s.serialize_str(&hex_encode(bytes))
    } else {
        serde_bytes::Bytes::new(bytes).serialize(s)
    }
}

/// Deserialize a fixed-length byte array.
pub(crate) fn deser_fixed<'de, const N: usize, D: Deserializer<'de>>(
    d: D,
) -> Result<[u8; N], D::Error> {
    if d.is_human_readable() {
        d.deserialize_str(HexVisitor::<N>)
    } else {
        d.deserialize_bytes(BytesVisitor::<N>)
    }
}

struct HexVisitor<const N: usize>;
impl<'de, const N: usize> Visitor<'de> for HexVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a {}-byte lowercase hex string", N)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        hex_decode::<N>(v).ok_or_else(|| E::custom("invalid hex"))
    }
}

struct BytesVisitor<const N: usize>;
impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exactly {} bytes", N)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        if v.len() != N {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(v);
        Ok(out)
    }

    fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(v)
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        self.visit_bytes(&v)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut out = [0u8; N];
        for slot in &mut out {
            *slot = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(N, &self))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            return Err(de::Error::invalid_length(N + 1, &self));
        }
        Ok(out)
    }
}

// ── tiny hex codec (no dependency just for hex) ──────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = NIBBLE[(b >> 4) as usize];
        let lo = NIBBLE[(b & 0x0f) as usize];
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = nibble_from_hex(bytes[2 * i])?;
        let lo = nibble_from_hex(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

const NIBBLE: &[u8; 16] = b"0123456789abcdef";

fn nibble_from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
