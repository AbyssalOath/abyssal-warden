use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A SHA-256 digest. Serialised as 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DigestParseError {
    #[error("expected 64 hexadecimal characters, found {0}")]
    InvalidLength(usize),
    #[error("invalid hexadecimal character at byte offset {0}")]
    InvalidCharacter(usize),
}

impl FromStr for Sha256Digest {
    type Err = DigestParseError;

    /// Parses exactly 64 hexadecimal characters (either case). No prefixes,
    /// separators or surrounding whitespace are accepted.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(DigestParseError::InvalidLength(bytes.len()));
        }
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = hex_value(pair[0]).ok_or(DigestParseError::InvalidCharacter(i * 2))?;
            let lo = hex_value(pair[1]).ok_or(DigestParseError::InvalidCharacter(i * 2 + 1))?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-256 of the empty input (FIPS 180-4 test vector).
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn round_trips_hex() {
        let d: Sha256Digest = EMPTY.parse().unwrap();
        assert_eq!(d.to_hex(), EMPTY);
        assert_eq!(d.as_bytes()[0], 0xe3);
        assert_eq!(d.as_bytes()[31], 0x55);
    }

    #[test]
    fn accepts_uppercase_and_normalises() {
        let d: Sha256Digest = EMPTY.to_uppercase().parse().unwrap();
        assert_eq!(d.to_string(), EMPTY);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(
            "abc".parse::<Sha256Digest>(),
            Err(DigestParseError::InvalidLength(3))
        );
        let mut bad = EMPTY.to_string();
        bad.replace_range(10..11, "g");
        assert_eq!(
            bad.parse::<Sha256Digest>(),
            Err(DigestParseError::InvalidCharacter(10))
        );
        let padded = format!(" {}", &EMPTY[1..]);
        assert!(padded.parse::<Sha256Digest>().is_err());
        // Multi-byte UTF-8 must be rejected by length/character checks, not panic.
        let multibyte = format!("é{}", &EMPTY[2..]);
        assert!(multibyte.parse::<Sha256Digest>().is_err());
    }

    #[test]
    fn serde_uses_hex_string() {
        let d: Sha256Digest = EMPTY.parse().unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{EMPTY}\""));
        let back: Sha256Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
        assert!(serde_json::from_str::<Sha256Digest>("\"00\"").is_err());
    }
}
