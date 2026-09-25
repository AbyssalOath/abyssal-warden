//! Quarantine item records. Each record is both the item's metadata and its
//! journal entry: `state` is advanced atomically at each step.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use warden_core::{ObservedPath, Sha256Digest};

pub const RECORD_FORMAT_VERSION: u32 = 1;

/// Random 128-bit item ID, 32 lowercase hex characters. IDs are used as file
/// names inside the store, so parsing is strict (no separators, no dots).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QuarantineId(String);

impl QuarantineId {
    // Used only by the Linux store until other platforms get one.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn random() -> Result<Self, getrandom::Error> {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b)?;
        Ok(Self(hex(&b)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for QuarantineId {
    type Err = crate::RemediationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(s.to_owned()))
        } else {
            Err(crate::RemediationError::InvalidId(
                s.chars().take(64).collect(),
            ))
        }
    }
}

impl fmt::Display for QuarantineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for QuarantineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuarantineId({})", self.0)
    }
}

impl Serialize for QuarantineId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for QuarantineId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Lifecycle of an item.
///
/// ```text
/// pending ──► quarantined ──► restored
///    │              └───────► deleted
///    └──► rolled_back | failed
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// Operation in progress (or interrupted; recovery resolves it).
    Pending,
    /// Content is in the store; the original has been removed.
    Quarantined,
    /// Content was written back and removed from the store.
    Restored,
    /// Content was permanently deleted from the store.
    Deleted,
    /// The operation was undone; the original was never removed.
    RolledBack,
    /// Recovery found neither a complete copy nor the original. Should not
    /// happen unless something else removed the file mid-operation.
    Failed,
}

/// What the file looked like when it was quarantined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalFile {
    pub path: ObservedPath,
    pub size: u64,
    pub sha256: Sha256Digest,
    /// Unix: `st_mode & 0o7777`. Windows: file attributes.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Unix: device. Windows: volume serial number.
    pub dev: u64,
    /// Unix: inode. Windows: file index.
    pub ino: u64,
    /// Windows: the file owner's SID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_sid: Option<String>,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub modified: Option<OffsetDateTime>,
}

/// Why the item was quarantined: the finding it came from, or a manual note.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineReason {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    pub format_version: u32,
    pub id: QuarantineId,
    pub state: ItemState,
    pub original: OriginalFile,
    /// Per-item XOR key (hex). Makes stored content inert; not a secret.
    pub key_hex: String,
    pub reason: QuarantineReason,
    pub actor_uid: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_to: Option<ObservedPath>,
    /// Human-readable notes added by operations and recovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

// Used only by the Linux store until other platforms get one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// Used only by the Linux store until other platforms get one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_strict() {
        let id = QuarantineId::random().unwrap();
        assert_eq!(id.as_str().len(), 32);
        assert_eq!(id.as_str().parse::<QuarantineId>().unwrap(), id);
        for bad in [
            "",
            "../../etc/passwd",
            "0123456789abcdef0123456789abcde",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdef.json",
            "0123456789abcdef/123456789abcdef",
        ] {
            assert!(bad.parse::<QuarantineId>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(
            unhex(&hex(&[0, 1, 0xfe, 0xff])).unwrap(),
            vec![0, 1, 0xfe, 0xff]
        );
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
}
