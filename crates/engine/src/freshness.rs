//! Freshness of the content update channel: the signed `timestamp.json`.
//!
//! A content bundle is signed with offline (possibly threshold) keys, so it
//! cannot be re-signed every day. Its `expires` stops endless replay of an
//! old release, but only coarsely. The update channel therefore also
//! publishes a small **timestamp**, re-signed often by a key with the
//! `timestamp` role, that names the latest bundle (name, sequence, manifest
//! hash) and expires within days. A client:
//!
//! * refuses a timestamp not signed by a timestamp-role key, expired, or
//!   older (`version`) than one it has seen (freeze and replay);
//! * refuses a timestamp naming an older bundle than it has accepted;
//! * downloads only the manifest whose SHA-256 the timestamp names, and
//!   then verifies the bundle itself with its content keys as usual.
//!
//! A stolen timestamp key can at worst delay updates (point at the current
//! bundle, or let a timestamp lapse); it cannot make content trusted.
//! See docs/architecture/decisions/0020-content-updates.md.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use warden_core::Sha256Digest;

use crate::trust::{KeyId, KeyRole, TrustError, TrustedKeys};

pub const TIMESTAMP_FILE: &str = "timestamp.json";
pub const TIMESTAMP_FORMAT: &str = "abyssal-warden.content-timestamp";
pub const MAX_TIMESTAMP_BYTES: u64 = 64 * 1024;
/// Longest lifetime a timestamp may declare.
pub const MAX_TIMESTAMP_LIFETIME: Duration = Duration::days(31);
/// Tolerated clock difference for `issued` in the future.
const CLOCK_SKEW: Duration = Duration::minutes(10);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamp {
    pub format: String,
    pub format_version: u32,
    /// Increases with every timestamp published (at least 1).
    pub version: u64,
    /// Bundle name.
    pub bundle: String,
    /// The bundle's current sequence.
    pub sequence: u64,
    pub manifest_sha256: Sha256Digest,
    pub manifest_size: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub issued: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
}

#[derive(Debug, thiserror::Error)]
pub enum FreshnessError {
    #[error(transparent)]
    Signature(#[from] TrustError),
    #[error("invalid timestamp: {0}")]
    Invalid(String),
    #[error(
        "the update channel's timestamp expired at {0}; the source is stale or frozen (refused)"
    )]
    Expired(String),
}

impl Timestamp {
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), FreshnessError> {
        let bad = |m: &str| Err(FreshnessError::Invalid(m.into()));
        if self.format != TIMESTAMP_FORMAT || self.format_version != 1 {
            return bad("unknown format or format_version");
        }
        if self.version == 0 || self.sequence == 0 {
            return bad("version and sequence must be at least 1");
        }
        if !crate::bundle::valid_name(&self.bundle) {
            return bad("bundle name must be 1-128 characters of [A-Za-z0-9._-]");
        }
        if self.manifest_size == 0 || self.manifest_size > crate::bundle::MAX_MANIFEST_BYTES {
            return bad("manifest_size out of range");
        }
        if self.expires <= self.issued || self.expires - self.issued > MAX_TIMESTAMP_LIFETIME {
            return bad("expires must be after issued and within 31 days of it");
        }
        if self.issued > now + CLOCK_SKEW {
            return bad("issued in the future (check the clock)");
        }
        Ok(())
    }
}

/// A timestamp whose signature, format and validity have been checked.
#[derive(Clone, Debug)]
pub struct VerifiedTimestamp {
    pub timestamp: Timestamp,
    pub signer: KeyId,
    pub sha256: Sha256Digest,
}

/// Verifies `data` (a `timestamp.json`) against `signature_text` with a
/// timestamp-role key. Expired timestamps are refused unless
/// `allow_expired`.
pub fn verify_timestamp(
    data: &[u8],
    signature_text: &str,
    keys: &TrustedKeys,
    now: OffsetDateTime,
    allow_expired: bool,
) -> Result<VerifiedTimestamp, FreshnessError> {
    use sha2::{Digest, Sha256};
    if data.len() as u64 > MAX_TIMESTAMP_BYTES {
        return Err(FreshnessError::Invalid("larger than 64 KiB".into()));
    }
    let (signer, _) = keys.verify_role(
        data,
        signature_text,
        std::path::Path::new(TIMESTAMP_FILE),
        now,
        KeyRole::Timestamp,
    )?;
    let timestamp: Timestamp =
        serde_json::from_slice(data).map_err(|e| FreshnessError::Invalid(e.to_string()))?;
    timestamp.validate(now)?;
    if now > timestamp.expires && !allow_expired {
        return Err(FreshnessError::Expired(
            timestamp
                .expires
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        ));
    }
    Ok(VerifiedTimestamp {
        timestamp,
        signer,
        sha256: Sha256Digest::from_bytes(Sha256::digest(data).into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(now: OffsetDateTime) -> Timestamp {
        Timestamp {
            format: TIMESTAMP_FORMAT.into(),
            format_version: 1,
            version: 3,
            bundle: "official".into(),
            sequence: 7,
            manifest_sha256: Sha256Digest::from_bytes([1; 32]),
            manifest_size: 100,
            issued: now - Duration::hours(1),
            expires: now + Duration::days(2),
        }
    }

    #[test]
    fn validation() {
        let now = OffsetDateTime::now_utc();
        assert!(ts(now).validate(now).is_ok());
        let cases: Vec<fn(&mut Timestamp)> = vec![
            |t| t.format = "x".into(),
            |t| t.version = 0,
            |t| t.bundle = "../x".into(),
            |t| t.manifest_size = 0,
            |t| t.expires = t.issued,
            |t| t.expires = t.issued + Duration::days(40),
            |t| t.issued += Duration::days(1),
        ];
        for (i, f) in cases.into_iter().enumerate() {
            let mut t = ts(now);
            f(&mut t);
            if i == 6 {
                t.expires = t.issued + Duration::days(1);
            }
            assert!(t.validate(now).is_err(), "case {i}");
        }
    }
}
