//! Signature verification for detection content (hash databases, YARA rules).
//!
//! Content files are signed with [minisign](https://jedisct1.github.io/minisign/)
//! (Ed25519). The signature of `rules.yar` is expected at `rules.yar.minisig`.
//! Only prehashed (`ED`) signatures are accepted; legacy signatures are
//! rejected. Verification covers both the content and the signed "trusted
//! comment".
//!
//! Verification happens **before** content is parsed, so parsers only ever
//! see authenticated input when a signature is required.
//!
//! This module provides authenticity only. Rollback and freeze protection
//! need persistent state and belong to the future updater
//! (`docs/security/update-security.md`).

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Largest `.minisig` file accepted.
const MAX_SIGNATURE_BYTES: u64 = 4096;
/// Largest public key file accepted.
const MAX_KEY_BYTES: u64 = 4096;

/// A minisign key ID, displayed as minisign does (16 uppercase hex digits).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 8]);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", u64::from_le_bytes(self.0))
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self})")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is larger than the {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("invalid public key in {source_name}: {reason}")]
    InvalidKey { source_name: String, reason: String },
    #[error("invalid signature file {path}: {reason}")]
    InvalidSignature { path: PathBuf, reason: String },
    #[error(
        "{path} is not signed: expected a signature at {signature_path} \
         (pass a trusted key, or explicitly allow unsigned content)"
    )]
    Unsigned {
        path: PathBuf,
        signature_path: PathBuf,
    },
    #[error("{path}: the signature does not verify with any trusted key")]
    Untrusted { path: PathBuf },
    #[error("signed content was required but no trusted keys are configured")]
    NoTrustedKeys,
    #[error("{path}: signed by key {id}, which is revoked in the keyring")]
    KeyRevoked { path: PathBuf, id: String },
    #[error("{path}: signed by key {id}, which is not valid at this time ({window})")]
    KeyOutsideValidity {
        path: PathBuf,
        id: String,
        window: String,
    },
    #[error("invalid keyring {source_name}: {reason}")]
    InvalidKeyring { source_name: String, reason: String },
    #[error(
        "{path}: the keyring requires {threshold} signatures, but individually signed files \
         carry one; distribute this content as a signed bundle"
    )]
    ThresholdRequiresBundle { path: PathBuf, threshold: usize },
}

/// Whether unsigned content may be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// A valid signature from a trusted key is required.
    RequireTrusted,
    /// Unsigned content is accepted. A signature file that *is* present must
    /// still verify: a bad signature is never silently ignored.
    AllowUnsigned,
}

#[derive(Clone, Debug)]
struct TrustedKey {
    id: KeyId,
    key: PublicKey,
    /// Validity window and revocation, from a keyring. Keys given directly
    /// (`--trusted-key`) have no window and are not revoked.
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
    revoked: bool,
}

impl TrustedKey {
    fn window(&self) -> String {
        let fmt = |t: Option<OffsetDateTime>| {
            t.and_then(|t| t.format(&Rfc3339).ok())
                .unwrap_or_else(|| "unbounded".to_owned())
        };
        format!(
            "valid from {} to {}",
            fmt(self.not_before),
            fmt(self.not_after)
        )
    }

    fn valid_at(&self, now: OffsetDateTime) -> bool {
        self.not_before.is_none_or(|t| now >= t) && self.not_after.is_none_or(|t| now <= t)
    }
}

/// On-disk keyring: the set of content-signing keys, with validity windows
/// and revocations. Distributed through a trusted channel (package or
/// release), never learned from content. See `docs/security/content-trust.md`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringFile {
    format: String,
    format_version: u32,
    keys: Vec<KeyringEntry>,
    #[serde(default)]
    policy: Option<KeyringPolicy>,
    /// Minimum acceptable sequence per bundle name, as of this keyring's
    /// release: protects fresh installations from old releases.
    #[serde(default)]
    bundles: Vec<BundleFloor>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringPolicy {
    /// Distinct valid signatures a content bundle manifest needs.
    threshold: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFloor {
    name: String,
    min_sequence: u64,
}

/// Largest signature threshold a keyring may set.
pub const MAX_THRESHOLD: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringEntry {
    /// Key ID as minisign prints it; must match `public_key`.
    id: String,
    /// Base64 minisign public key.
    public_key: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    not_before: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    not_after: Option<OffsetDateTime>,
    #[serde(default)]
    revoked: bool,
}

/// Value of a keyring's `format` field.
pub const KEYRING_FORMAT: &str = "abyssal-warden.keyring";
const MAX_KEYRING_BYTES: u64 = 256 * 1024;
const MAX_KEYRING_KEYS: usize = 256;

/// The set of public keys whose signatures are accepted, with the policy
/// from any keyrings: signature threshold and per-bundle sequence floors.
#[derive(Clone, Debug, Default)]
pub struct TrustedKeys {
    keys: Vec<TrustedKey>,
    /// Required distinct signatures for bundles (0 is treated as 1).
    threshold: usize,
    min_sequences: std::collections::HashMap<String, u64>,
}

impl TrustedKeys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Distinct valid signatures a bundle manifest needs (at least 1).
    pub fn threshold(&self) -> usize {
        self.threshold.max(1)
    }

    /// The keyring's minimum sequence for bundle `name`, if any.
    pub fn min_sequence(&self, name: &str) -> Option<u64> {
        self.min_sequences.get(name).copied()
    }

    /// Mark the key with ID `id` (as minisign prints it) revoked. Returns
    /// whether such a key is present. Revocation cannot be undone here.
    pub fn revoke(&mut self, id: &str) -> bool {
        let mut found = false;
        for k in &mut self.keys {
            if k.id.to_string().eq_ignore_ascii_case(id) {
                k.revoked = true;
                found = true;
            }
        }
        found
    }

    /// Add a key from the text of a minisign `.pub` file, or from a bare
    /// base64 public key.
    pub fn add_key_text(&mut self, text: &str, source_name: &str) -> Result<KeyId, TrustError> {
        let invalid = |reason: String| TrustError::InvalidKey {
            source_name: source_name.to_owned(),
            reason,
        };
        let b64 = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .ok_or_else(|| invalid("no key found".into()))?;
        let key = PublicKey::from_base64(b64).map_err(|e| invalid(e.to_string()))?;
        let raw = base64_decode(b64).ok_or_else(|| invalid("not valid base64".into()))?;
        let id_bytes: [u8; 8] = raw
            .get(2..10)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| invalid("key too short".into()))?;
        let id = KeyId(id_bytes);
        if !self.keys.iter().any(|k| k.id == id) {
            self.keys.push(TrustedKey {
                id,
                key,
                not_before: None,
                not_after: None,
                revoked: false,
            });
        }
        Ok(id)
    }

    /// Add the keys of a keyring file (JSON). A key already present (e.g.
    /// from `--trusted-key`) takes the keyring's restrictions: revocation
    /// always wins, and validity windows can only narrow.
    pub fn add_keyring(
        &mut self,
        json: &[u8],
        source_name: &str,
    ) -> Result<Vec<KeyId>, TrustError> {
        let invalid = |reason: String| TrustError::InvalidKeyring {
            source_name: source_name.to_owned(),
            reason,
        };
        let file: KeyringFile = serde_json::from_slice(json).map_err(|e| invalid(e.to_string()))?;
        if file.format != KEYRING_FORMAT {
            return Err(invalid(format!("format must be {KEYRING_FORMAT:?}")));
        }
        if file.format_version != 1 {
            return Err(invalid(format!(
                "unsupported format_version {}",
                file.format_version
            )));
        }
        if file.keys.len() > MAX_KEYRING_KEYS {
            return Err(invalid(format!("more than {MAX_KEYRING_KEYS} keys")));
        }
        if let Some(policy) = &file.policy {
            if !(1..=MAX_THRESHOLD).contains(&policy.threshold) {
                return Err(invalid(format!(
                    "policy.threshold must be between 1 and {MAX_THRESHOLD}"
                )));
            }
            // Several keyrings: the strictest threshold wins.
            self.threshold = self.threshold.max(policy.threshold);
        }
        for (i, floor) in file.bundles.iter().enumerate() {
            let ok_name = !floor.name.is_empty()
                && floor.name.len() <= 128
                && floor
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
            if !ok_name {
                return Err(invalid(format!("bundles[{i}].name is invalid")));
            }
            let e = self.min_sequences.entry(floor.name.clone()).or_insert(0);
            *e = (*e).max(floor.min_sequence);
        }
        let mut ids = Vec::new();
        for (i, entry) in file.keys.iter().enumerate() {
            if let Some(d) = &entry.description
                && (d.len() > 1024 || warden_core::text::has_unsafe_chars(d, false))
            {
                return Err(invalid(format!("keys[{i}].description is invalid")));
            }
            if let (Some(a), Some(b)) = (entry.not_before, entry.not_after)
                && a > b
            {
                return Err(invalid(format!("keys[{i}]: not_before is after not_after")));
            }
            let id = self
                .add_key_text(&entry.public_key, source_name)
                .map_err(|e| invalid(format!("keys[{i}]: {e}")))?;
            if !id.to_string().eq_ignore_ascii_case(&entry.id) {
                return Err(invalid(format!(
                    "keys[{i}]: id {:?} does not match the public key ({id})",
                    entry.id
                )));
            }
            if let Some(k) = self.keys.iter_mut().find(|k| k.id == id) {
                k.revoked |= entry.revoked;
                k.not_before = k.not_before.max(entry.not_before);
                k.not_after = match (k.not_after, entry.not_after) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
            ids.push(id);
        }
        Ok(ids)
    }

    pub fn add_keyring_file(&mut self, path: &Path) -> Result<Vec<KeyId>, TrustError> {
        let data = read_bounded(path, MAX_KEYRING_BYTES)?;
        self.add_keyring(&data, &path.display().to_string())
    }

    pub fn add_key_file(&mut self, path: &Path) -> Result<KeyId, TrustError> {
        let data = read_bounded(path, MAX_KEY_BYTES)?;
        let text = String::from_utf8(data).map_err(|_| TrustError::InvalidKey {
            source_name: path.display().to_string(),
            reason: "not UTF-8".into(),
        })?;
        self.add_key_text(&text, &path.display().to_string())
    }

    /// Verify `data` against the text of a `.minisig` file at time `now`.
    /// Returns the ID of the key that verified it and the signed trusted
    /// comment. A signature from a revoked key, or from a key outside its
    /// validity window, is refused with a specific error.
    pub fn verify(
        &self,
        data: &[u8],
        signature_text: &str,
        path: &Path,
        now: OffsetDateTime,
    ) -> Result<(KeyId, String), TrustError> {
        let sig = Signature::decode(signature_text).map_err(|e| TrustError::InvalidSignature {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;
        for k in &self.keys {
            // `false`: legacy (non-prehashed) signatures are refused.
            if k.key.verify(data, &sig, false).is_ok() {
                if k.revoked {
                    return Err(TrustError::KeyRevoked {
                        path: path.to_owned(),
                        id: k.id.to_string(),
                    });
                }
                if !k.valid_at(now) {
                    return Err(TrustError::KeyOutsideValidity {
                        path: path.to_owned(),
                        id: k.id.to_string(),
                        window: k.window(),
                    });
                }
                return Ok((k.id, sig.trusted_comment().to_owned()));
            }
        }
        Err(TrustError::Untrusted {
            path: path.to_owned(),
        })
    }
}

/// Content read from disk, with the outcome of signature verification.
#[derive(Debug)]
pub struct LoadedContent {
    pub path: PathBuf,
    pub data: Vec<u8>,
    /// Key that verified the content; `None` if loaded unsigned.
    pub signer: Option<KeyId>,
    /// The signed trusted comment, if verified.
    pub trusted_comment: Option<String>,
}

/// Path of the detached signature for `path` (`<path>.minisig`).
pub fn signature_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".minisig");
    PathBuf::from(s)
}

/// Read `path` (at most `max_bytes`) and verify its detached signature
/// according to `policy`.
pub fn load_content(
    path: &Path,
    max_bytes: u64,
    keys: &TrustedKeys,
    policy: SignaturePolicy,
) -> Result<LoadedContent, TrustError> {
    if policy == SignaturePolicy::RequireTrusted && keys.is_empty() {
        return Err(TrustError::NoTrustedKeys);
    }
    let threshold_error = || TrustError::ThresholdRequiresBundle {
        path: path.to_owned(),
        threshold: keys.threshold(),
    };
    if policy == SignaturePolicy::RequireTrusted && keys.threshold() > 1 {
        return Err(threshold_error());
    }
    let data = read_bounded(path, max_bytes)?;
    let sig_path = signature_path(path);
    let sig = match read_bounded(&sig_path, MAX_SIGNATURE_BYTES) {
        Ok(s) => Some(s),
        Err(TrustError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };

    match sig {
        None if policy == SignaturePolicy::AllowUnsigned => Ok(LoadedContent {
            path: path.to_owned(),
            data,
            signer: None,
            trusted_comment: None,
        }),
        None => Err(TrustError::Unsigned {
            path: path.to_owned(),
            signature_path: sig_path,
        }),
        Some(_) if keys.threshold() > 1 => Err(threshold_error()),
        Some(sig) => {
            let text = String::from_utf8(sig).map_err(|_| TrustError::InvalidSignature {
                path: sig_path.clone(),
                reason: "not UTF-8".into(),
            })?;
            let (id, comment) = keys.verify(&data, &text, path, OffsetDateTime::now_utc())?;
            Ok(LoadedContent {
                path: path.to_owned(),
                data,
                signer: Some(id),
                trusted_comment: Some(comment),
            })
        }
    }
}

pub(crate) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, TrustError> {
    let io_err = |source| TrustError::Io {
        path: path.to_owned(),
        source,
    };
    let file = File::open(path).map_err(io_err)?;
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(io_err)?;
    if data.len() as u64 > limit {
        return Err(TrustError::TooLarge {
            path: path.to_owned(),
            limit,
        });
    }
    Ok(data)
}

/// Standard base64 (with padding) decoder, used only to extract key IDs.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    // Length is checked above, so there is no remainder.
    let (chunks, _) = bytes.as_chunks::<4>();
    for chunk in chunks {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * pad as u32;
        let b = n.to_be_bytes();
        out.extend_from_slice(&b[1..4 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Signer {
        pk: minisign::PublicKey,
        sk: minisign::SecretKey,
    }

    impl Signer {
        fn new() -> Self {
            let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            Self {
                pk: kp.pk,
                sk: kp.sk,
            }
        }
        fn pub_text(&self) -> String {
            self.pk.to_box().unwrap().to_string()
        }
        fn sign(&self, data: &[u8]) -> String {
            minisign::sign(
                Some(&self.pk),
                &self.sk,
                Cursor::new(data),
                Some("test db v1"),
                None,
            )
            .unwrap()
            .to_string()
        }
    }

    fn write_signed(dir: &Path, name: &str, data: &[u8], signer: Option<&Signer>) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        if let Some(s) = signer {
            std::fs::write(signature_path(&p), s.sign(data)).unwrap();
        }
        p
    }

    fn keyring_json(entries: &[(&Signer, &str)]) -> String {
        let keys: Vec<String> = entries
            .iter()
            .map(|(s, extra)| {
                let mut probe = TrustedKeys::new();
                let id = probe.add_key_text(&s.pk.to_base64(), "probe").unwrap();
                format!(
                    r#"{{"id":"{id}","public_key":"{}"{extra}}}"#,
                    s.pk.to_base64()
                )
            })
            .collect();
        format!(
            r#"{{"format":"{KEYRING_FORMAT}","format_version":1,"keys":[{}]}}"#,
            keys.join(",")
        )
    }

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &Rfc3339).unwrap()
    }

    #[test]
    fn keyring_enforces_revocation_and_validity() {
        let current = Signer::new();
        let old = Signer::new();
        let future = Signer::new();
        let json = keyring_json(&[
            (&current, ""),
            (&old, r##","revoked":true,"description":"retired 2026-09""##),
            (&future, r#","not_before":"2030-01-01T00:00:00Z""#),
        ]);
        let mut keys = TrustedKeys::new();
        assert_eq!(keys.add_keyring(json.as_bytes(), "test").unwrap().len(), 3);
        let now = at("2026-09-25T00:00:00Z");
        let p = Path::new("x");

        assert!(keys.verify(b"data", &current.sign(b"data"), p, now).is_ok());
        assert!(matches!(
            keys.verify(b"data", &old.sign(b"data"), p, now),
            Err(TrustError::KeyRevoked { .. })
        ));
        assert!(matches!(
            keys.verify(b"data", &future.sign(b"data"), p, now),
            Err(TrustError::KeyOutsideValidity { .. })
        ));
        assert!(
            keys.verify(
                b"data",
                &future.sign(b"data"),
                p,
                at("2031-01-01T00:00:00Z")
            )
            .is_ok()
        );
    }

    #[test]
    fn keyring_revocation_overrides_directly_trusted_key() {
        let k = Signer::new();
        let mut keys = TrustedKeys::new();
        keys.add_key_text(&k.pub_text(), "cli").unwrap();
        keys.add_keyring(
            keyring_json(&[(&k, r#","revoked":true"#)]).as_bytes(),
            "ring",
        )
        .unwrap();
        assert!(matches!(
            keys.verify(
                b"d",
                &k.sign(b"d"),
                Path::new("x"),
                OffsetDateTime::now_utc()
            ),
            Err(TrustError::KeyRevoked { .. })
        ));
    }

    #[test]
    fn keyring_policy_and_floors_take_the_strictest_value() {
        let a = Signer::new();
        let ring = |extra: &str| {
            keyring_json(&[(&a, "")]).replacen(r#""keys":["#, &format!(r#"{extra}"keys":["#), 1)
        };
        let mut keys = TrustedKeys::new();
        assert_eq!(keys.threshold(), 1);
        keys.add_keyring(
            ring(r#""policy":{"threshold":2},"bundles":[{"name":"official","min_sequence":10}],"#)
                .as_bytes(),
            "one",
        )
        .unwrap();
        keys.add_keyring(
            ring(r#""policy":{"threshold":1},"bundles":[{"name":"official","min_sequence":7}],"#)
                .as_bytes(),
            "two",
        )
        .unwrap();
        assert_eq!(keys.threshold(), 2);
        assert_eq!(keys.min_sequence("official"), Some(10));
        assert_eq!(keys.min_sequence("other"), None);

        for bad in [
            r#""policy":{"threshold":0},"#,
            r#""policy":{"threshold":17},"#,
            r#""bundles":[{"name":"bad name","min_sequence":1}],"#,
        ] {
            assert!(
                TrustedKeys::new()
                    .add_keyring(ring(bad).as_bytes(), "t")
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn threshold_above_one_refuses_individually_signed_files() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        let mut keys = TrustedKeys::new();
        let ring = keyring_json(&[(&s, "")]).replacen(
            r#""keys":["#,
            r#""policy":{"threshold":2},"keys":["#,
            1,
        );
        keys.add_keyring(ring.as_bytes(), "t").unwrap();
        let p = write_signed(dir.path(), "db.json", b"{}", Some(&s));
        assert!(matches!(
            load_content(&p, 100, &keys, SignaturePolicy::RequireTrusted),
            Err(TrustError::ThresholdRequiresBundle { threshold: 2, .. })
        ));
    }

    #[test]
    fn revoke_marks_keys_revoked() {
        let s = Signer::new();
        let mut keys = TrustedKeys::new();
        let id = keys.add_key_text(&s.pub_text(), "k").unwrap();
        assert!(keys.revoke(&id.to_string().to_lowercase()));
        assert!(!keys.revoke("0000000000000000"));
        assert!(matches!(
            keys.verify(
                b"d",
                &s.sign(b"d"),
                Path::new("x"),
                OffsetDateTime::now_utc()
            ),
            Err(TrustError::KeyRevoked { .. })
        ));
    }

    #[test]
    fn keyring_is_validated() {
        let k = Signer::new();
        let good = keyring_json(&[(&k, "")]);
        let cases = [
            good.replace(KEYRING_FORMAT, "something-else"),
            good.replace(r#""format_version":1"#, r#""format_version":2"#),
            good.replace(r#""keys":["#, r#""extra":1,"keys":["#),
            // ID that does not match the public key.
            {
                let mut probe = TrustedKeys::new();
                let id = probe
                    .add_key_text(&k.pk.to_base64(), "p")
                    .unwrap()
                    .to_string();
                good.replace(&id, "0000000000000000")
            },
            keyring_json(&[(
                &k,
                r#","not_before":"2030-01-01T00:00:00Z","not_after":"2029-01-01T00:00:00Z""#,
            )]),
            "not json".to_owned(),
        ];
        for c in cases {
            assert!(
                matches!(
                    TrustedKeys::new().add_keyring(c.as_bytes(), "t"),
                    Err(TrustError::InvalidKeyring { .. })
                ),
                "accepted: {c}"
            );
        }
    }

    #[test]
    fn base64_decoding() {
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert!(base64_decode("TQ=").is_none());
        assert!(base64_decode("T!==").is_none());
    }

    #[test]
    fn key_id_matches_minisign_display() {
        let s = Signer::new();
        let mut keys = TrustedKeys::new();
        let id = keys.add_key_text(&s.pub_text(), "test").unwrap();
        // minisign writes "untrusted comment: minisign public key <ID>".
        assert!(
            s.pub_text().contains(&id.to_string()),
            "{} / {}",
            id,
            s.pub_text()
        );
        // Bare base64 works too, and duplicates are not added twice.
        keys.add_key_text(&s.pk.to_base64(), "bare").unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn verifies_trusted_signature() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        let mut keys = TrustedKeys::new();
        let id = keys.add_key_text(&s.pub_text(), "k").unwrap();
        let p = write_signed(dir.path(), "db.json", b"{}", Some(&s));
        let c = load_content(&p, 100, &keys, SignaturePolicy::RequireTrusted).unwrap();
        assert_eq!(c.signer, Some(id));
        assert_eq!(c.trusted_comment.as_deref(), Some("test db v1"));
        assert_eq!(c.data, b"{}");
    }

    #[test]
    fn rejects_tampered_content_and_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        let other = Signer::new();
        let mut keys = TrustedKeys::new();
        keys.add_key_text(&s.pub_text(), "k").unwrap();

        let p = write_signed(dir.path(), "db.json", b"{\"a\":1}", Some(&s));
        std::fs::write(&p, b"{\"a\":2}").unwrap();
        assert!(matches!(
            load_content(&p, 100, &keys, SignaturePolicy::RequireTrusted),
            Err(TrustError::Untrusted { .. })
        ));
        // A bad signature is an error even when unsigned content is allowed.
        assert!(matches!(
            load_content(&p, 100, &keys, SignaturePolicy::AllowUnsigned),
            Err(TrustError::Untrusted { .. })
        ));

        let q = write_signed(dir.path(), "other.json", b"{}", Some(&other));
        assert!(matches!(
            load_content(&q, 100, &keys, SignaturePolicy::RequireTrusted),
            Err(TrustError::Untrusted { .. })
        ));
    }

    #[test]
    fn unsigned_content_policy() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        let mut keys = TrustedKeys::new();
        keys.add_key_text(&s.pub_text(), "k").unwrap();
        let p = write_signed(dir.path(), "db.json", b"{}", None);
        assert!(matches!(
            load_content(&p, 100, &keys, SignaturePolicy::RequireTrusted),
            Err(TrustError::Unsigned { .. })
        ));
        let c = load_content(&p, 100, &keys, SignaturePolicy::AllowUnsigned).unwrap();
        assert!(c.signer.is_none());
        assert!(matches!(
            load_content(
                &p,
                100,
                &TrustedKeys::new(),
                SignaturePolicy::RequireTrusted
            ),
            Err(TrustError::NoTrustedKeys)
        ));
    }

    #[test]
    fn rejects_garbage_signature_and_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        let mut keys = TrustedKeys::new();
        keys.add_key_text(&s.pub_text(), "k").unwrap();
        let p = write_signed(dir.path(), "db.json", b"{}", None);
        std::fs::write(signature_path(&p), "not a signature").unwrap();
        assert!(matches!(
            load_content(&p, 100, &keys, SignaturePolicy::AllowUnsigned),
            Err(TrustError::InvalidSignature { .. })
        ));
        assert!(matches!(
            load_content(&p, 1, &keys, SignaturePolicy::AllowUnsigned),
            Err(TrustError::TooLarge { .. })
        ));
        assert!(keys.add_key_text("RWgarbage", "bad").is_err());
        assert!(keys.add_key_text("", "empty").is_err());
    }
}
