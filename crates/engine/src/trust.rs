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

#[derive(Debug)]
struct TrustedKey {
    id: KeyId,
    key: PublicKey,
}

/// The set of public keys whose signatures are accepted.
#[derive(Debug, Default)]
pub struct TrustedKeys {
    keys: Vec<TrustedKey>,
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
            self.keys.push(TrustedKey { id, key });
        }
        Ok(id)
    }

    pub fn add_key_file(&mut self, path: &Path) -> Result<KeyId, TrustError> {
        let data = read_bounded(path, MAX_KEY_BYTES)?;
        let text = String::from_utf8(data).map_err(|_| TrustError::InvalidKey {
            source_name: path.display().to_string(),
            reason: "not UTF-8".into(),
        })?;
        self.add_key_text(&text, &path.display().to_string())
    }

    /// Verify `data` against the text of a `.minisig` file. Returns the ID of
    /// the key that verified it.
    pub fn verify(
        &self,
        data: &[u8],
        signature_text: &str,
        path: &Path,
    ) -> Result<(KeyId, String), TrustError> {
        let sig = Signature::decode(signature_text).map_err(|e| TrustError::InvalidSignature {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;
        for k in &self.keys {
            // `false`: legacy (non-prehashed) signatures are refused.
            if k.key.verify(data, &sig, false).is_ok() {
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
        Some(sig) => {
            let text = String::from_utf8(sig).map_err(|_| TrustError::InvalidSignature {
                path: sig_path.clone(),
                reason: "not UTF-8".into(),
            })?;
            let (id, comment) = keys.verify(&data, &text, path)?;
            Ok(LoadedContent {
                path: path.to_owned(),
                data,
                signer: Some(id),
                trusted_comment: Some(comment),
            })
        }
    }
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, TrustError> {
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
    for chunk in bytes.chunks_exact(4) {
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
