//! Signed content bundles.
//!
//! A bundle is a directory holding detection content (hash databases, YARA
//! rules) and a `manifest.json` signed with minisign (`manifest.json.minisig`).
//! The manifest names the bundle, carries a strictly increasing `sequence`,
//! `issued` and `expires` times, and pins every content file by path, size
//! and SHA-256. See `docs/security/content-trust.md`.
//!
//! Loading order, so nothing unauthenticated is parsed:
//! 1. read the manifest (size-capped) and verify its signature against the
//!    trusted keys (revocation and key validity windows apply);
//! 2. parse and validate the manifest strictly;
//! 3. refuse it if expired (unless explicitly allowed);
//! 4. read each listed file relative to the bundle directory (it cannot
//!    escape it) and check its size and SHA-256 before returning it.
//!
//! Rollback protection needs persistent state and is applied by the caller
//! with [`crate::content_state::ContentState`].

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use warden_core::Sha256Digest;

use crate::trust::{KeyId, TrustError, TrustedKeys, read_bounded, signature_path};

/// File name of the manifest inside a bundle directory.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Value of the manifest's `format` field.
pub const MANIFEST_FORMAT: &str = "abyssal-warden.content-manifest";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 4096;
/// Signature files read per manifest: `manifest.json.minisig` and
/// `manifest.json.minisig.2` through `.16`.
pub const MAX_SIGNATURES: usize = 16;
const MAX_REVOCATIONS: usize = 64;
const MAX_FILES: usize = 10_000;
/// Largest content file accepted in a bundle.
pub const MAX_CONTENT_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_NAME_LEN: usize = 128;
const MAX_PATH_LEN: usize = 512;

/// What a content file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    HashDatabase,
    YaraRules,
}

/// One content file listed in a manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    /// Relative path inside the bundle, `/`-separated.
    pub path: String,
    pub kind: ContentKind,
    pub size: u64,
    pub sha256: Sha256Digest,
}

/// The signed description of a bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub format_version: u32,
    /// Bundle identity; rollback protection is tracked per name.
    pub name: String,
    /// Strictly increasing release number.
    pub sequence: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub issued: OffsetDateTime,
    /// After this time the bundle is refused unless expired content is
    /// explicitly allowed (freeze protection).
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
    pub files: Vec<ManifestFile>,
    /// Key IDs this release revokes. Recorded persistently once the manifest
    /// is accepted: content can remove trust, never add it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoke_keys: Vec<String>,
}

impl Manifest {
    /// A new, empty manifest (for the `content manifest` tool).
    pub fn new(
        name: String,
        sequence: u64,
        issued: OffsetDateTime,
        expires: OffsetDateTime,
    ) -> Self {
        Self {
            format: MANIFEST_FORMAT.to_owned(),
            format_version: 1,
            name,
            sequence,
            issued,
            expires,
            files: Vec::new(),
            revoke_keys: Vec::new(),
        }
    }

    /// Check every structural rule. Called on load, and by the manifest tool
    /// before writing.
    pub fn validate(&self) -> Result<(), BundleError> {
        let bad = |reason: String| BundleError::InvalidManifest(reason);
        if self.format != MANIFEST_FORMAT {
            return Err(bad(format!("format must be {MANIFEST_FORMAT:?}")));
        }
        if self.format_version != 1 {
            return Err(bad(format!(
                "unsupported format_version {}",
                self.format_version
            )));
        }
        if !valid_name(&self.name) {
            return Err(bad(format!(
                "name must be 1-{MAX_NAME_LEN} characters of [A-Za-z0-9._-]"
            )));
        }
        if self.sequence == 0 {
            return Err(bad("sequence must be at least 1".into()));
        }
        if self.expires <= self.issued {
            return Err(bad("expires must be after issued".into()));
        }
        if self.files.is_empty() {
            return Err(bad("the bundle lists no files".into()));
        }
        if self.files.len() > MAX_FILES {
            return Err(bad(format!("more than {MAX_FILES} files")));
        }
        if self.revoke_keys.len() > MAX_REVOCATIONS {
            return Err(bad(format!("more than {MAX_REVOCATIONS} revoked keys")));
        }
        if let Some(k) = self.revoke_keys.iter().find(|k| !valid_key_id(k)) {
            return Err(bad(format!(
                "revoke_keys entry {:?} is not a 16-hex-digit key ID",
                truncate(k)
            )));
        }
        let mut seen = HashSet::new();
        for f in &self.files {
            if !valid_relative_path(&f.path) {
                return Err(bad(format!("invalid file path {:?}", truncate(&f.path))));
            }
            if !seen.insert(f.path.as_str()) {
                return Err(bad(format!("duplicate file path {:?}", truncate(&f.path))));
            }
            if f.size > MAX_CONTENT_FILE_BYTES {
                return Err(bad(format!("{} is larger than the file limit", f.path)));
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error("{dir}: no signature at {signature}; content bundles must be signed")]
    Unsigned { dir: PathBuf, signature: PathBuf },
    #[error(
        "{dir}: {valid} valid signature(s) from distinct trusted keys, {required} required{}",
        if problems.is_empty() { String::new() } else { format!(" ({})", problems.join("; ")) }
    )]
    InsufficientSignatures {
        dir: PathBuf,
        valid: usize,
        required: usize,
        problems: Vec<String>,
    },
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error(
        "bundle {name:?} expired at {expires} (sequence {sequence}); refusing stale content \
         (update the bundle, or explicitly allow expired content)"
    )]
    Expired {
        name: String,
        sequence: u64,
        expires: String,
    },
    #[error("{path}: {reason}")]
    File { path: String, reason: String },
}

/// A content file read from a verified bundle.
#[derive(Debug)]
pub struct BundleFile {
    pub path: String,
    pub kind: ContentKind,
    pub data: Vec<u8>,
}

/// A bundle whose signature, structure, freshness and file hashes have been
/// verified. Rollback has **not** been checked yet.
#[derive(Debug)]
pub struct VerifiedBundle {
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// SHA-256 of the exact manifest bytes that were verified.
    pub manifest_sha256: Sha256Digest,
    /// Distinct trusted keys whose signatures verified (at least the
    /// threshold).
    pub signers: Vec<KeyId>,
    /// The bundle had expired and was accepted only because that was allowed.
    pub expired: bool,
    pub files: Vec<BundleFile>,
}

/// Options for [`load_bundle`].
#[derive(Clone, Copy, Debug)]
pub struct LoadOptions {
    pub allow_expired: bool,
    pub now: OffsetDateTime,
}

/// Verify and load the bundle in `dir`. See the module docs for the order of
/// checks.
pub fn load_bundle(
    dir: &Path,
    keys: &TrustedKeys,
    opts: LoadOptions,
) -> Result<VerifiedBundle, BundleError> {
    if keys.is_empty() {
        return Err(TrustError::NoTrustedKeys.into());
    }
    let manifest_path = dir.join(MANIFEST_FILE);
    let data = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let signers = verify_signatures(dir, &manifest_path, &data, keys, opts.now)?;

    let manifest: Manifest =
        serde_json::from_slice(&data).map_err(|e| BundleError::InvalidManifest(e.to_string()))?;
    manifest.validate()?;
    let expired = opts.now > manifest.expires;
    if expired && !opts.allow_expired {
        return Err(BundleError::Expired {
            name: manifest.name.clone(),
            sequence: manifest.sequence,
            expires: rfc3339(manifest.expires),
        });
    }

    let root =
        cap_std::fs::Dir::open_ambient_dir(dir, cap_std::ambient_authority()).map_err(|e| {
            BundleError::File {
                path: dir.display().to_string(),
                reason: e.to_string(),
            }
        })?;
    let mut files = Vec::with_capacity(manifest.files.len());
    for entry in &manifest.files {
        files.push(BundleFile {
            path: entry.path.clone(),
            kind: entry.kind,
            data: read_listed(&root, entry)?,
        });
    }

    Ok(VerifiedBundle {
        dir: dir.to_owned(),
        manifest_sha256: Sha256Digest::from_bytes(Sha256::digest(&data).into()),
        manifest,
        signers,
        expired,
        files,
    })
}

/// The signature files of a manifest: `.minisig`, then `.minisig.2` to
/// `.minisig.16`.
pub fn signature_paths(manifest_path: &Path) -> Vec<PathBuf> {
    let first = signature_path(manifest_path);
    let mut out = vec![first.clone()];
    for n in 2..=MAX_SIGNATURES {
        let mut p = first.clone().into_os_string();
        p.push(format!(".{n}"));
        out.push(PathBuf::from(p));
    }
    out
}

/// Verify every signature present and require `keys.threshold()` distinct,
/// currently valid, unrevoked keys. Signatures that fail (untrusted,
/// revoked, out of validity) do not count and are reported if the threshold
/// is not met.
fn verify_signatures(
    dir: &Path,
    manifest_path: &Path,
    data: &[u8],
    keys: &TrustedKeys,
    now: OffsetDateTime,
) -> Result<Vec<KeyId>, BundleError> {
    let mut signers: Vec<KeyId> = Vec::new();
    let mut problems = Vec::new();
    let mut found_any = false;
    for sig_path in signature_paths(manifest_path) {
        let sig = match read_bounded(&sig_path, MAX_SIGNATURE_BYTES) {
            Ok(s) => s,
            Err(TrustError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        found_any = true;
        let name = sig_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Ok(text) = String::from_utf8(sig) else {
            problems.push(format!("{name}: not UTF-8"));
            continue;
        };
        match keys.verify(data, &text, manifest_path, now) {
            Ok((id, _)) if !signers.contains(&id) => signers.push(id),
            Ok((id, _)) => problems.push(format!("{name}: another signature by key {id}")),
            Err(e) => problems.push(format!("{name}: {e}")),
        }
    }
    if !found_any {
        return Err(BundleError::Unsigned {
            dir: dir.to_owned(),
            signature: signature_path(manifest_path),
        });
    }
    let required = keys.threshold();
    if signers.len() < required {
        return Err(BundleError::InsufficientSignatures {
            dir: dir.to_owned(),
            valid: signers.len(),
            required,
            problems,
        });
    }
    Ok(signers)
}

/// Key IDs as minisign prints them: 16 hexadecimal digits.
fn valid_key_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read a listed file relative to the bundle root (no escape, final link not
/// followed) and check its exact size and hash.
fn read_listed(root: &cap_std::fs::Dir, entry: &ManifestFile) -> Result<Vec<u8>, BundleError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};

    let err = |reason: String| BundleError::File {
        path: entry.path.clone(),
        reason,
    };
    let mut opts = cap_std::fs::OpenOptions::new();
    opts.read(true);
    opts.follow(FollowSymlinks::No);
    let file = root
        .open_with(&entry.path, &opts)
        .map_err(|e| err(e.to_string()))?;
    let mut data = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
    file.take(entry.size.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|e| err(e.to_string()))?;
    if data.len() as u64 != entry.size {
        return Err(err(format!(
            "size is {} bytes, the manifest says {}",
            data.len(),
            entry.size
        )));
    }
    let actual = Sha256Digest::from_bytes(Sha256::digest(&data).into());
    if actual != entry.sha256 {
        return Err(err(format!(
            "SHA-256 {actual} does not match the manifest ({})",
            entry.sha256
        )));
    }
    Ok(data)
}

/// Bundle names: `[A-Za-z0-9._-]`, 1-128 characters.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A portable relative path: `/`-separated normal components only; no
/// absolute paths, `.`/`..`, backslashes, drive letters, empty components,
/// or control/bidi characters.
pub fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_LEN
        && !path.contains('\\')
        && !path.contains(':')
        && !warden_core::text::has_unsafe_chars(path, false)
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

fn truncate(s: &str) -> String {
    s.chars().take(80).collect()
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;
    use time::Duration;

    pub(crate) struct Signer {
        pub(crate) pk: minisign::PublicKey,
        sk: minisign::SecretKey,
    }

    impl Signer {
        pub(crate) fn new() -> Self {
            let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            Self {
                pk: kp.pk,
                sk: kp.sk,
            }
        }
        pub(crate) fn keys(&self) -> TrustedKeys {
            let mut k = TrustedKeys::new();
            k.add_key_text(&self.pk.to_base64(), "test").unwrap();
            k
        }
        pub(crate) fn sign(&self, data: &[u8]) -> String {
            minisign::sign(Some(&self.pk), &self.sk, Cursor::new(data), None, None)
                .unwrap()
                .to_string()
        }
    }

    /// Write a signed bundle to `dir` with the given files.
    pub(crate) fn write_bundle(
        dir: &Path,
        signer: &Signer,
        name: &str,
        sequence: u64,
        expires_in: Duration,
        files: &[(&str, ContentKind, &[u8])],
    ) -> Manifest {
        let now = OffsetDateTime::now_utc();
        let mut m = Manifest::new(
            name.into(),
            sequence,
            now - Duration::hours(1),
            now + expires_in,
        );
        for (path, kind, data) in files {
            let p = dir.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, data).unwrap();
            m.files.push(ManifestFile {
                path: (*path).to_owned(),
                kind: *kind,
                size: data.len() as u64,
                sha256: Sha256Digest::from_bytes(Sha256::digest(data).into()),
            });
        }
        let json = serde_json::to_vec_pretty(&m).unwrap();
        std::fs::write(dir.join(MANIFEST_FILE), &json).unwrap();
        std::fs::write(signature_path(&dir.join(MANIFEST_FILE)), signer.sign(&json)).unwrap();
        m
    }

    fn opts() -> LoadOptions {
        LoadOptions {
            allow_expired: false,
            now: OffsetDateTime::now_utc(),
        }
    }

    const FILES: &[(&str, ContentKind, &[u8])] = &[
        (
            "signatures/db.json",
            ContentKind::HashDatabase,
            b"{\"db\":1}",
        ),
        (
            "rules/r.yar",
            ContentKind::YaraRules,
            b"rule r { condition: true }",
        ),
    ];

    #[test]
    fn loads_a_valid_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        write_bundle(dir.path(), &s, "test-bundle", 7, Duration::days(30), FILES);
        let b = load_bundle(dir.path(), &s.keys(), opts()).unwrap();
        assert_eq!(b.manifest.sequence, 7);
        assert_eq!(b.files.len(), 2);
        assert_eq!(b.files[1].data, FILES[1].2);
        assert!(!b.expired);
    }

    #[test]
    fn tampered_or_extra_content_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        write_bundle(dir.path(), &s, "b", 1, Duration::days(1), FILES);
        // A content file changed after signing.
        std::fs::write(
            dir.path().join("rules/r.yar"),
            b"rule r { condition: false }",
        )
        .unwrap();
        let e = load_bundle(dir.path(), &s.keys(), opts()).unwrap_err();
        assert!(matches!(e, BundleError::File { .. }), "{e}");

        // The manifest changed after signing.
        let dir = tempfile::tempdir().unwrap();
        write_bundle(dir.path(), &s, "b", 1, Duration::days(1), FILES);
        let m = dir.path().join(MANIFEST_FILE);
        let text = std::fs::read_to_string(&m)
            .unwrap()
            .replace("\"sequence\": 1", "\"sequence\": 99");
        std::fs::write(&m, text).unwrap();
        let e = load_bundle(dir.path(), &s.keys(), opts()).unwrap_err();
        assert!(
            matches!(e, BundleError::InsufficientSignatures { valid: 0, .. }),
            "{e}"
        );
    }

    #[test]
    fn same_size_tampering_is_caught_by_the_hash() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        write_bundle(dir.path(), &s, "b", 1, Duration::days(1), FILES);
        // Same length as the signed file, different bytes.
        std::fs::write(
            dir.path().join("rules/r.yar"),
            b"rule r { condition: TRUE }",
        )
        .unwrap();
        let e = load_bundle(dir.path(), &s.keys(), opts()).unwrap_err();
        assert!(e.to_string().contains("does not match the manifest"), "{e}");
    }

    /// Keys trusting every given signer, with a threshold.
    fn keys_with_threshold(signers: &[&Signer], threshold: usize) -> TrustedKeys {
        let mut ring = String::from(r#"{"format":"abyssal-warden.keyring","format_version":1,"#);
        ring.push_str(&format!(r#""policy":{{"threshold":{threshold}}},"keys":["#));
        let entries: Vec<String> = signers
            .iter()
            .map(|s| {
                let mut probe = TrustedKeys::new();
                let id = probe.add_key_text(&s.pk.to_base64(), "p").unwrap();
                format!(r#"{{"id":"{id}","public_key":"{}"}}"#, s.pk.to_base64())
            })
            .collect();
        ring.push_str(&entries.join(","));
        ring.push_str("]}");
        let mut keys = TrustedKeys::new();
        keys.add_keyring(ring.as_bytes(), "test").unwrap();
        keys
    }

    fn add_signature(dir: &Path, n: usize, signer: &Signer) {
        let m = dir.join(MANIFEST_FILE);
        let data = std::fs::read(&m).unwrap();
        std::fs::write(&signature_paths(&m)[n - 1], signer.sign(&data)).unwrap();
    }

    #[test]
    fn threshold_requires_distinct_valid_signers() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, c) = (Signer::new(), Signer::new(), Signer::new());
        write_bundle(dir.path(), &a, "b", 1, Duration::days(1), FILES);
        let keys = keys_with_threshold(&[&a, &b], 2);

        // One signature: not enough.
        let e = load_bundle(dir.path(), &keys, opts()).unwrap_err();
        assert!(
            matches!(
                e,
                BundleError::InsufficientSignatures {
                    valid: 1,
                    required: 2,
                    ..
                }
            ),
            "{e}"
        );
        // The same key twice still counts once.
        add_signature(dir.path(), 2, &a);
        let e = load_bundle(dir.path(), &keys, opts()).unwrap_err();
        assert!(e.to_string().contains("another signature by key"), "{e}");
        // An untrusted key does not count.
        add_signature(dir.path(), 3, &c);
        assert!(load_bundle(dir.path(), &keys, opts()).is_err());
        // A second trusted key meets the threshold.
        add_signature(dir.path(), 4, &b);
        let loaded = load_bundle(dir.path(), &keys, opts()).unwrap();
        assert_eq!(loaded.signers.len(), 2);

        // Revoking one of them drops below the threshold again.
        let mut revoked = keys.clone();
        let mut probe = TrustedKeys::new();
        let b_id = probe.add_key_text(&b.pk.to_base64(), "p").unwrap();
        assert!(revoked.revoke(&b_id.to_string()));
        let e = load_bundle(dir.path(), &revoked, opts()).unwrap_err();
        assert!(e.to_string().contains("revoked"), "{e}");
    }

    #[test]
    fn revoke_keys_must_be_key_ids() {
        let now = OffsetDateTime::now_utc();
        let mut m = Manifest::new("ok".into(), 1, now, now + Duration::days(1));
        m.files.push(ManifestFile {
            path: "a.json".into(),
            kind: ContentKind::HashDatabase,
            size: 1,
            sha256: Sha256Digest::from_bytes([0; 32]),
        });
        m.revoke_keys = vec!["70EF691BC71E4DD9".into()];
        assert!(m.validate().is_ok());
        m.revoke_keys = vec!["not-a-key".into()];
        assert!(m.validate().is_err());
    }

    #[test]
    fn untrusted_and_unsigned_bundles_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        write_bundle(dir.path(), &s, "b", 1, Duration::days(1), FILES);
        let e = load_bundle(dir.path(), &Signer::new().keys(), opts()).unwrap_err();
        assert!(matches!(
            e,
            BundleError::InsufficientSignatures { valid: 0, .. }
        ));
        std::fs::remove_file(signature_path(&dir.path().join(MANIFEST_FILE))).unwrap();
        let e = load_bundle(dir.path(), &s.keys(), opts()).unwrap_err();
        assert!(matches!(e, BundleError::Unsigned { .. }));
    }

    #[test]
    fn expired_bundles_are_refused_unless_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        write_bundle(dir.path(), &s, "b", 1, Duration::minutes(30), FILES);
        let later = LoadOptions {
            allow_expired: false,
            now: OffsetDateTime::now_utc() + Duration::hours(1),
        };
        assert!(matches!(
            load_bundle(dir.path(), &s.keys(), later),
            Err(BundleError::Expired { .. })
        ));
        let allowed = LoadOptions {
            allow_expired: true,
            ..later
        };
        assert!(load_bundle(dir.path(), &s.keys(), allowed).unwrap().expired);
    }

    #[cfg(unix)]
    #[test]
    fn listed_files_cannot_escape_the_bundle() {
        let top = tempfile::tempdir().unwrap();
        let dir = top.path().join("bundle");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(top.path().join("outside.json"), b"{\"db\":1}").unwrap();
        let s = Signer::new();
        write_bundle(&dir, &s, "b", 1, Duration::days(1), FILES);
        // Replace a listed file with a link to a file outside the bundle
        // that has the right content: still refused.
        std::fs::remove_file(dir.join("signatures/db.json")).unwrap();
        std::os::unix::fs::symlink(
            top.path().join("outside.json"),
            dir.join("signatures/db.json"),
        )
        .unwrap();
        let e = load_bundle(&dir, &s.keys(), opts()).unwrap_err();
        assert!(matches!(e, BundleError::File { .. }), "{e}");
    }

    #[test]
    fn manifest_rules() {
        let now = OffsetDateTime::now_utc();
        let base = || {
            let mut m = Manifest::new("ok".into(), 1, now, now + Duration::days(1));
            m.files.push(ManifestFile {
                path: "a.json".into(),
                kind: ContentKind::HashDatabase,
                size: 1,
                sha256: Sha256Digest::from_bytes([0; 32]),
            });
            m
        };
        assert!(base().validate().is_ok());
        let mut cases: Vec<Manifest> = Vec::new();
        let mut m = base();
        m.name = "bad name".into();
        cases.push(m);
        let mut m = base();
        m.sequence = 0;
        cases.push(m);
        let mut m = base();
        m.expires = m.issued;
        cases.push(m);
        let mut m = base();
        m.files.clear();
        cases.push(m);
        for p in [
            "../x",
            "/abs",
            "a//b",
            "./a",
            "a\\b",
            "C:x",
            "a/\u{202E}b",
            "",
        ] {
            let mut m = base();
            m.files[0].path = p.into();
            cases.push(m);
        }
        let mut m = base();
        m.files.push(m.files[0].clone());
        cases.push(m);
        for (i, c) in cases.iter().enumerate() {
            assert!(c.validate().is_err(), "case {i} accepted: {c:?}");
        }
    }

    #[test]
    fn unknown_manifest_fields_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        write_bundle(dir.path(), &s, "b", 1, Duration::days(1), FILES);
        let m = dir.path().join(MANIFEST_FILE);
        let text = std::fs::read_to_string(&m)
            .unwrap()
            .replacen('{', "{\"trust_me\": true,", 1);
        std::fs::write(&m, &text).unwrap();
        std::fs::write(signature_path(&m), s.sign(text.as_bytes())).unwrap();
        assert!(matches!(
            load_bundle(dir.path(), &s.keys(), opts()),
            Err(BundleError::InvalidManifest(_))
        ));
    }
}
