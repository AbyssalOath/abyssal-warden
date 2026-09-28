//! The updater against a local-directory source, with freshly generated
//! content and timestamp keys.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use warden_core::Sha256Digest;
use warden_engine::bundle::{ContentKind, MANIFEST_FILE, Manifest, ManifestFile};
use warden_engine::content_state::StateError;
use warden_engine::freshness::{TIMESTAMP_FILE, TIMESTAMP_FORMAT, Timestamp};
use warden_engine::trust::TrustedKeys;
use warden_update::{Source, UpdateError, UpdateOptions, update};

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
    fn sign(&self, data: &[u8]) -> String {
        minisign::sign(
            Some(&self.pk),
            &self.sk,
            Cursor::new(data),
            Some("test"),
            None,
        )
        .unwrap()
        .to_string()
    }
    fn id(&self) -> String {
        let mut probe = TrustedKeys::new();
        probe
            .add_key_text(&self.pk.to_base64(), "probe")
            .unwrap()
            .to_string()
    }
    fn entry(&self, roles: &str) -> String {
        let id = self.id();
        format!(
            r#"{{"id":"{id}","public_key":"{}","roles":{roles}}}"#,
            self.pk.to_base64()
        )
    }
}

fn sha(d: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(d).into())
}

fn db(version: &str) -> Vec<u8> {
    format!(
        r#"{{"format":"abyssal-warden.hash-signatures","format_version":1,"database":{{"name":"t","version":"{version}"}},"signatures":[]}}"#
    )
    .into_bytes()
}

struct World {
    _dir: tempfile::TempDir,
    source: PathBuf,
    content: PathBuf,
    state: PathBuf,
    content_key: Signer,
    stamp_key: Signer,
    /// The offline backup timestamp key, listed in the keyring from the start.
    backup_stamp_key: Signer,
    keys: TrustedKeys,
}

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let content_key = Signer::new();
        let stamp_key = Signer::new();
        let backup_stamp_key = Signer::new();
        let ring = format!(
            r#"{{"format":"abyssal-warden.keyring","format_version":1,"keys":[{},{},{}]}}"#,
            content_key.entry(r#"["content"]"#),
            stamp_key.entry(r#"["timestamp"]"#),
            backup_stamp_key.entry(r#"["timestamp"]"#)
        );
        let mut keys = TrustedKeys::new();
        keys.add_keyring(ring.as_bytes(), "ring").unwrap();
        let root = dir.path().to_owned();
        Self {
            source: root.join("mirror"),
            content: root.join("content"),
            state: root.join("state/content-state.json"),
            _dir: dir,
            content_key,
            stamp_key,
            backup_stamp_key,
            keys,
        }
    }

    /// Publishes bundle `sequence` and a timestamp (`version`, lifetime).
    fn publish(&self, sequence: u64, version: u64, lifetime: Duration) {
        self.publish_with(sequence, version, lifetime, &[], &self.stamp_key);
    }

    /// [`World::publish`] with manifest revocations and a chosen timestamp key.
    fn publish_with(
        &self,
        sequence: u64,
        version: u64,
        lifetime: Duration,
        revoke: &[String],
        stamp_key: &Signer,
    ) {
        let _ = std::fs::remove_dir_all(&self.source);
        std::fs::create_dir_all(self.source.join("signatures")).unwrap();
        let data = db(&sequence.to_string());
        std::fs::write(self.source.join("signatures/main.json"), &data).unwrap();
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let mut m = Manifest::new("official".into(), sequence, now, now + Duration::days(30));
        m.revoke_keys = revoke.to_vec();
        m.files.push(ManifestFile {
            path: "signatures/main.json".into(),
            kind: ContentKind::HashDatabase,
            size: data.len() as u64,
            sha256: sha(&data),
        });
        let manifest = serde_json::to_vec_pretty(&m).unwrap();
        std::fs::write(self.source.join(MANIFEST_FILE), &manifest).unwrap();
        std::fs::write(
            self.source.join(format!("{MANIFEST_FILE}.minisig")),
            self.content_key.sign(&manifest),
        )
        .unwrap();
        self.stamp(sequence, version, lifetime, &manifest, stamp_key);
    }

    fn stamp(
        &self,
        sequence: u64,
        version: u64,
        lifetime: Duration,
        manifest: &[u8],
        key: &Signer,
    ) {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let issued = if lifetime.is_negative() {
            now + lifetime - Duration::hours(1)
        } else {
            now
        };
        let ts = Timestamp {
            format: TIMESTAMP_FORMAT.into(),
            format_version: 1,
            version,
            bundle: "official".into(),
            sequence,
            manifest_sha256: sha(manifest),
            manifest_size: manifest.len() as u64,
            issued,
            expires: now + lifetime,
        };
        let ts = serde_json::to_vec(&ts).unwrap();
        std::fs::write(self.source.join(TIMESTAMP_FILE), &ts).unwrap();
        std::fs::write(
            self.source.join(format!("{TIMESTAMP_FILE}.minisig")),
            key.sign(&ts),
        )
        .unwrap();
    }

    fn run(
        &self,
        allow_expired: bool,
        validate: &dyn Fn(&warden_engine::bundle::VerifiedBundle) -> Result<(), String>,
    ) -> Result<warden_update::UpdateOutcome, UpdateError> {
        update(&UpdateOptions {
            source: Source::Dir(self.source.clone()),
            content_dir: self.content.clone(),
            state_path: self.state.clone(),
            keys: &self.keys,
            allow_expired,
            validate,
        })
    }

    fn installed_version(&self) -> String {
        String::from_utf8(
            std::fs::read(self.content.join("official/signatures/main.json")).unwrap(),
        )
        .unwrap()
    }
}

fn ok(_: &warden_engine::bundle::VerifiedBundle) -> Result<(), String> {
    Ok(())
}

#[test]
fn installs_updates_and_stays_current() {
    let w = World::new();
    w.publish(1, 1, Duration::days(2));
    let first = w.run(false, &ok).unwrap();
    assert!(first.changed);
    assert_eq!((first.previous, first.sequence), (None, 1));
    assert!(w.installed_version().contains("\"version\":\"1\""));
    assert!(!w.run(false, &ok).unwrap().changed, "already current");

    w.publish(2, 2, Duration::days(2));
    let second = w.run(false, &ok).unwrap();
    assert!(second.changed);
    assert_eq!(second.previous, Some(1));
    assert!(w.installed_version().contains("\"version\":\"2\""));
    // No staging or old directories are left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&w.content)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(leftovers, vec![std::ffi::OsString::from("official")]);
}

#[test]
fn timestamps_must_come_from_a_timestamp_key_and_be_fresh() {
    let w = World::new();
    w.publish(1, 1, Duration::days(2));
    let manifest = std::fs::read(w.source.join(MANIFEST_FILE)).unwrap();
    // A content key cannot sign timestamps.
    w.stamp(1, 1, Duration::days(2), &manifest, &w.content_key);
    assert!(matches!(
        w.run(false, &ok).unwrap_err(),
        UpdateError::Freshness(_)
    ));
    // An expired timestamp is refused unless explicitly allowed.
    w.stamp(1, 1, -Duration::hours(1), &manifest, &w.stamp_key);
    let err = w.run(false, &ok).unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
    assert!(w.run(true, &ok).unwrap().changed);
}

#[test]
fn replayed_or_stale_channels_are_refused() {
    let w = World::new();
    w.publish(5, 10, Duration::days(2));
    w.run(false, &ok).unwrap();
    // An older timestamp (replay) is refused.
    w.publish(5, 9, Duration::days(2));
    assert!(matches!(
        w.run(false, &ok).unwrap_err(),
        UpdateError::State(StateError::TimestampRollback { .. })
    ));
    // A newer timestamp pointing at an older bundle is refused.
    w.publish(4, 11, Duration::days(2));
    assert!(matches!(
        w.run(false, &ok).unwrap_err(),
        UpdateError::State(StateError::StaleTimestamp { .. })
    ));
    assert!(
        w.installed_version().contains("\"version\":\"5\""),
        "installed bundle untouched"
    );
}

#[test]
fn tampered_downloads_and_invalid_content_never_install() {
    let w = World::new();
    w.publish(1, 1, Duration::days(2));
    w.run(false, &ok).unwrap();

    // The mirror serves a manifest other than the one the timestamp names.
    w.publish(2, 2, Duration::days(2));
    std::fs::write(w.source.join(MANIFEST_FILE), b"{}").unwrap();
    assert!(matches!(
        w.run(false, &ok).unwrap_err(),
        UpdateError::Mismatch(_)
    ));

    // A content file was altered on the mirror (same size).
    w.publish(3, 3, Duration::days(2));
    let f = w.source.join("signatures/main.json");
    let mut data = std::fs::read(&f).unwrap();
    let last = data.len() - 3;
    data[last] ^= 0x01;
    std::fs::write(&f, data).unwrap();
    assert!(matches!(
        w.run(false, &ok).unwrap_err(),
        UpdateError::Mismatch(_)
    ));

    // The caller's validator refuses the content.
    w.publish(4, 4, Duration::days(2));
    let refuse = |_: &warden_engine::bundle::VerifiedBundle| Err("does not parse".to_owned());
    assert!(matches!(
        w.run(false, &refuse).unwrap_err(),
        UpdateError::Invalid(_)
    ));

    assert!(
        w.installed_version().contains("\"version\":\"1\""),
        "installed bundle untouched"
    );
    assert!(
        std::fs::read_dir(&w.content)
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with(".staging"))
    );
    // And the valid update still goes through.
    assert!(w.run(false, &ok).unwrap().changed);
}

#[test]
fn an_interrupted_swap_is_recovered() {
    let w = World::new();
    w.publish(1, 1, Duration::days(2));
    w.run(false, &ok).unwrap();
    // Simulate a crash after the old bundle was set aside.
    std::fs::rename(
        w.content.join("official"),
        w.content.join(".old-official-deadbeef"),
    )
    .unwrap();
    std::fs::create_dir(w.content.join(".staging-official-cafe")).unwrap();
    assert!(
        !w.run(false, &ok).unwrap().changed,
        "recovered copy is current"
    );
    assert!(w.installed_version().contains("\"version\":\"1\""));
    assert!(!Path::new(&w.content.join(".staging-official-cafe")).exists());
}

#[test]
fn a_leaked_timestamp_key_is_retired_for_the_backup_key() {
    let w = World::new();
    w.publish(1, 1, Duration::days(2));
    w.run(false, &ok).unwrap();

    // Rotation: a bundle signed with the offline content key revokes the
    // online timestamp key; the offline backup key signs its timestamp.
    let leaked = w.stamp_key.id();
    w.publish_with(2, 2, Duration::days(2), &[leaked], &w.backup_stamp_key);
    assert!(w.run(false, &ok).unwrap().changed);

    // The leaked key is refused from now on, even though the caller still
    // trusts it (the revocation is in the content state).
    let manifest = std::fs::read(w.source.join(MANIFEST_FILE)).unwrap();
    w.stamp(2, 3, Duration::days(2), &manifest, &w.stamp_key);
    let err = w.run(false, &ok).unwrap_err();
    assert!(matches!(err, UpdateError::Freshness(_)), "{err}");
    // The backup key keeps the channel working.
    w.stamp(2, 3, Duration::days(2), &manifest, &w.backup_stamp_key);
    assert!(!w.run(false, &ok).unwrap().changed);
    w.publish_with(3, 4, Duration::days(2), &[], &w.backup_stamp_key);
    assert!(w.run(false, &ok).unwrap().changed);
}
