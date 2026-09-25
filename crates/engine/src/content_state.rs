//! Rollback protection for content bundles.
//!
//! Records, per bundle name, the highest `sequence` accepted and the SHA-256
//! of that manifest. A bundle is refused if its sequence is **lower** than the
//! recorded one (rollback), or **equal** with a different manifest
//! (equivocation: two different releases claiming the same number).
//!
//! The state file is written atomically (temporary file, fsync, rename) under
//! an exclusive lock, with owner-only permissions on Unix. It protects
//! against a compromised or stale content source, not against an attacker
//! who can already write the user's files; that is recorded in the threat
//! model.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use warden_core::Sha256Digest;

use crate::bundle::VerifiedBundle;

const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("content state {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "content state {path} is unreadable ({reason}); rollback protection cannot be applied. \
         Inspect it; deleting it resets rollback protection"
    )]
    Corrupt { path: PathBuf, reason: String },
    #[error(
        "bundle {name:?}: sequence {offered} is older than sequence {recorded}, which was \
         already accepted (rollback refused)"
    )]
    Rollback {
        name: String,
        offered: u64,
        recorded: u64,
    },
    #[error(
        "bundle {name:?}: sequence {sequence} was already accepted with a different manifest; \
         two different releases claim the same sequence (refused)"
    )]
    Equivocation { name: String, sequence: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRecord {
    pub sequence: u64,
    pub manifest_sha256: Sha256Digest,
    pub signers: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub accepted_at: OffsetDateTime,
}

/// A key revoked by an accepted bundle manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRecord {
    pub by_bundle: String,
    pub sequence: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    format_version: u32,
    bundles: BTreeMap<String, BundleRecord>,
    /// Key IDs (uppercase) revoked by accepted manifests. Only ever grows:
    /// content can remove trust, never add it.
    #[serde(default)]
    revoked_keys: BTreeMap<String, RevocationRecord>,
}

/// The rollback state, loaded and locked for exclusive use until dropped.
#[derive(Debug)]
pub struct ContentState {
    path: PathBuf,
    data: StateFile,
    _lock: File,
}

impl ContentState {
    /// Open (or start) the state at `path`, taking an exclusive lock that
    /// is held until the value is dropped, so concurrent scans cannot
    /// interleave read-modify-write cycles.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let io_err = |source| StateError::Io {
            path: path.to_owned(),
            source,
        };
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            create_private_dir(dir).map_err(io_err)?;
        }
        let lock = private_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path(path))
            .map_err(io_err)?;
        lock.lock().map_err(io_err)?;

        let data = match File::open(path) {
            Ok(f) => {
                let mut bytes = Vec::new();
                f.take(MAX_STATE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(io_err)?;
                if bytes.len() as u64 > MAX_STATE_BYTES {
                    return Err(corrupt(path, "too large"));
                }
                let data: StateFile =
                    serde_json::from_slice(&bytes).map_err(|e| corrupt(path, &e.to_string()))?;
                if data.format_version != 1 {
                    return Err(corrupt(path, "unsupported format_version"));
                }
                data
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => StateFile {
                format_version: 1,
                ..StateFile::default()
            },
            Err(e) => return Err(io_err(e)),
        };
        Ok(Self {
            path: path.to_owned(),
            data,
            _lock: lock,
        })
    }

    pub fn record_for(&self, name: &str) -> Option<&BundleRecord> {
        self.data.bundles.get(name)
    }

    /// Key IDs revoked by accepted manifests.
    pub fn revoked_keys(&self) -> impl Iterator<Item = &str> {
        self.data.revoked_keys.keys().map(String::as_str)
    }

    /// Read only the revoked keys from the state at `path`, without locking
    /// or creating anything (for scans that load no bundles). A missing file
    /// means none.
    pub fn read_revoked_keys(path: &Path) -> Result<Vec<String>, StateError> {
        let io_err = |source| StateError::Io {
            path: path.to_owned(),
            source,
        };
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_err(e)),
        };
        let mut bytes = Vec::new();
        f.take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_err)?;
        let data: StateFile =
            serde_json::from_slice(&bytes).map_err(|e| corrupt(path, &e.to_string()))?;
        Ok(data.revoked_keys.into_keys().collect())
    }

    /// Refuse `bundle` if it would roll back, or equivocate with, what was
    /// accepted before. `floor` is the keyring's minimum sequence for the
    /// bundle, which protects installations that have no record yet.
    pub fn check(&self, bundle: &VerifiedBundle, floor: Option<u64>) -> Result<(), StateError> {
        let m = &bundle.manifest;
        if let Some(floor) = floor
            && m.sequence < floor
        {
            return Err(StateError::Rollback {
                name: m.name.clone(),
                offered: m.sequence,
                recorded: floor,
            });
        }
        match self.data.bundles.get(&m.name) {
            None => Ok(()),
            Some(r) if m.sequence < r.sequence => Err(StateError::Rollback {
                name: m.name.clone(),
                offered: m.sequence,
                recorded: r.sequence,
            }),
            Some(r) if m.sequence == r.sequence && bundle.manifest_sha256 != r.manifest_sha256 => {
                Err(StateError::Equivocation {
                    name: m.name.clone(),
                    sequence: m.sequence,
                })
            }
            Some(_) => Ok(()),
        }
    }

    /// Record `bundle` as accepted, including any keys it revokes. Call
    /// [`ContentState::check`] first and [`ContentState::save`] after.
    pub fn record(&mut self, bundle: &VerifiedBundle, now: OffsetDateTime) {
        let m = &bundle.manifest;
        for id in &m.revoke_keys {
            self.data
                .revoked_keys
                .entry(id.to_ascii_uppercase())
                .or_insert_with(|| RevocationRecord {
                    by_bundle: m.name.clone(),
                    sequence: m.sequence,
                    recorded_at: now,
                });
        }
        let newer = self
            .data
            .bundles
            .get(&m.name)
            .is_none_or(|r| m.sequence > r.sequence);
        if newer {
            self.data.bundles.insert(
                m.name.clone(),
                BundleRecord {
                    sequence: m.sequence,
                    manifest_sha256: bundle.manifest_sha256,
                    signers: bundle.signers.iter().map(ToString::to_string).collect(),
                    accepted_at: now,
                },
            );
        }
    }

    /// Write the state atomically.
    pub fn save(&self) -> Result<(), StateError> {
        let io_err = |source| StateError::Io {
            path: self.path.clone(),
            source,
        };
        let json =
            serde_json::to_vec_pretty(&self.data).map_err(|e| io_err(io::Error::other(e)))?;
        let tmp = tmp_path(&self.path);
        let mut f = private_options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(io_err)?;
        f.write_all(&json).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
        drop(f);
        std::fs::rename(&tmp, &self.path).map_err(io_err)?;
        #[cfg(unix)]
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            File::open(dir).and_then(|d| d.sync_all()).map_err(io_err)?;
        }
        Ok(())
    }
}

fn corrupt(path: &Path, reason: &str) -> StateError {
    StateError::Corrupt {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn lock_path(path: &Path) -> PathBuf {
    with_suffix(path, ".lock")
}

fn tmp_path(path: &Path) -> PathBuf {
    with_suffix(path, ".tmp")
}

fn private_options() -> OpenOptions {
    #[allow(unused_mut)]
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::DirBuilderExt::mode(std::fs::DirBuilder::new().recursive(true), 0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::tests::{Signer, write_bundle};
    use crate::bundle::{ContentKind, LoadOptions, load_bundle};
    use time::Duration;

    fn bundle(seq: u64, content: &[u8]) -> (tempfile::TempDir, VerifiedBundle) {
        let dir = tempfile::tempdir().unwrap();
        let s = Signer::new();
        write_bundle(
            dir.path(),
            &s,
            "official",
            seq,
            Duration::days(1),
            &[("db.json", ContentKind::HashDatabase, content)],
        );
        let b = load_bundle(
            dir.path(),
            &s.keys(),
            LoadOptions {
                allow_expired: false,
                now: OffsetDateTime::now_utc(),
            },
        )
        .unwrap();
        (dir, b)
    }

    #[test]
    fn rollback_and_equivocation_are_refused_across_restarts() {
        let state_dir = tempfile::tempdir().unwrap();
        let path = state_dir.path().join("sub/content-state.json");
        let now = OffsetDateTime::now_utc();
        let (_d5, b5) = bundle(5, b"v5");
        {
            let mut st = ContentState::open(&path).unwrap();
            st.check(&b5, None).unwrap();
            st.record(&b5, now);
            st.save().unwrap();
        }
        // New process: state persisted.
        let st = ContentState::open(&path).unwrap();
        assert_eq!(st.record_for("official").unwrap().sequence, 5);
        let (_d4, b4) = bundle(4, b"v4");
        assert!(matches!(
            st.check(&b4, None),
            Err(StateError::Rollback {
                offered: 4,
                recorded: 5,
                ..
            })
        ));
        let (_dx, b5_other) = bundle(5, b"different v5");
        assert!(matches!(
            st.check(&b5_other, None),
            Err(StateError::Equivocation { .. })
        ));
        st.check(&b5, None).unwrap(); // the same release again is fine
        let (_d6, b6) = bundle(6, b"v6");
        st.check(&b6, None).unwrap();
    }

    #[test]
    fn keyring_floor_protects_fresh_installations() {
        let dir = tempfile::tempdir().unwrap();
        let st = ContentState::open(&dir.path().join("s.json")).unwrap();
        let (_a, b3) = bundle(3, b"3");
        assert!(matches!(
            st.check(&b3, Some(5)),
            Err(StateError::Rollback {
                offered: 3,
                recorded: 5,
                ..
            })
        ));
        st.check(&b3, Some(3)).unwrap();
    }

    #[test]
    fn revocations_from_manifests_persist_and_only_grow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let (_a, mut b) = bundle(1, b"1");
        b.manifest.revoke_keys = vec!["deadbeefdeadbeef".into()];
        {
            let mut st = ContentState::open(&path).unwrap();
            st.record(&b, OffsetDateTime::now_utc());
            st.save().unwrap();
        }
        assert_eq!(
            ContentState::read_revoked_keys(&path).unwrap(),
            vec!["DEADBEEFDEADBEEF".to_string()]
        );
        // A later manifest without the revocation does not undo it.
        let (_c, b2) = bundle(2, b"2");
        let mut st = ContentState::open(&path).unwrap();
        st.record(&b2, OffsetDateTime::now_utc());
        st.save().unwrap();
        assert_eq!(
            st.revoked_keys().collect::<Vec<_>>(),
            vec!["DEADBEEFDEADBEEF"]
        );
        assert!(
            ContentState::read_revoked_keys(&dir.path().join("missing.json"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn record_never_lowers_the_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let mut st = ContentState::open(&path).unwrap();
        let (_a, b7) = bundle(7, b"7");
        let (_b, b3) = bundle(3, b"3");
        st.record(&b7, OffsetDateTime::now_utc());
        st.record(&b3, OffsetDateTime::now_utc());
        assert_eq!(st.record_for("official").unwrap().sequence, 7);
    }

    #[test]
    fn corrupt_state_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(
            ContentState::open(&path),
            Err(StateError::Corrupt { .. })
        ));
        std::fs::write(&path, br#"{"format_version":1,"bundles":{},"extra":1}"#).unwrap();
        assert!(matches!(
            ContentState::open(&path),
            Err(StateError::Corrupt { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn state_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new/s.json");
        let st = ContentState::open(&path).unwrap();
        st.save().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }
}
