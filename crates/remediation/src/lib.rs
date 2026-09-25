//! Quarantine, restore and delete, with a crash-safe journal and a
//! hash-chained audit log.
//!
//! This crate is the only part of Abyssal Warden that moves or deletes
//! files. The safety model is specified in `docs/security/quarantine.md`;
//! the invariants the implementation keeps are:
//!
//! * **No data loss.** The original is removed only after the quarantined
//!   copy has been written, `fsync`ed, re-read and verified against the
//!   original's SHA-256. Each item's record doubles as its journal entry and
//!   is written atomically; [`QuarantineStore::open`] replays unfinished
//!   operations.
//! * **Handle-relative, link-free resolution.** Paths are resolved with
//!   `openat2(RESOLVE_NO_SYMLINKS)`; the file is opened and removed relative
//!   to a pinned directory handle, and removed only if it is still the same
//!   inode that was copied.
//! * **Inert storage.** Quarantined content is XOR-encoded with a random
//!   per-item key so it cannot be executed or opened by accident.
//! * **No overwrite on restore.** Restores use `RENAME_NOREPLACE` into a
//!   directory that is not group- or world-writable.
//!
//! Implemented for Linux (`linux.rs`) and Windows (`windows.rs`, same
//! guarantees with Windows mechanisms). On other platforms
//! [`QuarantineStore::open`] returns [`RemediationError::Unsupported`].

mod allowlist;
mod anchors;
mod audit;
mod common;
mod policy;
mod record;
mod report;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

pub use allowlist::{AllowEntry, MAX_ALLOW_ENTRIES, read_allowlist};
pub use anchors::{Anchor, AnchorComparison, compare_anchors, parse_anchor};
pub use audit::{AuditEntry, AuditError, audit_chain, chain_id, verify_audit_log};
pub use policy::{auto_quarantine_target, is_protected_path};
pub use record::{
    ItemState, OriginalFile, QuarantineId, QuarantineReason, QuarantineRecord,
    RECORD_FORMAT_VERSION,
};
pub use report::{mark_allowed, quarantine_report, reason_for};

use std::path::PathBuf;

use warden_core::Sha256Digest;

#[cfg(target_os = "linux")]
pub use linux::{AnchorTarget, QuarantineStore};
#[cfg(windows)]
pub use windows::{AnchorTarget, QuarantineStore};

/// Default store location. Linux: `/var/lib/abyssal-warden/quarantine` when
/// running as root, otherwise `$XDG_DATA_HOME/abyssal-warden/quarantine`
/// (falling back to `~/.local/share`). Windows: `%ProgramData%` (elevated)
/// or `%LOCALAPPDATA%`, then `AbyssalWarden\Quarantine`. `None` if it
/// cannot be determined.
pub fn default_store_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        // Administrators (and the service): machine-wide; others: per user.
        let admin = warden_winsec::process_is_admin().unwrap_or(false);
        let base = if admin {
            std::env::var_os("ProgramData")
        } else {
            std::env::var_os("LOCALAPPDATA")
        };
        base.map(|b| PathBuf::from(b).join("AbyssalWarden").join("Quarantine"))
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        if rustix::process::geteuid().is_root() {
            return Some(PathBuf::from("/var/lib/abyssal-warden/quarantine"));
        }
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
        Some(base.join("abyssal-warden").join("quarantine"))
    }
}

/// A request to quarantine one file.
#[derive(Clone, Debug)]
pub struct QuarantineRequest {
    /// Absolute path, without symbolic links in any component.
    pub path: PathBuf,
    /// If set, the file's current content must hash to this value, or
    /// nothing is changed. Always set this when acting on a finding: it
    /// guarantees the file quarantined is the file that was detected.
    pub expected_sha256: Option<Sha256Digest>,
    pub reason: QuarantineReason,
    /// Refuse files larger than this.
    pub max_size: u64,
    /// Permit paths under system directories (see [`is_protected_path`]).
    /// Never set automatically.
    pub allow_protected: bool,
    /// Pause processes running the file before it is moved, and kill them
    /// once it is quarantined (Linux). Without this they are only reported.
    pub kill_processes: bool,
}

/// What recovery did with an operation that was interrupted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryAction {
    pub id: QuarantineId,
    pub outcome: ItemState,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RemediationError {
    #[error("quarantine is not supported on this platform yet")]
    Unsupported,
    #[error("path must be absolute and must not contain `..`: {0}")]
    InvalidPath(PathBuf),
    #[error(
        "{0} contains a symbolic link (or is not reachable without one); \
         use the fully resolved path"
    )]
    SymlinkInPath(PathBuf),
    #[error("{0} is under a protected system directory; refusing without explicit override")]
    Protected(PathBuf),
    #[error("{0} is inside the quarantine store")]
    InsideStore(PathBuf),
    #[error("{0} is not a regular file")]
    NotRegularFile(PathBuf),
    #[error(
        "{0} is in use by another program (opened without sharing, or a running program); nothing was changed"
    )]
    InUse(PathBuf),
    #[error("{path} is larger than the {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error(
        "{path} has {links} hard links; quarantining one name would leave the \
         content reachable through the others"
    )]
    HardLinked { path: PathBuf, links: u64 },
    #[error("{path} changed: expected SHA-256 {expected}, found {actual}; nothing was modified")]
    FileChanged {
        path: PathBuf,
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    #[error("{path} was replaced while it was being quarantined; nothing was removed")]
    Replaced { path: PathBuf },
    #[error("quarantine store {path} is unsafe: {reason}")]
    StoreInsecure { path: PathBuf, reason: String },
    #[error("quarantine store is in use by another process")]
    StoreBusy,
    #[error("invalid quarantine ID {0:?}")]
    InvalidId(String),
    #[error("no quarantined item {0}")]
    UnknownItem(QuarantineId),
    #[error("item {id} is {state:?}; this operation needs it to be quarantined")]
    InvalidState { id: QuarantineId, state: ItemState },
    #[error("{0} already exists; restore never overwrites")]
    TargetExists(PathBuf),
    #[error("cannot restore into {path}: {reason}")]
    UnsafeTarget { path: PathBuf, reason: String },
    #[error("quarantine data for {id} is corrupt: {reason}")]
    Corrupt { id: QuarantineId, reason: String },
    #[error("{op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("audit log: {0}")]
    Audit(#[from] AuditError),
    #[cfg(test)]
    #[error("injected fault")]
    InjectedFault,
}

#[cfg(not(any(target_os = "linux", windows)))]
mod unsupported {
    use super::*;
    use std::path::Path;

    /// Placeholder on platforms without a quarantine implementation. Every
    /// operation fails with [`RemediationError::Unsupported`].
    #[derive(Debug)]
    pub struct QuarantineStore(());

    // Mirrors the Linux API so callers compile everywhere. `open` always
    // fails, so no value of this type can exist and the other methods are
    // unreachable.
    impl QuarantineStore {
        pub fn open(_root: &Path) -> Result<Self, RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn root(&self) -> &Path {
            Path::new("")
        }
        pub fn recovered(&self) -> &[RecoveryAction] {
            &[]
        }
        pub fn quarantine(
            &mut self,
            _req: &QuarantineRequest,
        ) -> Result<QuarantineRecord, RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn restore(
            &mut self,
            _id: &QuarantineId,
            _dest_dir: Option<&Path>,
        ) -> Result<PathBuf, RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn delete(&mut self, _id: &QuarantineId) -> Result<(), RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn get(&self, _id: &QuarantineId) -> Result<QuarantineRecord, RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn list(&self) -> Result<Vec<QuarantineRecord>, RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn verify_audit_log(&mut self) -> Result<u64, RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn audit_head(&self) -> (u64, &str) {
            (0, "")
        }
        pub fn anchor_failed(&self) -> bool {
            false
        }
        pub fn allowlist(&self) -> Result<Vec<AllowEntry>, RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn allow(
            &mut self,
            _sha256: Sha256Digest,
            _reason: &str,
            _item: Option<&QuarantineId>,
            _detection_name: Option<&str>,
        ) -> Result<(), RemediationError> {
            Err(RemediationError::Unsupported)
        }
        pub fn disallow(&mut self, _sha256: Sha256Digest) -> Result<bool, RemediationError> {
            Err(RemediationError::Unsupported)
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub use unsupported::QuarantineStore;
