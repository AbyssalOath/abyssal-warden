//! Allow-list of exact file contents (SHA-256) the user has decided to keep,
//! normally by restoring them from quarantine.
//!
//! Stored as `allowlist.json` in the private quarantine store. Only exact
//! hashes are listed: any change to the file makes it a different file.
//! Allowed findings are still reported (marked `allowed`), never hidden.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use warden_core::Sha256Digest;

use crate::RemediationError;

pub(crate) const ALLOWLIST_FILE: &str = "allowlist.json";
pub(crate) const MAX_ALLOWLIST_BYTES: u64 = 4 * 1024 * 1024;
/// Most entries kept; adding beyond this fails rather than growing without
/// bound.
pub const MAX_ALLOW_ENTRIES: usize = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub sha256: Sha256Digest,
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
    /// Why it was allowed (e.g. "restored from quarantine").
    pub reason: String,
    /// The quarantine item it was restored from, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// Detection name at the time, for the user's reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_name: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AllowlistFile {
    pub(crate) format_version: u32,
    pub(crate) entries: Vec<AllowEntry>,
}

pub(crate) fn parse(bytes: &[u8], path: &Path) -> Result<AllowlistFile, RemediationError> {
    let corrupt = |reason: String| RemediationError::StoreInsecure {
        path: path.to_owned(),
        reason: format!("allow-list is unreadable ({reason})"),
    };
    let file: AllowlistFile = serde_json::from_slice(bytes).map_err(|e| corrupt(e.to_string()))?;
    if file.format_version != 1 {
        return Err(corrupt("unsupported format_version".into()));
    }
    Ok(file)
}

/// Read the allow-list of the store at `store_root` without opening
/// (locking, recovering or creating) the store. A missing store or list
/// means an empty list. The file must not be a symbolic link.
pub fn read_allowlist(store_root: &Path) -> Result<Vec<AllowEntry>, RemediationError> {
    let path = store_root.join(ALLOWLIST_FILE);
    let io_err = |op, e| RemediationError::Io {
        op,
        path: path.clone(),
        source: e,
    };
    match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
            return Err(RemediationError::StoreInsecure {
                path: path.clone(),
                reason: "the allow-list is not a regular file".into(),
            });
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err("stat", e)),
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|e| io_err("open", e))?
        .take(MAX_ALLOWLIST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_err("read", e))?;
    if bytes.len() as u64 > MAX_ALLOWLIST_BYTES {
        return Err(RemediationError::StoreInsecure {
            path,
            reason: "the allow-list is too large".into(),
        });
    }
    Ok(parse(&bytes, &path)?.entries)
}
