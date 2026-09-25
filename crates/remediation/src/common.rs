//! Pieces shared by the platform quarantine stores.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::{QuarantineId, RemediationError};

pub(crate) const DATA_MAGIC: &[u8; 8] = b"AWQDATA1";
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const CHUNK: usize = 64 * 1024;
pub(crate) const MAX_RECORD_BYTES: u64 = 1024 * 1024;

pub(crate) type Result<T> = std::result::Result<T, RemediationError>;

pub(crate) fn io_err(op: &'static str, path: &Path, e: impl Into<io::Error>) -> RemediationError {
    RemediationError::Io {
        op,
        path: path.to_owned(),
        source: e.into(),
    }
}

pub(crate) fn corrupt(id: &QuarantineId, reason: &str) -> RemediationError {
    RemediationError::Corrupt {
        id: id.clone(),
        reason: reason.to_owned(),
    }
}

pub(crate) fn xor_in_place(buf: &mut [u8], key: &[u8], offset: u64) {
    let klen = key.len() as u64;
    for (i, b) in buf.iter_mut().enumerate() {
        let k = key[((offset + i as u64) % klen) as usize];
        *b ^= k;
    }
}

/// Split an absolute path into parent and final component, rejecting `..`
/// and paths without a final normal component.
pub(crate) fn split_checked(path: &Path) -> Result<(PathBuf, OsString)> {
    let invalid = || RemediationError::InvalidPath(path.to_owned());
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Err(invalid());
    }
    let Some(Component::Normal(name)) = path.components().next_back() else {
        return Err(invalid());
    };
    let parent = path.parent().ok_or_else(invalid)?.to_path_buf();
    Ok((parent, name.to_owned()))
}

/// The anchor text for one audit entry (the system log adds its own
/// header). Only characters that cannot start a new field or line are kept.
pub(crate) fn anchor_text(
    seq: u64,
    hash: &str,
    chain: &str,
    action: &str,
    outcome: &str,
) -> String {
    let clean = |s: &str, max: usize| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(max)
            .collect()
    };
    format!(
        "audit seq={seq} hash={} chain={} action={} outcome={}",
        clean(hash, 64),
        clean(chain, 16),
        clean(action, 32),
        clean(outcome, 32),
    )
}
