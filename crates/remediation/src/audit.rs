//! Hash-chained, append-only audit log (JSON Lines).
//!
//! Each line records one action and carries `prev`, the SHA-256 of the
//! previous line's bytes (all zeros for the first). Editing, removing or
//! reordering any line other than the last breaks the chain, which
//! [`verify_audit_log`] reports.
//!
//! Limitation: someone who can write the file can rewrite the whole chain
//! consistently, or truncate it at the end. Anchoring the head hash outside
//! the host (syslog / remote collector) is future work.

use std::io::{BufRead, BufReader, Read};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use warden_core::{ObservedPath, Sha256Digest};

pub(crate) const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Longest accepted line; paths are bounded by PATH_MAX, so real entries are
/// far smaller.
const MAX_LINE: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub seq: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    pub actor_uid: u32,
    /// The user a service performed the action for (IPC caller).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<u32>,
    /// `quarantine`, `restore`, `delete`, `recover`.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<ObservedPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Digest>,
    /// `ok` or `error`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// SHA-256 (hex) of the previous line.
    pub prev: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("line {line}: {reason}")]
    Broken { line: u64, reason: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot serialise entry: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Chain position after the last valid line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChainHead {
    pub(crate) seq: u64,
    pub(crate) hash: String,
    /// Hash of the first entry, which identifies the chain.
    pub(crate) first: Option<String>,
}

impl ChainHead {
    pub(crate) fn genesis() -> Self {
        Self {
            seq: 0,
            hash: GENESIS.to_owned(),
            first: None,
        }
    }

    /// The chain's identifier (see [`chain_id`]), once it has an entry.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn chain_id(&self) -> Option<String> {
        self.first.as_deref().map(chain_id)
    }
}

/// Identifies an audit chain in anchors: the first 16 hex digits of the
/// hash of its first entry. A chain rewritten from the start gets a new id.
pub fn chain_id(first_entry_hash: &str) -> String {
    first_entry_hash.chars().take(16).collect()
}

pub(crate) fn line_hash(line: &[u8]) -> String {
    Sha256Digest::from_bytes(Sha256::digest(line).into()).to_hex()
}

/// Serialise `entry` (whose `seq` and `prev` are set from `head`) as one
/// line, returning the line (with newline) and the new head.
// Used only by the Linux store until other platforms get one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn encode(
    mut entry: AuditEntry,
    head: &ChainHead,
) -> Result<(Vec<u8>, ChainHead), AuditError> {
    entry.seq = head.seq + 1;
    entry.prev = head.hash.clone();
    let mut line = serde_json::to_vec(&entry)?;
    let hash = line_hash(&line);
    let new_head = ChainHead {
        seq: entry.seq,
        first: head.first.clone().or_else(|| Some(hash.clone())),
        hash,
    };
    line.push(b'\n');
    Ok((line, new_head))
}

/// Verify the whole chain and return its head. An empty log is valid.
pub fn verify_audit_log<R: Read>(reader: R) -> Result<u64, AuditError> {
    verify_chain(reader).map(|h| h.seq)
}

/// Verify the whole chain and return every entry's sequence number and hash.
pub fn audit_chain<R: Read>(reader: R) -> Result<Vec<(u64, String)>, AuditError> {
    let mut out = Vec::new();
    walk_chain(reader, |seq, hash| out.push((seq, hash.to_owned())))?;
    Ok(out)
}

pub(crate) fn verify_chain<R: Read>(reader: R) -> Result<ChainHead, AuditError> {
    walk_chain(reader, |_, _| {})
}

fn walk_chain<R: Read>(
    reader: R,
    mut on_entry: impl FnMut(u64, &str),
) -> Result<ChainHead, AuditError> {
    let mut head = ChainHead::genesis();
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader
            .by_ref()
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(head);
        }
        let lineno = head.seq + 1;
        let broken = |reason: String| AuditError::Broken {
            line: lineno,
            reason,
        };
        if line.last() != Some(&b'\n') {
            return Err(broken("incomplete or over-long line".into()));
        }
        line.pop();
        let entry: AuditEntry =
            serde_json::from_slice(&line).map_err(|e| broken(format!("not a valid entry: {e}")))?;
        if entry.seq != lineno {
            return Err(broken(format!(
                "sequence {} where {lineno} expected",
                entry.seq
            )));
        }
        if entry.prev != head.hash {
            return Err(broken(
                "hash chain mismatch (a previous line was altered or removed)".into(),
            ));
        }
        let hash = line_hash(&line);
        on_entry(lineno, &hash);
        head = ChainHead {
            seq: lineno,
            first: head.first.or_else(|| Some(hash.clone())),
            hash,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(action: &str) -> AuditEntry {
        AuditEntry {
            seq: 0,
            time: OffsetDateTime::UNIX_EPOCH,
            actor_uid: 1000,
            on_behalf_of: None,
            action: action.into(),
            item: None,
            path: None,
            sha256: None,
            outcome: "ok".into(),
            detail: None,
            prev: String::new(),
        }
    }

    fn log(actions: &[&str]) -> Vec<u8> {
        let mut head = ChainHead::genesis();
        let mut out = Vec::new();
        for a in actions {
            let (line, h) = encode(entry(a), &head).unwrap();
            out.extend(line);
            head = h;
        }
        out
    }

    #[test]
    fn valid_chain_verifies() {
        assert_eq!(verify_audit_log(&b""[..]).unwrap(), 0);
        let l = log(&["quarantine", "restore", "delete"]);
        assert_eq!(verify_audit_log(&l[..]).unwrap(), 3);
    }

    #[test]
    fn detects_edits_removals_and_truncated_lines() {
        let l = log(&["quarantine", "restore", "delete"]);
        let text = String::from_utf8(l.clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        let edited = text.replacen("\"restore\"", "\"delete\"", 1);
        assert!(verify_audit_log(edited.as_bytes()).is_err());

        let removed = format!("{}\n{}\n", lines[0], lines[2]);
        assert!(verify_audit_log(removed.as_bytes()).is_err());

        let partial = &l[..l.len() - 5];
        assert!(verify_audit_log(partial).is_err());

        let reordered = format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]);
        assert!(verify_audit_log(reordered.as_bytes()).is_err());
    }
}
