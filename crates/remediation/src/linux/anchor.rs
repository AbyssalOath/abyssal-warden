//! External anchoring of the audit log in the system log.
//!
//! After each audit entry is written, its sequence number and chain hash are
//! sent to syslog (`/dev/log`; journald listens there on systemd systems) as
//! an `authpriv.notice` message tagged `abyssal-warden`. Unprivileged users
//! cannot delete or rewrite system journal entries, so a local audit log
//! that was rewritten, truncated or reset no longer matches the anchored
//! hashes:
//!
//! ```text
//! journalctl -t abyssal-warden          # anchored heads
//! abyssal-warden quarantine verify-log  # local chain and its head
//! ```
//!
//! Only fixed-format ASCII is sent (no paths or detection names), so the
//! anchor cannot be used for log injection and does not put file names in
//! the system log.
//!
//! `ABYSSAL_WARDEN_SYSLOG_SOCKET` overrides the socket path; set it to an
//! empty string to disable anchoring (tests use it to capture messages).

use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

/// syslog facility `authpriv` (10) and severity `notice` (5).
const PRIORITY: u32 = 10 * 8 + 5;
const DEFAULT_SOCKET: &str = "/dev/log";
const SOCKET_ENV: &str = "ABYSSAL_WARDEN_SYSLOG_SOCKET";

/// Where audit anchors are sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AnchorTarget {
    /// `/dev/log`, unless `ABYSSAL_WARDEN_SYSLOG_SOCKET` says otherwise (an
    /// empty value disables anchoring).
    #[default]
    FromEnvironment,
    Disabled,
    /// A specific syslog datagram socket.
    Socket(PathBuf),
}

impl AnchorTarget {
    /// The socket to send to, or `None` when disabled.
    pub(super) fn resolve(&self) -> Option<PathBuf> {
        match self {
            Self::Disabled => None,
            Self::Socket(p) => Some(p.clone()),
            Self::FromEnvironment => match std::env::var_os(SOCKET_ENV) {
                Some(v) if v.is_empty() => None,
                Some(v) => Some(PathBuf::from(v)),
                None => Some(PathBuf::from(DEFAULT_SOCKET)),
            },
        }
    }
}

/// The message for one audit entry: syslog header plus the shared anchor
/// text.
pub(super) fn message(seq: u64, hash: &str, chain: &str, action: &str, outcome: &str) -> String {
    format!(
        "<{PRIORITY}>abyssal-warden[{}]: {}",
        std::process::id(),
        crate::common::anchor_text(seq, hash, chain, action, outcome)
    )
}

/// Send one anchor to `socket` (`None`: disabled). Returns false if it
/// could not be delivered.
pub(super) fn send(
    socket: Option<&Path>,
    seq: u64,
    hash: &str,
    chain: &str,
    action: &str,
    outcome: &str,
) -> bool {
    let Some(path) = socket else {
        return true;
    };
    UnixDatagram::unbound()
        .and_then(|s| s.send_to(message(seq, hash, chain, action, outcome).as_bytes(), path))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_hash_is_kept() {
        let hash = "a".repeat(64);
        assert!(
            message(1, &hash, "0123456789abcdef", "x", "ok")
                .contains(&format!("hash={hash} chain=0123456789abcdef "))
        );
    }

    #[test]
    fn message_is_fixed_format_ascii() {
        let m = message(7, "ab12", "cd34", "quarantine", "ok");
        assert!(m.starts_with("<85>abyssal-warden["));
        assert!(m.ends_with("]: audit seq=7 hash=ab12 chain=cd34 action=quarantine outcome=ok"));
        assert!(
            crate::parse_anchor(&m).is_none(),
            "short test hashes are not valid anchors"
        );
        // Hostile input cannot inject newlines or fields.
        let m = message(1, "x\nfake=1", "c", "a b", "ok\r\n<13>spoof");
        assert!(!m.contains('\n') && !m.contains('\r') && !m.contains(" b"));
    }
}
