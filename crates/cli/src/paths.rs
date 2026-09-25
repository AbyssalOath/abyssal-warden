//! Default per-user and system locations.

use std::path::PathBuf;

/// Rollback-protection state for content bundles:
/// * root (Linux): `/var/lib/abyssal-warden/content-state.json`
/// * other Unix users: `$XDG_STATE_HOME/abyssal-warden/content-state.json`
///   (default `~/.local/state`)
/// * Windows: `%LOCALAPPDATA%\AbyssalWarden\content-state.json`
pub(crate) fn content_state_path() -> Option<PathBuf> {
    const FILE: &str = "content-state.json";
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("AbyssalWarden").join(FILE));
    }
    if running_as_root() {
        return Some(PathBuf::from("/var/lib/abyssal-warden").join(FILE));
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("abyssal-warden").join(FILE))
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[cfg(not(target_os = "linux"))]
fn running_as_root() -> bool {
    false
}
