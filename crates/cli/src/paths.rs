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

/// Where `abyssal-warden update` installs bundles (one subdirectory each):
/// * root (Linux): `/var/lib/abyssal-warden/content`
/// * other Unix users: `$XDG_DATA_HOME/abyssal-warden/content` (default
///   `~/.local/share`)
/// * Windows: `%ProgramData%\AbyssalWarden\Content` when elevated, else
///   `%LOCALAPPDATA%\AbyssalWarden\Content`
#[cfg(windows)]
pub(crate) fn content_dir_path() -> Option<PathBuf> {
    let admin = warden_winsec::process_is_admin().unwrap_or(false);
    let base = std::env::var_os(if admin { "ProgramData" } else { "LOCALAPPDATA" })?;
    Some(PathBuf::from(base).join("AbyssalWarden").join("Content"))
}

/// See the Windows variant above for the locations.
#[cfg(not(windows))]
pub(crate) fn content_dir_path() -> Option<PathBuf> {
    if running_as_root() {
        return Some(PathBuf::from("/var/lib/abyssal-warden/content"));
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
    Some(base.join("abyssal-warden").join("content"))
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[cfg(not(target_os = "linux"))]
fn running_as_root() -> bool {
    false
}
