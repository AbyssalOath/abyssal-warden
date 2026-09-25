use std::path::Path;

use serde::{Deserialize, Serialize};

/// A filesystem path as observed during a scan, in a form that can always be
/// serialised.
///
/// File names on Linux are arbitrary byte sequences and on Windows arbitrary
/// UTF-16 code units; neither is guaranteed to be valid Unicode. An attacker
/// can choose a file name specifically to break report generation, so reports
/// never store a bare `PathBuf`.
///
/// * `text` is always present. It is exact when `raw_hex` is absent and a
///   lossy rendering (invalid sequences replaced by U+FFFD) otherwise.
/// * `raw_hex` is present only when the path is not valid Unicode. It holds
///   the platform-native encoding, hex-encoded: the raw bytes on Unix, or
///   the UTF-16 code units as little-endian byte pairs on Windows.
///
/// `text` is untrusted data. It may contain control characters or
/// bidirectional-override characters; renderers must escape it before
/// displaying it on a terminal or in a UI.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObservedPath {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_hex: Option<String>,
}

impl ObservedPath {
    pub fn from_path(path: &Path) -> Self {
        match path.to_str() {
            Some(s) => Self {
                text: s.to_owned(),
                raw_hex: None,
            },
            None => Self {
                text: path.to_string_lossy().into_owned(),
                raw_hex: native_hex(path),
            },
        }
    }

    /// True when `text` is not an exact representation of the path.
    pub fn is_lossy(&self) -> bool {
        self.raw_hex.is_some()
    }
}

impl From<&Path> for ObservedPath {
    fn from(path: &Path) -> Self {
        Self::from_path(path)
    }
}

#[cfg(unix)]
fn native_hex(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    Some(crate::digest::hex_encode(path.as_os_str().as_bytes()))
}

#[cfg(windows)]
fn native_hex(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    let bytes: Vec<u8> = path
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    Some(crate::digest::hex_encode(&bytes))
}

#[cfg(not(any(unix, windows)))]
fn native_hex(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_path_is_exact() {
        let p = ObservedPath::from_path(Path::new("/tmp/ok/файл.txt"));
        assert_eq!(p.text, "/tmp/ok/файл.txt");
        assert!(!p.is_lossy());
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("raw_hex"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_keeps_raw_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let raw = b"/tmp/bad\xff\xfename";
        let p = ObservedPath::from_path(Path::new(OsStr::from_bytes(raw)));
        assert!(p.is_lossy());
        assert!(p.text.contains('\u{FFFD}'));
        assert_eq!(
            p.raw_hex.as_deref(),
            Some(crate::digest::hex_encode(raw).as_str())
        );
        let json = serde_json::to_string(&p).unwrap();
        let back: ObservedPath = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}
