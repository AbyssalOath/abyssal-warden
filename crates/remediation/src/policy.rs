//! Remediation safety policy.

use std::path::{Path, PathBuf};

use warden_core::{
    Confidence, Finding, FindingKind, FindingTarget, ObservedPath, RecommendedAction, Sha256Digest,
    ThreatCategory,
};

/// System directories whose files are never quarantined unless an operator
/// explicitly overrides it. Removing a file here can break the system, and a
/// detection here is more likely to be a false positive on a legitimate
/// component.
#[cfg(unix)]
const PROTECTED_PREFIXES: &[&str] = &[
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/proc",
    "/sbin",
    "/sys",
    "/usr",
    "/var/lib/dpkg",
    "/var/lib/rpm",
];

/// True if `path` is under a protected system directory. `path` must be
/// absolute and free of `..` and symlinks (the store enforces both), so
/// this lexical check is meaningful.
#[cfg(unix)]
pub fn is_protected_path(path: &Path) -> bool {
    PROTECTED_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Windows: under `%SystemRoot%`, the Program Files directories,
/// `%ProgramData%\Microsoft`, or the boot and recovery folders of the system
/// drive. Compared case-insensitively, with or without the `\\?\` prefix.
#[cfg(windows)]
pub fn is_protected_path(path: &Path) -> bool {
    let env = |k: &str| std::env::var(k).ok();
    let drive = env("SystemDrive").unwrap_or_else(|| "C:".into());
    let mut roots: Vec<String> = [
        env("SystemRoot"),
        env("ProgramFiles"),
        env("ProgramFiles(x86)"),
        env("ProgramW6432"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if let Some(pd) = env("ProgramData") {
        roots.push(format!(r"{pd}\Microsoft"));
    }
    for d in [
        "Boot",
        "Recovery",
        "System Volume Information",
        "$Recycle.Bin",
        "EFI",
    ] {
        roots.push(format!(r"{drive}\{d}"));
    }
    windows_path_under(&path.to_string_lossy(), &roots)
}

#[cfg(not(any(unix, windows)))]
pub fn is_protected_path(_path: &Path) -> bool {
    false
}

#[cfg_attr(not(windows), allow(dead_code))]
/// Case-insensitive, component-wise "is `path` under one of `roots`" for
/// Windows paths (`\\?\` prefixes and `/` separators tolerated).
pub(crate) fn windows_path_under(path: &str, roots: &[String]) -> bool {
    let norm = |s: &str| -> String {
        let s = s.replace('/', "\\");
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_ascii_lowercase();
        s.trim_end_matches('\\').to_owned()
    };
    let p = norm(path);
    roots
        .iter()
        .map(|r| norm(r))
        .filter(|r| !r.is_empty())
        .any(|r| p == r || p.starts_with(&format!("{r}\\")))
}

/// The file and expected hash to quarantine automatically for `finding`, or
/// why it is not eligible.
///
/// Only **confirmed malware matches** qualify: `kind = known_indicator`,
/// `confidence = confirmed`, `category = malware`, recommended action
/// `quarantine`, and a file target with a hash. Heuristic, suspicious,
/// pattern-based (YARA) and test-indicator findings never do.
pub fn auto_quarantine_target(finding: &Finding) -> Result<(PathBuf, Sha256Digest), String> {
    if finding.kind != FindingKind::KnownIndicator || finding.confidence != Confidence::Confirmed {
        return Err("only confirmed known-indicator matches are remediated automatically".into());
    }
    if finding.category != ThreatCategory::Malware {
        return Err("only findings categorised as malware are remediated automatically".into());
    }
    if finding.recommended_action != RecommendedAction::Quarantine {
        return Err("the detection does not recommend quarantine".into());
    }
    let (path, sha256) = match &finding.target {
        FindingTarget::File {
            path,
            sha256: Some(sha256),
            ..
        } => (path, sha256),
        // Quarantining a whole archive (possibly a user's document or
        // backup) because one member matched is a decision for a person.
        FindingTarget::ArchiveMember { .. } => {
            return Err(
                "the detection is inside an archive; review it and quarantine the archive \
                 manually if appropriate"
                    .into(),
            );
        }
        _ => return Err("the finding does not identify a file by hash".into()),
    };
    let path = native_path(path).ok_or("the file path could not be reconstructed")?;
    if is_protected_path(&path) {
        return Err("the file is under a protected system directory".into());
    }
    Ok((path, *sha256))
}

/// Reconstruct the exact native path from an [`ObservedPath`].
pub(crate) fn native_path(p: &ObservedPath) -> Option<PathBuf> {
    match &p.raw_hex {
        None => Some(PathBuf::from(&p.text)),
        #[cfg(unix)]
        Some(h) => {
            use std::os::unix::ffi::OsStringExt;
            let bytes = crate::record::unhex(h)?;
            Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
        }
        // Windows: UTF-16LE code units (the engine's encoding).
        #[cfg(windows)]
        Some(h) => {
            use std::os::windows::ffi::OsStringExt;
            let bytes = crate::record::unhex(h)?;
            if bytes.len() % 2 != 0 {
                return None;
            }
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            Some(PathBuf::from(std::ffi::OsString::from_wide(&units)))
        }
        #[cfg(not(any(unix, windows)))]
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use warden_core::{DetectionSource, FindingId, RemediationStatus, Severity};

    fn finding(kind: FindingKind, conf: Confidence, cat: ThreatCategory, path: &str) -> Finding {
        Finding {
            id: FindingId::new_random(),
            kind,
            name: "x".into(),
            severity: Severity::High,
            confidence: conf,
            category: cat,
            target: FindingTarget::File {
                path: ObservedPath::from_path(Path::new(path)),
                sha256: Some(Sha256Digest::from_bytes([1; 32])),
                metadata: None,
            },
            source: DetectionSource {
                detector: "d".into(),
                detector_version: "0".into(),
                rule_id: None,
                rule_version: None,
                database_name: None,
                database_version: None,
            },
            evidence: vec![],
            explanation: String::new(),
            recommended_action: RecommendedAction::Quarantine,
            remediation_guidance: None,
            remediation_status: RemediationStatus::NotAttempted,
            remediation_detail: None,
            detected_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn windows_protected_paths() {
        let roots = vec![r"C:\Windows".to_owned(), r"C:\Program Files".to_owned()];
        assert!(windows_path_under(r"C:\Windows\System32\x.dll", &roots));
        assert!(windows_path_under(r"\\?\c:\windows\x", &roots));
        assert!(windows_path_under("C:/Program Files/App/a.exe", &roots));
        assert!(windows_path_under(r"C:\Windows", &roots));
        assert!(!windows_path_under(r"C:\WindowsApps\x", &roots));
        assert!(!windows_path_under(r"C:\Users\a\x.exe", &roots));
        assert!(!windows_path_under(r"C:\Users\a\x.exe", &[String::new()]));
    }

    #[test]
    fn only_confirmed_malware_outside_system_dirs_is_eligible() {
        use Confidence::*;
        use FindingKind::*;
        use ThreatCategory::*;
        let ok = finding(KnownIndicator, Confirmed, Malware, "/home/u/evil");
        assert_eq!(
            auto_quarantine_target(&ok).unwrap().0,
            PathBuf::from("/home/u/evil")
        );

        for f in [
            finding(KnownIndicator, High, Malware, "/home/u/evil"),
            finding(Heuristic, Confirmed, Malware, "/home/u/evil"),
            finding(Suspicious, Medium, Malware, "/home/u/evil"),
            finding(KnownIndicator, Confirmed, TestIndicator, "/home/u/evil"),
            finding(
                KnownIndicator,
                Confirmed,
                PotentiallyUnwanted,
                "/home/u/evil",
            ),
        ] {
            assert!(auto_quarantine_target(&f).is_err(), "{f:?}");
        }
        let mut review = ok.clone();
        review.recommended_action = RecommendedAction::Review;
        assert!(auto_quarantine_target(&review).is_err());

        let mut in_archive = ok.clone();
        in_archive.target = FindingTarget::ArchiveMember {
            archive: ObservedPath::from_path(Path::new("/home/u/a.zip")),
            member: vec![ObservedPath::from_path(Path::new("evil.exe"))],
            sha256: Some(Sha256Digest::from_bytes([1; 32])),
            size: 1,
        };
        let why = auto_quarantine_target(&in_archive).unwrap_err();
        assert!(why.contains("inside an archive"), "{why}");
    }

    // Protected prefixes are defined for Unix only; the quarantine store is
    // not supported on other platforms.
    #[cfg(unix)]
    #[test]
    fn confirmed_malware_in_system_dirs_is_not_eligible() {
        use Confidence::*;
        use FindingKind::*;
        use ThreatCategory::*;
        for path in ["/usr/bin/ls", "/etc/passwd"] {
            let f = finding(KnownIndicator, Confirmed, Malware, path);
            assert!(auto_quarantine_target(&f).is_err(), "{path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn protected_prefixes_are_component_wise() {
        assert!(is_protected_path(Path::new("/usr/lib/x")));
        assert!(is_protected_path(Path::new("/etc")));
        assert!(!is_protected_path(Path::new("/usrlocal/x")));
        assert!(!is_protected_path(Path::new("/home/u/etc/x")));
    }

    #[cfg(unix)]
    #[test]
    fn native_path_round_trips_non_utf8() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let raw = Path::new(OsStr::from_bytes(b"/tmp/a\xffb"));
        let observed = ObservedPath::from_path(raw);
        assert_eq!(native_path(&observed).unwrap(), raw);
    }
}
