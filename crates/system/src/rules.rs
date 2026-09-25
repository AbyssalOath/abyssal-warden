//! Catalogue of system-check rules. Each rule has a stable ID, a rationale
//! and known false positives, documented in `docs/detection/system-checks.md`.
//! Heuristic rules never claim `confirmed` confidence.

use time::OffsetDateTime;
use warden_core::{
    Confidence, DetectionSource, Evidence, EvidenceKind, Finding, FindingId, FindingKind,
    FindingTarget, RecommendedAction, RemediationStatus, Severity, ThreatCategory,
};

/// Detector id recorded in findings.
pub const DETECTOR_ID: &str = "system-checks";

#[derive(Debug)]
pub(crate) struct Rule {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) kind: FindingKind,
    pub(crate) severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) evidence: EvidenceKind,
    pub(crate) explanation: &'static str,
}

impl Rule {
    /// A finding for this rule. `summary` states the concrete observation;
    /// it is untrusted text (it may quote file contents).
    pub(crate) fn finding(&self, target: FindingTarget, summary: String) -> Finding {
        Finding {
            id: FindingId::new_random(),
            kind: self.kind,
            name: self.name.to_owned(),
            severity: self.severity,
            confidence: self.confidence,
            category: ThreatCategory::Unknown,
            target,
            source: DetectionSource {
                detector: DETECTOR_ID.to_owned(),
                detector_version: env!("CARGO_PKG_VERSION").to_owned(),
                rule_id: Some(self.id.to_owned()),
                rule_version: Some(1),
                database_name: None,
                database_version: None,
            },
            evidence: vec![Evidence {
                kind: self.evidence,
                summary,
            }],
            explanation: self.explanation.to_owned(),
            recommended_action: if self.kind == FindingKind::Informational {
                RecommendedAction::None
            } else {
                RecommendedAction::Review
            },
            remediation_guidance: None,
            remediation_status: RemediationStatus::NotAttempted,
            remediation_detail: None,
            detected_at: OffsetDateTime::now_utc(),
        }
    }
}

macro_rules! rule {
    ($const:ident, $id:literal, $name:literal, $kind:ident, $sev:ident, $conf:ident, $ev:ident, $expl:literal) => {
        pub(crate) const $const: Rule = Rule {
            id: $id,
            name: $name,
            kind: FindingKind::$kind,
            severity: Severity::$sev,
            confidence: Confidence::$conf,
            evidence: EvidenceKind::$ev,
            explanation: $expl,
        };
    };
}

rule!(
    TEMP_EXEC,
    "AW-SYS-001",
    "Persistence runs a file from a temporary directory",
    Suspicious,
    High,
    Medium,
    SuspiciousLocation,
    "A persistence entry starts a program in /tmp, /var/tmp, /dev/shm or a similar directory. \
     Legitimate software is installed elsewhere; malware often drops payloads in these \
     world-writable locations."
);
rule!(
    DOWNLOAD_EXEC,
    "AW-SYS-002",
    "Persistence downloads and runs code",
    Suspicious,
    High,
    Medium,
    SuspiciousCommand,
    "The command fetches content from the network and pipes it to an interpreter or makes it \
     executable. This is how many droppers and cryptominers re-install themselves; \
     legitimate installers occasionally do it once, rarely on every boot or schedule."
);
rule!(
    REVERSE_SHELL,
    "AW-SYS-003",
    "Persistence opens a reverse shell",
    Suspicious,
    Critical,
    Medium,
    SuspiciousCommand,
    "The command connects a shell to a network socket (/dev/tcp, nc -e, socat exec, \
     interpreter socket code). This gives a remote party interactive control."
);
rule!(
    ENCODED_EXEC,
    "AW-SYS-004",
    "Persistence decodes and runs an encoded payload",
    Suspicious,
    High,
    Medium,
    SuspiciousCommand,
    "The command decodes base64 (or similar) data and executes it, which hides the real \
     command from casual inspection."
);
rule!(
    LD_PRELOAD_ENV,
    "AW-SYS-005",
    "LD_PRELOAD is set by a persistence entry",
    Suspicious,
    High,
    Medium,
    SuspiciousCommand,
    "LD_PRELOAD makes every program started in that context load an extra library first. \
     User-mode rootkits use it to hide files and processes and to intercept credentials."
);
rule!(
    LD_SO_PRELOAD,
    "AW-SYS-006",
    "/etc/ld.so.preload is in use",
    Suspicious,
    High,
    Medium,
    PersistenceEntry,
    "Libraries listed in /etc/ld.so.preload are loaded into every dynamically linked program \
     on the system. It is rarely used legitimately and is a classic user-mode rootkit \
     technique."
);
rule!(
    WRITABLE_EXEC,
    "AW-SYS-007",
    "System persistence runs a file that other users can modify",
    Suspicious,
    High,
    Medium,
    InsecurePermissions,
    "A system-level entry (usually run as root) starts a program that is not owned by root \
     or that group/other users can write, or that sits in a directory they can write. \
     Whoever can change that file can run code as root."
);
rule!(
    WRITABLE_DEFINITION,
    "AW-SYS-008",
    "Persistence definition can be modified by other users",
    Suspicious,
    Medium,
    High,
    InsecurePermissions,
    "The file that defines this persistence entry is writable by group or other users (or, \
     for system entries, not owned by root), so they can change what runs."
);
rule!(
    HIDDEN_EXEC,
    "AW-SYS-009",
    "Persistence runs a hidden file",
    Heuristic,
    Medium,
    Low,
    SuspiciousLocation,
    "The program started lives in a hidden (dot-prefixed) file or directory outside the \
     common tool directories. Malware hides this way; some user tools do too."
);
rule!(
    PAM_NONSTANDARD,
    "AW-SYS-010",
    "PAM loads a module from a non-standard location",
    Suspicious,
    High,
    Medium,
    PersistenceEntry,
    "PAM modules run inside login, sudo and sshd with access to passwords. Modules loaded by \
     absolute path outside the system security directories are a known backdoor technique."
);
rule!(
    MODULE_HIDDEN,
    "AW-SYS-011",
    "Kernel module hidden from one view",
    Suspicious,
    Critical,
    Medium,
    CrossViewMismatch,
    "A loadable kernel module appears in /sys/module but not in /proc/modules, or the \
     reverse. Kernel rootkits unlink themselves from one list; legitimate modules appear in \
     both."
);
rule!(
    KERNEL_FORCED,
    "AW-SYS-012",
    "A kernel module was force-loaded",
    Suspicious,
    Medium,
    Low,
    KernelTaint,
    "The kernel taint flags show a module loaded with version checks bypassed (flag F). \
     Rootkits built for a different kernel are sometimes loaded this way."
);
rule!(
    KERNEL_TAINT_INFO,
    "AW-SYS-018",
    "Kernel tainted by out-of-tree or unsigned modules",
    Informational,
    Info,
    High,
    KernelTaint,
    "Proprietary, out-of-tree or unsigned modules are loaded (common for graphics or \
     virtualisation drivers). Listed for review; not a finding of compromise by itself."
);
rule!(
    HIDDEN_PROCESS,
    "AW-SYS-013",
    "Hidden process",
    Suspicious,
    Critical,
    Medium,
    CrossViewMismatch,
    "A process exists (its /proc entry answers directly) but is missing from the /proc \
     directory listing. Rootkits hide processes this way."
);
rule!(
    DELETED_EXEC,
    "AW-SYS-014",
    "Process runs a deleted executable from a writable location",
    Suspicious,
    High,
    Medium,
    DeletedExecutable,
    "A running program's executable was deleted after start and was located in a temporary, \
     world-writable or home directory. Malware often deletes itself to avoid disk scans."
);
rule!(
    PACKAGE_MODIFIED,
    "AW-SYS-015",
    "System file differs from its installed package",
    Suspicious,
    High,
    Medium,
    PackageVerification,
    "The package manager reports that this file's content no longer matches what the \
     package installed. Trojanised system binaries show up this way; so do prelinked \
     binaries and local modifications. The package database itself can be forged by root."
);
rule!(
    LAUNCHES_DETECTED,
    "AW-SYS-016",
    "Persistence launches detected content",
    Suspicious,
    Critical,
    High,
    DetectedContent,
    "A persistence entry starts a file that the content detectors flagged. See the matching \
     finding in the referenced-file scan for the detection itself."
);
rule!(
    PAM_EXEC,
    "AW-SYS-017",
    "PAM runs an external program",
    Heuristic,
    Low,
    Low,
    PersistenceEntry,
    "pam_exec runs a program during authentication. It has legitimate uses, but the program \
     can see authentication events and sometimes passwords; review it."
);
rule!(
    INJECTED_LIBRARY,
    "AW-SYS-019",
    "Code injected into the scanner process",
    Suspicious,
    Critical,
    Medium,
    CrossViewMismatch,
    "A shared library that this program never asks for is mapped into its own process. \
     User-mode rootkits inject themselves into every program this way (ld.so.preload, \
     LD_PRELOAD, LD_AUDIT) to hide files and processes, even when they hide the preload \
     configuration itself. Results of this run may be falsified."
);
rule!(
    LOLBIN_EXEC,
    "AW-SYS-020",
    "Persistence uses a system program to run script or remote code",
    Suspicious,
    High,
    Medium,
    SuspiciousCommand,
    "The command uses a built-in Windows program (mshta, rundll32, regsvr32, certutil, \
     bitsadmin, wmic) to fetch or run script code. Attackers use these signed binaries to \
     avoid dropping their own executables."
);
rule!(
    IFEO_DEBUGGER,
    "AW-SYS-021",
    "Program launch redirected by Image File Execution Options",
    Suspicious,
    High,
    Medium,
    PersistenceEntry,
    "A Debugger (or SilentProcessExit monitor) is registered for a program, so Windows starts \
     the registered command instead of, or alongside, that program. Used to hijack \
     accessibility tools and security software."
);
rule!(
    WINLOGON_MODIFIED,
    "AW-SYS-022",
    "Winlogon shell or user-init changed",
    Suspicious,
    High,
    Medium,
    PersistenceEntry,
    "Winlogon's Shell or Userinit value differs from the Windows default, so an extra \
     program runs at every logon."
);
rule!(
    APPINIT_DLLS,
    "AW-SYS-023",
    "AppInit_DLLs are loaded into every GUI process",
    Suspicious,
    High,
    Medium,
    PersistenceEntry,
    "AppInit_DLLs is set and enabled, so the listed libraries load into every process that \
     uses user32.dll. Deprecated, and rarely used legitimately."
);
rule!(
    SYSTEM_USER_WRITABLE,
    "AW-SYS-024",
    "System-level entry runs a program from a user-writable location",
    Heuristic,
    Medium,
    Low,
    SuspiciousLocation,
    "A service or scheduled task that runs with system privileges starts a program under \
     C:\\Users or C:\\ProgramData, where ordinary users can usually create or replace files."
);
rule!(
    HIDDEN_TASK,
    "AW-SYS-025",
    "Scheduled task is marked hidden",
    Heuristic,
    Low,
    Low,
    PersistenceEntry,
    "The task is flagged Hidden, so it does not appear in Task Scheduler by default."
);
rule!(
    SECURE_BOOT_OFF,
    "AW-SYS-027",
    "Secure Boot is disabled",
    Informational,
    Info,
    High,
    PersistenceEntry,
    "The firmware reports that Secure Boot is off, so the boot loader and kernel are not \
     verified before they run. Common on self-built systems; bootkits rely on it."
);
rule!(
    WEAK_CMDLINE,
    "AW-SYS-028",
    "Kernel command line weakens security",
    Suspicious,
    Medium,
    Medium,
    PersistenceEntry,
    "The running kernel was booted with options that disable a security mechanism or \
     replace init (selinux=0, enforcing=0, apparmor=0, init=, module.sig_enforce=0, \
     ima_appraise=off, debug shells). Attackers with boot-loader access set these."
);
rule!(
    BOOT_WRITABLE,
    "AW-SYS-029",
    "Boot files can be modified by other users",
    Suspicious,
    High,
    High,
    InsecurePermissions,
    "A kernel, initramfs, boot-loader file or directory under /boot is not owned by root or \
     is writable by group or other users, who could then run code at the next boot."
);
