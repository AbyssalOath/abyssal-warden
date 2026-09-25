//! Catalogue of file heuristics. Each rule has a stable ID, a rationale and
//! documented false positives (`docs/detection/heuristics.md`). No rule
//! claims `confirmed` confidence or recommends quarantine.

use warden_core::{
    Confidence, DetectionSource, Evidence, EvidenceKind, Finding, FindingId, FindingKind,
    FindingTarget, RecommendedAction, RemediationStatus, Severity, ThreatCategory,
};

/// Detector id recorded in findings and reports.
pub const DETECTOR_ID: &str = "heuristics";

#[derive(Debug)]
pub(crate) struct Rule {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) kind: FindingKind,
    pub(crate) severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) explanation: &'static str,
}

impl Rule {
    pub(crate) fn finding(&self, target: FindingTarget, evidence: Vec<String>) -> Finding {
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
            evidence: evidence
                .into_iter()
                .map(|summary| Evidence {
                    kind: EvidenceKind::Heuristic,
                    summary,
                })
                .collect(),
            explanation: self.explanation.to_owned(),
            recommended_action: RecommendedAction::Review,
            remediation_guidance: None,
            remediation_status: RemediationStatus::NotAttempted,
            remediation_detail: None,
            detected_at: time::OffsetDateTime::now_utc(),
        }
    }
}

macro_rules! rule {
    ($const:ident, $id:literal, $name:literal, $kind:ident, $sev:ident, $conf:ident, $expl:literal) => {
        pub(crate) const $const: Rule = Rule {
            id: $id,
            name: $name,
            kind: FindingKind::$kind,
            severity: Severity::$sev,
            confidence: Confidence::$conf,
            explanation: $expl,
        };
    };
}

// File names.
rule!(
    DISGUISED_EXECUTABLE,
    "AW-HEU-001",
    "Executable disguised as a document or media file",
    Suspicious,
    High,
    Medium,
    "The file is a program (its content is a PE, ELF or Mach-O executable) but its extension \
     claims a document, image, archive or media type. Opening it may run it."
);
rule!(
    DOUBLE_EXTENSION,
    "AW-HEU-002",
    "Double extension hides an executable type",
    Suspicious,
    Medium,
    Medium,
    "The name ends in a document-like extension followed by an executable one (for example \
     invoice.pdf.exe), or pads the name with spaces before the real extension, a common way \
     to make a program look like a document when extensions are hidden."
);
rule!(
    BIDI_NAME,
    "AW-HEU-003",
    "File name uses bidirectional control characters",
    Suspicious,
    High,
    Medium,
    "The name contains Unicode bidirectional controls (such as RIGHT-TO-LEFT OVERRIDE) that \
     make it display differently from what it is, e.g. showing 'exe.pdf' as 'fdp.exe'."
);
// PE.
rule!(
    PE_RWX_SECTION,
    "AW-HEU-010",
    "Program section is both writable and executable",
    Heuristic,
    Medium,
    Low,
    "A PE section is mapped writable and executable, which lets code modify itself. \
     Normal compilers do not produce this; packers, protectors and shellcode loaders do."
);
rule!(
    PE_ENTRY_OUTSIDE_CODE,
    "AW-HEU-011",
    "Program starts outside its code",
    Heuristic,
    Medium,
    Low,
    "The entry point is not inside an executable section. Packers and file infectors move \
     the entry point; normal programs start in their code section."
);
rule!(
    PE_KNOWN_PACKER,
    "AW-HEU-012",
    "Program is packed with a known packer",
    Heuristic,
    Low,
    Medium,
    "Section names show a known packer or protector (UPX, ASPack, MPRESS, Themida, VMProtect, \
     ...). Packing hides the real code from inspection; legitimate software uses it too."
);
rule!(
    PE_HIGH_ENTROPY,
    "AW-HEU-013",
    "Program code looks compressed or encrypted",
    Heuristic,
    Low,
    Low,
    "The executable sections have very high entropy and the program imports very few \
     functions, typical of packed or encrypted code that unpacks itself at run time."
);
rule!(
    PE_INJECTION_IMPORTS,
    "AW-HEU-014",
    "Program imports process-injection functions",
    Heuristic,
    Medium,
    Low,
    "The import table contains a complete set of functions used to write code into another \
     process and run it (or to hollow a process). Debuggers and some security tools \
     legitimately import these."
);
rule!(
    PE_EMBEDDED_EXECUTABLE,
    "AW-HEU-015",
    "Program carries another program after its end",
    Heuristic,
    Medium,
    Low,
    "Data appended after the last section (outside any signature) contains a complete PE \
     executable. Droppers carry their payload this way; some installers do too."
);
rule!(
    PE_MALFORMED,
    "AW-HEU-016",
    "Malformed program headers",
    Heuristic,
    Low,
    Low,
    "The file has PE signatures but its headers cannot be parsed consistently. Malware \
     sometimes corrupts headers to break analysis tools; truncated downloads look the same."
);
// ELF.
rule!(
    ELF_RWX_SEGMENT,
    "AW-HEU-020",
    "ELF segment is both writable and executable",
    Heuristic,
    Medium,
    Low,
    "A loadable segment is writable and executable. Modern toolchains never produce this; \
     packers, self-modifying code and hand-built payloads do."
);
rule!(
    ELF_EXEC_STACK,
    "AW-HEU-021",
    "ELF requests an executable stack",
    Heuristic,
    Low,
    Low,
    "The program asks for an executable stack, which makes memory-corruption exploits \
     easier and is used by some shellcode loaders. Old or hand-written assembly also does."
);
rule!(
    ELF_UPX,
    "AW-HEU-022",
    "ELF is packed with UPX",
    Heuristic,
    Medium,
    Medium,
    "The file carries UPX packer markers. On Linux, UPX packing is rare for legitimate \
     software and common for botnet and cryptominer binaries."
);
rule!(
    ELF_NO_SECTIONS,
    "AW-HEU-023",
    "ELF executable has no section headers",
    Heuristic,
    Low,
    Low,
    "The program has no section headers at all, which breaks common analysis tools. \
     Normal stripped binaries keep them; packers and hand-built payloads remove them."
);
rule!(
    ELF_UNSAFE_RPATH,
    "AW-HEU-024",
    "ELF loads libraries from an unsafe search path",
    Suspicious,
    Medium,
    Medium,
    "The library search path (RPATH/RUNPATH) contains a temporary directory, the current \
     directory or a relative path, so whoever controls that location controls the code the \
     program loads."
);
rule!(
    ELF_ENTRY_OUTSIDE_CODE,
    "AW-HEU-025",
    "ELF starts outside its executable segments",
    Heuristic,
    Medium,
    Low,
    "The entry point is not inside an executable segment."
);
rule!(
    ELF_ODD_INTERPRETER,
    "AW-HEU-026",
    "ELF uses an unusual program interpreter",
    Suspicious,
    Medium,
    Medium,
    "The dynamic loader (PT_INTERP) is not a standard ld.so, or lives in a temporary \
     directory. Whoever provides the interpreter runs code before the program itself."
);
// Scripts.
rule!(
    SCRIPT_DOWNLOAD_EXEC,
    "AW-HEU-030",
    "Script downloads and runs code",
    Heuristic,
    Medium,
    Low,
    "The script fetches content from the network and runs it (curl | sh, PowerShell \
     download cradles, certutil, bitsadmin). Installers do this; so do droppers."
);
rule!(
    SCRIPT_REVERSE_SHELL,
    "AW-HEU-031",
    "Script opens a reverse shell",
    Suspicious,
    High,
    Medium,
    "The script connects a shell to a network socket, giving a remote party control."
);
rule!(
    SCRIPT_ENCODED_EXEC,
    "AW-HEU-032",
    "Script decodes and runs a hidden payload",
    Suspicious,
    Medium,
    Low,
    "The script decodes base64 (or similar) data and executes it, hiding what it runs."
);
rule!(
    SCRIPT_LOLBIN,
    "AW-HEU-033",
    "Script uses a system program to run remote or script code",
    Suspicious,
    Medium,
    Low,
    "The script uses mshta, rundll32, regsvr32, wmic or wscript to fetch or run code."
);
rule!(
    SCRIPT_LOADER_INJECTION,
    "AW-HEU-034",
    "Script sets LD_PRELOAD or LD_AUDIT",
    Heuristic,
    Low,
    Low,
    "The script injects a library into the programs it starts. Test harnesses and allocator \
     wrappers do this legitimately."
);
rule!(
    SCRIPT_ENCODED_BLOB,
    "AW-HEU-035",
    "Shell or batch script embeds a large encoded blob",
    Heuristic,
    Low,
    Low,
    "A shell, PowerShell, batch or VBScript file contains a long run of base64 text, often \
     an embedded payload. Self-extracting installers do this too."
);
// Location.
rule!(
    TEMP_EXECUTABLE,
    "AW-HEU-040",
    "Executable in a temporary or shared-memory directory",
    Heuristic,
    Low,
    Low,
    "A program file sits in /tmp, /var/tmp, /dev/shm or a Windows temporary or public \
     folder, where droppers stage payloads. Build and installer output also lands there."
);
// Combination.
rule!(
    MULTIPLE,
    "AW-HEU-099",
    "Several independent heuristics matched",
    Suspicious,
    Medium,
    Medium,
    "Three or more unrelated heuristics matched this file. Each alone is weak evidence; \
     together they make benign explanations less likely."
);
