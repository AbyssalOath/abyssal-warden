//! Heuristic detectors for Abyssal Warden.
//!
//! Heuristics describe how a file is built or named, not what it is, so
//! every finding is `heuristic` or `suspicious` with `low` or `medium`
//! confidence, recommends review, and never triggers automatic
//! remediation. Each rule, its rationale, known false positives and
//! measured hit rates are in `docs/detection/heuristics.md`.
//!
//! Analysed: file names (all files), PE and ELF structure (parsed with the
//! `object` crate, read-only), scripts (command patterns shared with the
//! system checks), and executables in temporary locations. Content is
//! untrusted; every parser is bounded and fuzzed.

mod elf;
mod names;
pub mod patterns;
mod pe;
mod rules;
mod script;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use warden_core::{
    Detector, DetectorError, DetectorInfo, DetectorRequirements, FileObservation, Finding,
    FindingTarget,
};

pub use rules::DETECTOR_ID;

use patterns::Pattern;
use rules::Rule;

/// Shannon entropy in bits per byte.
pub(crate) fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[usize::from(b)] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Pe,
    Elf,
    MachO,
    Other,
}

fn format(data: &[u8]) -> Format {
    if data.starts_with(b"\x7fELF") {
        Format::Elf
    } else if pe::looks_like_pe(data) {
        Format::Pe
    } else if data.len() >= 4
        && matches!(
            [data[0], data[1], data[2], data[3]],
            [0xFE, 0xED, 0xFA, 0xCE]
                | [0xFE, 0xED, 0xFA, 0xCF]
                | [0xCE, 0xFA, 0xED, 0xFE]
                | [0xCF, 0xFA, 0xED, 0xFE]
        )
    {
        Format::MachO
    } else {
        Format::Other
    }
}

const TEMP_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
const WINDOWS_TEMP: &[&str] = &["\\temp\\", "\\tmp\\", "\\users\\public\\", "$recycle.bin"];

fn in_temp_location(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let lower = text.replace('/', "\\").to_ascii_lowercase();
    TEMP_PREFIXES.iter().any(|p| text.starts_with(p))
        || (text.contains(':') || text.starts_with("\\\\"))
            && WINDOWS_TEMP.iter().any(|t| lower.contains(t))
}

/// Heuristic detector. Stateless and cheap to share.
#[derive(Debug, Default)]
pub struct HeuristicsDetector;

impl HeuristicsDetector {
    pub fn new() -> Self {
        Self
    }
}

struct Out {
    target: FindingTarget,
    findings: Vec<Finding>,
}

impl Out {
    fn add(&mut self, rule: &Rule, evidence: Vec<String>) {
        self.findings
            .push(rule.finding(self.target.clone(), evidence));
    }
}

/// The analysis behind [`HeuristicsDetector`], also used for fuzzing and
/// corpus evaluation. `name` is the file (or archive member) name; `path`
/// is set for files on disk (location rules).
pub fn analyze(
    name: &str,
    path: Option<&Path>,
    data: &[u8],
    target: FindingTarget,
    deadline: Instant,
) -> Result<Vec<Finding>, DetectorError> {
    let mut out = Out {
        target,
        findings: Vec::new(),
    };
    let fmt = format(data);
    let executable = matches!(fmt, Format::Pe | Format::Elf | Format::MachO);

    // Names.
    if executable && names::has_document_extension(name) {
        out.add(
            &rules::DISGUISED_EXECUTABLE,
            vec![format!(
                "{fmt:?} executable named {}",
                patterns::snippet(name)
            )],
        );
    }
    if let Some(why) = names::double_extension(name) {
        out.add(&rules::DOUBLE_EXTENSION, vec![why]);
    }
    let bidi = names::bidi_controls(name);
    if !bidi.is_empty() {
        out.add(
            &rules::BIDI_NAME,
            vec![format!("name contains {}", bidi.join(", "))],
        );
    }
    if executable && path.is_some_and(in_temp_location) {
        out.add(
            &rules::TEMP_EXECUTABLE,
            vec![format!("{fmt:?} executable in a temporary location")],
        );
    }
    if Instant::now() > deadline {
        return Err(DetectorError::new("time limit reached"));
    }

    match fmt {
        Format::Pe => pe_rules(&mut out, data),
        Format::Elf => elf_rules(&mut out, data),
        Format::MachO | Format::Other => {
            if script::is_script(name, data) {
                script_rules(&mut out, name, data);
            }
        }
    }

    let distinct: BTreeSet<&str> = out
        .findings
        .iter()
        .filter_map(|f| f.source.rule_id.as_deref())
        .collect();
    if distinct.len() >= 3 {
        let list = distinct.iter().copied().collect::<Vec<_>>().join(", ");
        out.add(&rules::MULTIPLE, vec![format!("matched {list}")]);
    }
    Ok(out.findings)
}

fn pe_rules(out: &mut Out, data: &[u8]) {
    let facts = match pe::analyze(data) {
        Ok(f) => f,
        Err(e) => {
            out.add(
                &rules::PE_MALFORMED,
                vec![format!("parser: {}", patterns::snippet(&e))],
            );
            return;
        }
    };
    let signed = if facts.signed {
        " (the file has an Authenticode signature; it was not verified)"
    } else {
        ""
    };
    if !facts.rwx_sections.is_empty() {
        out.add(
            &rules::PE_RWX_SECTION,
            vec![format!(
                "writable and executable: {}{signed}",
                facts.rwx_sections.join(", ")
            )],
        );
    }
    if let Some(e) = &facts.entry_outside_code {
        out.add(&rules::PE_ENTRY_OUTSIDE_CODE, vec![e.clone()]);
    }
    if !facts.packers.is_empty() {
        out.add(
            &rules::PE_KNOWN_PACKER,
            vec![format!(
                "section names of {}{signed}",
                facts.packers.join(", ")
            )],
        );
    }
    if pe::looks_packed(&facts) {
        out.add(
            &rules::PE_HIGH_ENTROPY,
            vec![format!(
                "code entropy {:.2} bits/byte, {} imported function(s)",
                facts.code_entropy.unwrap_or_default(),
                facts.imports.len()
            )],
        );
    }
    for (label, funcs) in &facts.injection {
        out.add(
            &rules::PE_INJECTION_IMPORTS,
            vec![format!("{label}: imports {}{signed}", funcs.join(", "))],
        );
    }
    if let Some(at) = facts.embedded_pe_at {
        out.add(
            &rules::PE_EMBEDDED_EXECUTABLE,
            vec![format!(
                "PE image at offset {at:#x}, after the last section"
            )],
        );
    }
}

fn elf_rules(out: &mut Out, data: &[u8]) {
    let Ok(f) = elf::analyze(data) else {
        return; // Relocatable objects and odd variants: nothing to say.
    };
    if f.rwx_segments > 0 {
        out.add(
            &rules::ELF_RWX_SEGMENT,
            vec![format!(
                "{} loadable segment(s) are writable and executable",
                f.rwx_segments
            )],
        );
    }
    if f.exec_stack {
        out.add(
            &rules::ELF_EXEC_STACK,
            vec!["PT_GNU_STACK has the execute flag".into()],
        );
    }
    if f.upx {
        out.add(&rules::ELF_UPX, vec!["UPX! markers present".into()]);
    }
    if f.no_sections {
        out.add(
            &rules::ELF_NO_SECTIONS,
            vec!["e_shnum = 0 and e_shoff = 0".into()],
        );
    }
    if let Some(e) = f.entry_outside_code {
        out.add(&rules::ELF_ENTRY_OUTSIDE_CODE, vec![e]);
    }
    if !f.unsafe_rpath.is_empty() {
        out.add(
            &rules::ELF_UNSAFE_RPATH,
            vec![format!(
                "search path entries: {}",
                patterns::snippet(&f.unsafe_rpath.join(", "))
            )],
        );
    }
    if f.odd_interpreter {
        out.add(
            &rules::ELF_ODD_INTERPRETER,
            vec![format!(
                "interpreter {}",
                patterns::snippet(f.interpreter.as_deref().unwrap_or(""))
            )],
        );
    }
}

fn script_rules(out: &mut Out, name: &str, data: &[u8]) {
    let f = script::analyze(name, data);
    for (kind, line, matched) in &f.matches {
        let rule = match kind {
            Pattern::DownloadExec => &rules::SCRIPT_DOWNLOAD_EXEC,
            Pattern::ReverseShell => &rules::SCRIPT_REVERSE_SHELL,
            Pattern::EncodedExec => &rules::SCRIPT_ENCODED_EXEC,
            Pattern::LolBin => &rules::SCRIPT_LOLBIN,
            Pattern::LoaderInjection => &rules::SCRIPT_LOADER_INJECTION,
        };
        out.add(rule, vec![format!("line {line}: {matched}")]);
    }
    if let Some((line, len)) = f.blob {
        out.add(
            &rules::SCRIPT_ENCODED_BLOB,
            vec![format!(
                "line {line}: base64 run of at least {len} characters"
            )],
        );
    }
}

impl Detector for HeuristicsDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: DETECTOR_ID.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            database: None,
        }
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements { content: true }
    }

    fn inspect_file(&self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Some(data) = file.content else {
            return Ok(Vec::new());
        };
        let (name, path) = match file.member.and_then(|m| m.last()) {
            Some(member) => (
                member
                    .text
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                None,
            ),
            None => (
                file.path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                Some(file.path),
            ),
        };
        analyze(&name, path, data, file.target(), file.deadline)
    }
}

/// Runs [`analyze`] on arbitrary input. For fuzzing only.
#[doc(hidden)]
pub fn fuzz_analyze(data: &[u8]) {
    let far = Instant::now() + std::time::Duration::from_secs(3600);
    let target = FindingTarget::System {
        component: "fuzz".into(),
    };
    for name in ["x.pdf", "a.pdf.exe", "s.sh"] {
        let _ = analyze(name, Some(Path::new("/tmp/x")), data, target.clone(), far);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7; 100]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn temp_locations() {
        assert!(in_temp_location(Path::new("/tmp/x")));
        assert!(in_temp_location(Path::new("/dev/shm/.x")));
        assert!(in_temp_location(Path::new(
            r"C:\Users\a\AppData\Local\Temp\x.exe"
        )));
        assert!(!in_temp_location(Path::new("/usr/bin/ls")));
        assert!(!in_temp_location(Path::new("/home/u/temp/x")));
    }
}
