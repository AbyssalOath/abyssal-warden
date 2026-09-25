//! Scans arbitrary file content with rules that import the binary-format
//! modules (PE, ELF, Mach-O, .NET, LNK, DEX), so their parsers see untrusted
//! input through the same path the scanner uses.
#![no_main]

use std::cell::RefCell;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use warden_core::{Detector, DetectorWorker, FileMetadata, FileObservation, Sha256Digest};
use warden_yara::{RuleSource, YaraDetector};

const RULES: &str = r#"
import "pe"
import "elf"
import "macho"
import "dotnet"
import "lnk"
import "dex"
import "math"
import "hash"
rule formats {
  condition:
    pe.is_pe or elf.type == elf.ET_EXEC or macho.magic == 0xfeedface or
    dotnet.is_dotnet or lnk.is_lnk or dex.is_dex or
    math.entropy(0, filesize) > 7.9 or
    hash.md5(0, 4) == "00000000000000000000000000000000"
}
rule pattern {
  strings:
    $a = "ABYSSAL" nocase
    $b = { 4D 5A ?? ?? 50 45 }
    $c = /eval\([a-z]{4,32}\)/
  condition:
    any of them
}
"#;

fn detector() -> &'static YaraDetector {
    static D: OnceLock<YaraDetector> = OnceLock::new();
    D.get_or_init(|| {
        YaraDetector::compile(
            &[RuleSource {
                namespace: "fuzz".into(),
                origin: "fuzz".into(),
                text: RULES.into(),
            }],
            None,
        )
        .expect("fuzz rules compile")
    })
}

thread_local! {
    // Reuse one YARA-X scanner across inputs, as the scan engine does per
    // worker thread; this also exercises scanner reuse after arbitrary input.
    static WORKER: RefCell<Box<dyn DetectorWorker + 'static>> =
        RefCell::new(detector().worker());
}

fuzz_target!(|data: &[u8]| {
    let sha = Sha256Digest::from_bytes([0; 32]);
    let meta = FileMetadata {
        size: data.len() as u64,
        modified: None,
        unix_mode: None,
    };
    let obs = FileObservation {
        path: std::path::Path::new("/fuzz/input"),
        sha256: &sha,
        metadata: &meta,
        content: Some(data),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    WORKER.with(|w| {
        let _ = w.borrow_mut().inspect_file(&obs);
    });
});
