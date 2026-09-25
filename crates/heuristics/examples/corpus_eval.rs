//! Measures how often each heuristic matches on a corpus: run it on known
//! clean files to estimate false positives (see docs/detection/heuristics.md).
//!
//! `cargo run --release -p warden-heuristics --example corpus_eval -- DIR...`
//!
//! Reads regular files up to 64 MiB without following links, and prints per
//! rule the number of matching files, the rate per file of the relevant
//! type, and up to five example paths.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use warden_core::{FindingTarget, ObservedPath};

const MAX: u64 = 64 << 20;

fn main() {
    let dirs: Vec<String> = std::env::args().skip(1).collect();
    assert!(!dirs.is_empty(), "usage: corpus_eval DIR...");
    let mut files = 0u64;
    let mut kinds: BTreeMap<&str, u64> = BTreeMap::new();
    let mut hits: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    let started = Instant::now();
    for dir in &dirs {
        for entry in walkdir::WalkDir::new(dir)
            .follow_links(false)
            .same_file_system(true)
        {
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() || entry.metadata().map_or(true, |m| m.len() > MAX) {
                continue;
            }
            let Ok(data) = std::fs::read(entry.path()) else {
                continue;
            };
            files += 1;
            let kind = if data.starts_with(b"\x7fELF") {
                "ELF"
            } else if data.starts_with(b"MZ") {
                "MZ"
            } else if data.starts_with(b"#!") {
                "script"
            } else {
                "other"
            };
            *kinds.entry(kind).or_default() += 1;
            let name = entry.file_name().to_string_lossy().into_owned();
            let target = FindingTarget::File {
                path: ObservedPath::from_path(entry.path()),
                sha256: None,
                metadata: None,
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            let Ok(findings) =
                warden_heuristics::analyze(&name, Some(entry.path()), &data, target, deadline)
            else {
                continue;
            };
            for f in findings {
                let id = format!("{} {}", f.source.rule_id.unwrap_or_default(), f.name);
                let e = hits.entry(id).or_default();
                e.0 += 1;
                if e.1.len() < 5 {
                    e.1.push(entry.path().display().to_string());
                }
            }
        }
    }
    println!(
        "{files} files in {:.1} s: {kinds:?}",
        started.elapsed().as_secs_f64()
    );
    println!("| Rule | Files | Per 10,000 files | Examples |");
    println!("|---|---|---|---|");
    for (rule, (n, examples)) in hits {
        println!(
            "| {rule} | {n} | {:.2} | {} |",
            n as f64 * 10_000.0 / files.max(1) as f64,
            examples.join("<br>")
        );
    }
}
