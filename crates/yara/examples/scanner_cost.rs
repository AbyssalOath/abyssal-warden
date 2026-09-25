//! Measures the per-file overhead of creating a YARA-X scanner, which the
//! detector does for every file. `cargo run --release -p warden-yara --example scanner_cost`
#![allow(clippy::unwrap_used, clippy::print_stdout)]

use std::time::Instant;

fn main() {
    let mut src = String::new();
    for i in 0..500 {
        src.push_str(&format!(
            "rule r{i} {{ strings: $a = \"synthetic-pattern-{i:05}\" condition: $a }}\n"
        ));
    }
    let mut c = yara_x::Compiler::new();
    c.add_source(src.as_str()).unwrap();
    let rules = c.build();
    let data = vec![0x41u8; 4096];
    let n = 5_000;

    let t = Instant::now();
    for _ in 0..n {
        let s = yara_x::Scanner::new(&rules);
        std::hint::black_box(&s);
    }
    let create = t.elapsed() / n;

    let mut shared = yara_x::Scanner::new(&rules);
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(shared.scan(&data).unwrap().matching_rules().len());
    }
    let reuse = t.elapsed() / n;

    let t = Instant::now();
    for _ in 0..n {
        let mut s = yara_x::Scanner::new(&rules);
        std::hint::black_box(s.scan(&data).unwrap().matching_rules().len());
    }
    let fresh = t.elapsed() / n;
    println!(
        "500 rules, 4 KiB input: create {create:?}; scan reused {reuse:?}; create+scan {fresh:?}"
    );
}
