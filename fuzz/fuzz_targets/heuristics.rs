//! Untrusted files (PE, ELF, scripts, anything) must never make the
//! heuristic analysers panic or hang.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    warden_heuristics::fuzz_analyze(data);
});
