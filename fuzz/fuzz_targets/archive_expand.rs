//! ZIP parsing and decompression of untrusted archives must never panic,
//! hang, or exceed the archive limits.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = warden_engine::fuzz_expand_archive(data);
});
