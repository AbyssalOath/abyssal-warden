//! Configuration files from an inspected (possibly hostile) system image
//! must never make the parsers or command patterns panic or hang.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    warden_system::fuzz_parsers(&String::from_utf8_lossy(data));
});
