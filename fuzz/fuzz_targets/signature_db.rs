//! The signature database parser consumes untrusted update data. It must
//! return an error, never panic, on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use warden_engine::signatures::HashSignatureDatabase;

fuzz_target!(|data: &[u8]| {
    if let Ok(db) = HashSignatureDatabase::from_slice(data) {
        // Exercise the index on anything that parsed.
        let _ = db.lookup(&warden_core::Sha256Digest::from_bytes([0; 32]));
    }
});
