//! Digest parsing must reject malformed input without panicking, and
//! accepted input must round-trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use warden_core::Sha256Digest;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(d) = s.parse::<Sha256Digest>()
    {
        assert_eq!(d.to_hex(), s.to_ascii_lowercase());
    }
});
