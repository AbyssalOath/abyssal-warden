//! Content metadata that arrives from update sources or disk before (or
//! while) its signature is checked: keyrings, public keys, minisign
//! signature text, bundle manifests and update timestamps. Every parser must
//! return an error, never panic, on any input.
#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;
use warden_engine::bundle::Manifest;
use warden_engine::freshness::{Timestamp, verify_timestamp};
use warden_engine::trust::{KeyRole, TrustedKeys};

const KEY: &str = include_str!("../../examples/keys/synthetic-test.pub");

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
    let text = String::from_utf8_lossy(rest);
    match selector % 5 {
        0 => {
            let _ = TrustedKeys::new().add_keyring(rest, "fuzz");
        }
        1 => {
            let _ = TrustedKeys::new().add_key_text(&text, "fuzz");
        }
        2 => {
            if let Ok(ts) = serde_json::from_slice::<Timestamp>(rest) {
                let _ = ts.validate(now);
            }
        }
        3 => {
            if let Ok(m) = serde_json::from_slice::<Manifest>(rest) {
                let _ = m.validate();
            }
        }
        _ => {
            // Split into signed data and signature text at the first NUL.
            let (signed, sig) = match rest.iter().position(|&b| b == 0) {
                Some(i) => (&rest[..i], String::from_utf8_lossy(&rest[i + 1..])),
                None => (rest, text.clone()),
            };
            let mut keys = TrustedKeys::new();
            if keys.add_key_text(KEY, "fuzz").is_ok() {
                let _ = keys.verify_role(signed, &sig, Path::new("f"), now, KeyRole::Content);
                let _ = verify_timestamp(signed, &sig, &keys, now, true);
            }
        }
    }
});
