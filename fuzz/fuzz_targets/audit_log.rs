//! The audit-log verifier reads a file an attacker may have edited. It must
//! reject or accept any input without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = warden_remediation::verify_audit_log(data);
});
