//! Any local user can send the service a request: decoding, validation
//! and authorisation must never panic, whatever the bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use warden_ipc::policy::{Caller, authorize};

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = warden_ipc::decode::<warden_ipc::Request>(data) {
        let _ = req.validate();
        for admin in [false, true] {
            let _ = authorize(Caller { uid: 1000, admin }, &req.op);
        }
    }
    let _ = warden_ipc::decode::<warden_ipc::Response>(data);
    let mut framed = data;
    let _ = warden_ipc::read_frame::<warden_ipc::Request>(&mut framed, warden_ipc::MAX_REQUEST);
});
