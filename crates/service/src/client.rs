//! A minimal client for the service endpoint (used by the CLI).
//!
//! On Windows the client connects at *identification* impersonation level
//! (a server can learn who the client is but cannot act as it) and checks
//! that the pipe is owned by SYSTEM, Administrators or the client itself,
//! so a pipe created first by another user is refused.

use std::path::Path;

use warden_ipc::{MAX_REQUEST, MAX_RESPONSE, Op, Reply, Request, Response};

fn exchange<S: std::io::Read + std::io::Write>(stream: &mut S, op: Op) -> Result<Reply, String> {
    let id = u64::from(std::process::id());
    warden_ipc::write_frame(stream, &Request::new(id, op), MAX_REQUEST)
        .map_err(|e| e.to_string())?;
    let resp: Response = warden_ipc::read_frame(stream, MAX_RESPONSE).map_err(|e| e.to_string())?;
    if resp.id != id && resp.id != 0 {
        return Err("the service answered a different request".into());
    }
    Ok(resp.reply)
}

/// Sends one request and returns the reply (errors from the service are
/// returned as `Reply::Error`).
#[cfg(unix)]
pub fn call(socket: &Path, op: Op) -> Result<Reply, String> {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    let mut stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            format!("the service is not running ({}: {e})", socket.display())
        }
        _ => format!("{}: {e}", socket.display()),
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    exchange(&mut stream, op)
}

/// Access a client needs on the pipe: read, write data, read control (for
/// the owner check). Not FILE_APPEND_DATA, which on pipes means "create
/// instance" and is reserved to the service.
#[cfg(windows)]
const PIPE_CLIENT_ACCESS: u32 = 0x0012_008b;
#[cfg(windows)]
const SECURITY_IDENTIFICATION: u32 = 1 << 16;
#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;

#[cfg(windows)]
pub fn call(pipe: &Path, op: Op) -> Result<Reply, String> {
    use std::os::windows::fs::OpenOptionsExt;
    use warden_winsec::sddl;
    let mut attempts = 0;
    let mut file = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .access_mode(PIPE_CLIENT_ACCESS)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(pipe)
        {
            Ok(f) => break f,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!(
                    "the service is not running ({}: {e})",
                    pipe.display()
                ));
            }
            Err(e) => return Err(format!("{}: {e}", pipe.display())),
        }
    };
    let owner = warden_winsec::pipe_owner_sid(&file)
        .map_err(|e| format!("cannot check the pipe's owner: {e}"))?;
    let me = warden_winsec::process_user_sid().map_err(|e| e.to_string())?;
    if ![sddl::SYSTEM, sddl::ADMINISTRATORS, me.as_str()].contains(&owner.as_str()) {
        return Err(format!(
            "{} is owned by {owner}, not by the service; refusing to talk to it",
            pipe.display()
        ));
    }
    exchange(&mut file, op)
}
