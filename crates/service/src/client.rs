//! A minimal client for the service socket (used by the CLI).

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use warden_ipc::{MAX_REQUEST, MAX_RESPONSE, Op, Reply, Request, Response};

/// Sends one request and returns the reply (errors from the service are
/// returned as `Reply::Error`).
pub fn call(socket: &Path, op: Op) -> Result<Reply, String> {
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
    let id = u64::from(std::process::id());
    warden_ipc::write_frame(&mut stream, &Request::new(id, op), MAX_REQUEST)
        .map_err(|e| e.to_string())?;
    let resp: Response =
        warden_ipc::read_frame(&mut stream, MAX_RESPONSE).map_err(|e| e.to_string())?;
    if resp.id != id && resp.id != 0 {
        return Err("the service answered a different request".into());
    }
    Ok(resp.reply)
}
