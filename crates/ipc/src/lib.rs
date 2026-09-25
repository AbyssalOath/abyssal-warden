//! The Abyssal Warden service protocol.
//!
//! * **Framing**: a 4-byte big-endian length, then that many bytes of UTF-8
//!   JSON. Requests are at most [`MAX_REQUEST`] bytes and responses at most
//!   [`MAX_RESPONSE`]; the length is checked before anything is allocated.
//! * **Messages**: [`Request`] and [`Response`], versioned by
//!   [`PROTOCOL_VERSION`]. Unknown operations and unknown fields are
//!   rejected.
//! * **Validation** ([`Request::validate`]) and **authorisation**
//!   ([`policy`]) are pure functions, so the service and the tests share
//!   them.
//!
//! Transport and peer authentication (Unix socket, `SO_PEERCRED`) are the
//! service's job; see docs/security/privilege-model.md.

pub mod policy;

use std::io::{self, Read, Write};
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Protocol version; a server rejects requests for any other version.
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest request frame.
pub const MAX_REQUEST: usize = 64 * 1024;
/// Largest response frame (reports can be large).
pub const MAX_RESPONSE: usize = 64 << 20;
/// Most paths in one scan request.
pub const MAX_PATHS: usize = 64;
/// Longest path in a request.
pub const MAX_PATH_BYTES: usize = 4096;

/// Default socket path on Linux.
pub const DEFAULT_SOCKET: &str = "/run/abyssal-warden/wardend.sock";
/// Default pipe name on Windows.
pub const DEFAULT_PIPE: &str = r"\\.\pipe\AbyssalWarden";

/// The default endpoint for this platform.
pub fn default_endpoint() -> &'static str {
    if cfg!(windows) {
        DEFAULT_PIPE
    } else {
        DEFAULT_SOCKET
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    /// Chosen by the client; echoed in the response.
    pub id: u64,
    pub op: Op,
}

/// What a client asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
// Every variant is a struct variant, even when empty: serde applies
// `deny_unknown_fields` only to those.
pub enum Op {
    Ping {},
    Status {},
    /// Scan paths. For non-administrators the scan runs with the caller's
    /// own identity, so it reads only what they can read.
    Scan {
        paths: Vec<String>,
        #[serde(default)]
        heuristics: bool,
        #[serde(default)]
        no_archives: bool,
        /// Quarantine confirmed malware afterwards (administrators only).
        #[serde(default)]
        quarantine: bool,
    },
    /// Run `system-check` with the service's privileges (administrators).
    SystemCheck {
        #[serde(default)]
        heuristics: bool,
    },
    /// Jobs the caller may see (all jobs for administrators).
    Jobs {},
    Job {
        job: Uuid,
    },
    Report {
        job: Uuid,
    },
    Cancel {
        job: Uuid,
    },
    Schedules {},
    RunSchedule {
        name: String,
    },
    QuarantineList {},
    QuarantineRestore {
        id: String,
        /// Allow-list the restored content (the default for restores).
        #[serde(default = "yes")]
        allow: bool,
    },
    QuarantineDelete {
        id: String,
    },
    /// Verify the quarantine audit chain against the system log's anchors.
    VerifyAudit {},
}

fn yes() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    VersionMismatch,
    Unauthorized,
    NotFound,
    Busy,
    Unsupported,
    Internal,
}

/// A request that failed validation or authorisation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Rejection {
    pub code: ErrorCode,
    pub message: String,
}

impl Rejection {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Request {
    pub fn new(id: u64, op: Op) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            id,
            op,
        }
    }

    /// Checks everything that does not depend on who is asking.
    pub fn validate(&self) -> Result<(), Rejection> {
        if self.version != PROTOCOL_VERSION {
            return Err(Rejection::new(
                ErrorCode::VersionMismatch,
                format!(
                    "protocol version {} is not supported (server speaks {PROTOCOL_VERSION})",
                    self.version
                ),
            ));
        }
        let bad = |m: String| Err(Rejection::new(ErrorCode::BadRequest, m));
        match &self.op {
            Op::Scan { paths, .. } => {
                if paths.is_empty() || paths.len() > MAX_PATHS {
                    return bad(format!("between 1 and {MAX_PATHS} paths are required"));
                }
                for p in paths {
                    if p.len() > MAX_PATH_BYTES || p.contains('\0') {
                        return bad("path too long or contains NUL".into());
                    }
                    if !Path::new(p).is_absolute() {
                        return bad(format!("path {p:?} is not absolute"));
                    }
                }
            }
            Op::RunSchedule { name } if !valid_name(name) => {
                return bad("invalid schedule name".into());
            }
            Op::QuarantineRestore { id, .. } | Op::QuarantineDelete { id }
                if id.is_empty()
                    || id.len() > 64
                    || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') =>
            {
                return bad("invalid quarantine id".into());
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub id: u64,
    pub reply: Reply,
}

impl Response {
    pub fn new(id: u64, reply: Reply) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            id,
            reply,
        }
    }

    pub fn error(id: u64, r: Rejection) -> Self {
        Self::new(
            id,
            Reply::Error {
                code: r.code,
                message: r.message,
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reply {
    Pong {
        server_version: String,
    },
    Status(Box<ServiceStatus>),
    JobStarted {
        job: Uuid,
    },
    Jobs {
        jobs: Vec<JobSummary>,
    },
    Job(Box<JobSummary>),
    /// The stored report (a `ScanReport` or `SystemReport` in JSON,
    /// according to the job's kind).
    Report {
        job: Uuid,
        report: serde_json::Value,
    },
    Schedules {
        schedules: Vec<ScheduleInfo>,
    },
    Quarantine {
        items: Vec<QuarantineItem>,
    },
    Done {
        message: String,
    },
    Audit(Box<AuditStatus>),
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Scan,
    SystemCheck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl JobState {
    pub fn finished(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSummary {
    pub id: Uuid,
    pub kind: JobKind,
    pub state: JobState,
    /// Who asked: a uid (Unix) or SID (Windows); the service's own
    /// identity for scheduled jobs.
    pub owner: String,
    /// Schedule name, for scheduled jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    pub paths: Vec<String>,
    pub heuristics: bool,
    pub quarantine: bool,
    /// The job ran with the owner's identity, not the scanner account's.
    pub as_owner: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub started_at: Option<OffsetDateTime>,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub finished_at: Option<OffsetDateTime>,
    /// Exit status of the scanner process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub server_version: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    pub running_as_root: bool,
    pub jobs_running: u32,
    pub jobs_queued: u32,
    pub schedules: u32,
    /// The caller's uid (Unix) or SID (Windows).
    pub caller: String,
    pub caller_is_admin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_audit: Option<AuditStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleInfo {
    pub name: String,
    pub kind: JobKind,
    pub paths: Vec<String>,
    pub every_hours: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_utc: Option<String>,
    pub heuristics: bool,
    pub quarantine: bool,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_run: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub next_run: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub state: String,
    pub original_path: String,
    pub sha256: String,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Result of comparing the quarantine audit chain with the system log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditStatus {
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
    /// The local hash chain verified.
    pub chain_ok: bool,
    pub entries: u64,
    /// Anchors were read from the system journal.
    pub journal_checked: bool,
    pub matched: u64,
    pub mismatched: Vec<u64>,
    pub missing_locally: Vec<u64>,
    pub unanchored: u64,
    pub other_chains: u64,
    /// Everything consistent (chain valid, no mismatched or missing anchors).
    pub consistent: bool,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("connection closed")]
    Closed,
    #[error("message of {0} bytes exceeds the {1}-byte limit")]
    TooLarge(usize, usize),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Writes one frame.
pub fn write_frame<T: Serialize>(
    w: &mut impl Write,
    msg: &T,
    max: usize,
) -> Result<(), FrameError> {
    let body = serde_json::to_vec(msg).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if body.len() > max {
        return Err(FrameError::TooLarge(body.len(), max));
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(body.len(), max))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Reads one frame of at most `max` bytes.
pub fn read_frame<T: DeserializeOwned>(r: &mut impl Read, max: usize) -> Result<T, FrameError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(FrameError::TooLarge(len, max));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    decode(&body)
}

/// Decodes one frame body. Exposed for fuzzing.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(body).map_err(|e| FrameError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(req: &Request) -> Request {
        let mut buf = Vec::new();
        write_frame(&mut buf, req, MAX_REQUEST).expect("write");
        read_frame(&mut buf.as_slice(), MAX_REQUEST).expect("read")
    }

    #[test]
    fn frames_round_trip() {
        let req = Request::new(
            7,
            Op::Scan {
                paths: vec!["/home/a".into()],
                heuristics: true,
                no_archives: false,
                quarantine: false,
            },
        );
        assert_eq!(roundtrip(&req), req);
        let restore: Request =
            decode(br#"{"version":1,"id":1,"op":{"type":"quarantine_restore","id":"ab-12"}}"#)
                .expect("decode");
        assert_eq!(
            restore.op,
            Op::QuarantineRestore {
                id: "ab-12".into(),
                allow: true
            }
        );
    }

    #[test]
    fn limits_are_checked_before_allocation() {
        let mut huge = (u32::MAX).to_be_bytes().to_vec();
        huge.extend_from_slice(b"{}");
        assert!(matches!(
            read_frame::<Request>(&mut huge.as_slice(), MAX_REQUEST),
            Err(FrameError::TooLarge(..))
        ));
        assert!(matches!(
            read_frame::<Request>(&mut [0u8; 2].as_slice(), MAX_REQUEST),
            Err(FrameError::Closed)
        ));
        let mut short = 10u32.to_be_bytes().to_vec();
        short.extend_from_slice(b"{}");
        assert!(read_frame::<Request>(&mut short.as_slice(), MAX_REQUEST).is_err());
    }

    #[test]
    fn unknown_operations_and_fields_are_rejected() {
        for bad in [
            &br#"{"version":1,"id":1,"op":{"type":"format_disk"}}"#[..],
            br#"{"version":1,"id":1,"op":{"type":"ping","extra":1}}"#,
            br#"{"version":1,"id":1,"op":{"type":"scan","paths":["/"],"as_uid":0}}"#,
            br#"{"version":1,"id":1,"op":{"type":"ping"},"admin":true}"#,
            br#"{"version":1,"op":{"type":"ping"}}"#,
            br#"not json"#,
        ] {
            assert!(
                decode::<Request>(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn validation() {
        let scan = |paths: Vec<&str>| {
            Request::new(
                1,
                Op::Scan {
                    paths: paths.into_iter().map(String::from).collect(),
                    heuristics: false,
                    no_archives: false,
                    quarantine: false,
                },
            )
        };
        assert!(scan(vec!["/home"]).validate().is_ok());
        assert_eq!(
            scan(vec![]).validate().unwrap_err().code,
            ErrorCode::BadRequest
        );
        assert!(scan(vec!["relative"]).validate().is_err());
        assert!(scan(vec!["/a\0b"]).validate().is_err());
        assert!(scan(vec!["/x"; MAX_PATHS + 1]).validate().is_err());
        let mut old = Request::new(1, Op::Ping {});
        old.version = 99;
        assert_eq!(old.validate().unwrap_err().code, ErrorCode::VersionMismatch);
        assert!(
            Request::new(
                1,
                Op::RunSchedule {
                    name: "../x".into()
                }
            )
            .validate()
            .is_err()
        );
        assert!(
            Request::new(
                1,
                Op::QuarantineDelete {
                    id: "../../etc".into()
                }
            )
            .validate()
            .is_err()
        );
    }
}
