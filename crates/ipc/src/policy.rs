//! Who may do what (docs/security/privilege-model.md). Pure functions,
//! checked by the service for every request after peer authentication.

use crate::{ErrorCode, Op, Rejection};

/// An authenticated client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    pub uid: u32,
    /// Root, a configured administrator, or a member of the admin group.
    pub admin: bool,
}

/// Rejects operations the caller may not perform at all. Per-job access
/// is checked separately with [`can_access_job`].
pub fn authorize(caller: Caller, op: &Op) -> Result<(), Rejection> {
    let admin_only = match op {
        Op::Ping {}
        | Op::Status {}
        | Op::Jobs {}
        | Op::Job { .. }
        | Op::Report { .. }
        | Op::Cancel { .. }
        | Op::Schedules {} => false,
        Op::Scan { quarantine, .. } => *quarantine,
        Op::SystemCheck { .. }
        | Op::RunSchedule { .. }
        | Op::QuarantineList {}
        | Op::QuarantineRestore { .. }
        | Op::QuarantineDelete { .. }
        | Op::VerifyAudit {} => true,
    };
    if admin_only && !caller.admin {
        return Err(Rejection::new(
            ErrorCode::Unauthorized,
            "this operation needs an administrator (root, or a member of the configured admin group)",
        ));
    }
    Ok(())
}

/// Whether the caller may see or cancel a job owned by `owner_uid`.
pub fn can_access_job(caller: Caller, owner_uid: u32) -> bool {
    caller.admin || caller.uid == owner_uid
}

/// Whether a scan for this caller runs with the caller's own identity
/// (non-administrators) rather than the privileged scanner account.
pub fn scan_as_caller(caller: Caller) -> bool {
    !caller.admin
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn authorization_matrix() {
        let user = Caller {
            uid: 1000,
            admin: false,
        };
        let admin = Caller {
            uid: 0,
            admin: true,
        };
        let job = Uuid::nil();
        let scan = |quarantine| Op::Scan {
            paths: vec!["/x".into()],
            heuristics: false,
            no_archives: false,
            quarantine,
        };
        let everyone = [
            Op::Ping {},
            Op::Status {},
            Op::Jobs {},
            Op::Job { job },
            Op::Report { job },
            Op::Cancel { job },
            Op::Schedules {},
            scan(false),
        ];
        let admins = [
            scan(true),
            Op::SystemCheck { heuristics: false },
            Op::RunSchedule { name: "d".into() },
            Op::QuarantineList {},
            Op::QuarantineRestore {
                id: "a".into(),
                allow: true,
            },
            Op::QuarantineDelete { id: "a".into() },
            Op::VerifyAudit {},
        ];
        for op in &everyone {
            assert!(authorize(user, op).is_ok(), "{op:?}");
            assert!(authorize(admin, op).is_ok(), "{op:?}");
        }
        for op in &admins {
            assert_eq!(
                authorize(user, op).unwrap_err().code,
                ErrorCode::Unauthorized,
                "{op:?}"
            );
            assert!(authorize(admin, op).is_ok(), "{op:?}");
        }
        assert!(can_access_job(user, 1000));
        assert!(!can_access_job(user, 1001));
        assert!(can_access_job(admin, 1001));
        assert!(scan_as_caller(user));
        assert!(!scan_as_caller(admin));
    }
}
