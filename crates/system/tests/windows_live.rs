//! Read-only run of the Windows checks against the CI machine's own
//! registry and task store. Runs only on Windows.
#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use warden_core::{CancellationToken, CheckStatus, PersistenceMechanism};
use warden_system::{SystemCheckError, SystemCheckOptions, run_checks};

#[test]
fn live_windows_checks_run_and_are_honest() {
    let out = run_checks(&SystemCheckOptions::default(), &CancellationToken::new()).expect("run");
    assert_eq!(out.host.os, "windows");
    let status = |id: &str| out.checks.iter().find(|c| c.id == id).map(|c| c.status);
    for id in [
        "persistence.registry_run",
        "persistence.winlogon",
        "persistence.services",
        "persistence.scheduled_tasks",
        "persistence.startup_folders",
    ] {
        assert!(
            matches!(
                status(id),
                Some(CheckStatus::Completed | CheckStatus::Partial)
            ),
            "{id}: {:?}",
            status(id)
        );
    }
    // Checks that do not exist yet say so.
    assert_eq!(status("persistence.wmi"), Some(CheckStatus::Unsupported));
    // Every Windows installation has automatic services and Winlogon values.
    assert!(
        out.persistence
            .iter()
            .any(|e| e.mechanism == PersistenceMechanism::WindowsService)
    );
    assert!(
        out.persistence
            .iter()
            .any(|e| e.mechanism == PersistenceMechanism::Winlogon)
    );
}

#[test]
fn offline_windows_roots_are_refused() {
    let opts = SystemCheckOptions {
        root: "D:\\mnt\\image".into(),
        ..SystemCheckOptions::default()
    };
    assert!(matches!(
        run_checks(&opts, &CancellationToken::new()),
        Err(SystemCheckError::OfflineWindows)
    ));
}
