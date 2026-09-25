//! Windows Service Control Manager integration (through the
//! `windows-service` crate, whose dispatcher macro expands to `unsafe`
//! code, which is why this lives in the one crate allowed to contain it).

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

type Body = fn(Arc<AtomicBool>) -> Result<(), String>;

static SERVICE: OnceLock<(&'static str, Body)> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

fn status(state: ServiceState, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let Some(&(name, body)) = SERVICE.get() else {
        return;
    };
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            flag.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(name, handler) else {
        return;
    };
    let _ = handle.set_service_status(status(ServiceState::Running, 0));
    let result = body(stop);
    if let Err(e) = &result {
        let _ = crate::report_event(name, &format!("service stopped with an error: {e}"), true);
    }
    let _ = handle.set_service_status(status(ServiceState::Stopped, u32::from(result.is_err())));
}

/// Hands the process to the Service Control Manager, which calls `body`
/// with a flag that is set when the service must stop.
pub fn run_as_service(name: &'static str, body: Body) -> io::Result<()> {
    let _ = SERVICE.set((name, body));
    service_dispatcher::start(name, ffi_service_main).map_err(io::Error::other)
}

/// Registers the service: automatic start, LocalSystem, the given
/// executable and arguments.
pub fn install(
    name: &str,
    display: &str,
    description: &str,
    exe: &Path,
    args: &[&str],
) -> io::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(io::Error::other)?;
    let info = ServiceInfo {
        name: name.into(),
        display_name: display.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_owned(),
        launch_arguments: args.iter().map(OsString::from).collect(),
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(io::Error::other)?;
    service
        .set_description(description)
        .map_err(io::Error::other)
}

/// Stops (if running) and removes the service.
pub fn uninstall(name: &str) -> io::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(io::Error::other)?;
    let service = manager
        .open_service(
            name,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(io::Error::other)?;
    if service
        .query_status()
        .map_err(io::Error::other)?
        .current_state
        != ServiceState::Stopped
    {
        let _ = service.stop();
    }
    service.delete().map_err(io::Error::other)
}
