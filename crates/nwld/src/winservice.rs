//! Running nwld as a Windows service, and installing it as one.
//!
//! `nwld --install-service` registers this executable as the automatic
//! service "NattoWokLimiter" (LocalSystem, started with `--service`) and
//! starts it; `--uninstall-service` stops and removes it. The installer
//! runs both. Under the service manager, logs go to `nwld.log` in the
//! data folder.

use crate::Args;
use anyhow::Context;
use std::ffi::OsString;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "NattoWokLimiter";
const DISPLAY_NAME: &str = "NattoWok Limiter";
const DESCRIPTION: &str = "Per-application network monitor, firewall and bandwidth limiter.";

/// The arguments, for the service's entry point (the dispatcher can't pass them).
static ARGS: OnceLock<Args> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Hands control to the service manager; returns when the service stops.
pub fn run(args: Args) -> anyhow::Result<()> {
    let _ = ARGS.set(args);
    service_dispatcher::start(NAME, ffi_service_main)
        .context("starting as a service (use --service only from the service manager)")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = Mutex::new(Some(stop_tx));
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = stop_tx.lock().unwrap_or_else(|p| p.into_inner()).take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(NAME, handler)?;
    let report = |state, accept, code| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };
    report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0)?;
    let args = ARGS.get().cloned().context("service arguments")?;
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
        .and_then(|rt| {
            rt.block_on(crate::run(args, async {
                let _ = stop_rx.await;
            }))
        });
    if let Err(e) = &result {
        tracing::error!("{e:#}");
    }
    report(ServiceState::Stopped, ServiceControlAccept::empty(), if result.is_ok() { 0 } else { 1 })?;
    result
}

/// Registers and starts the service (replacing an older registration).
pub fn install() -> anyhow::Result<()> {
    let _ = uninstall_quietly();
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the service manager (run as Administrator)")?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["--service".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating the service")?;
    service.set_description(DESCRIPTION)?;
    service.start::<&str>(&[]).context("starting the service")?;
    println!("installed and started the {DISPLAY_NAME} service");
    Ok(())
}

/// Stops and removes the service.
pub fn uninstall() -> anyhow::Result<()> {
    uninstall_quietly()?;
    println!("removed the {DISPLAY_NAME} service");
    Ok(())
}

fn uninstall_quietly() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run as Administrator)")?;
    let service = manager
        .open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
        .context("the service isn't installed")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        while service.query_status()?.current_state != ServiceState::Stopped && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service.delete().context("removing the service")?;
    Ok(())
}
