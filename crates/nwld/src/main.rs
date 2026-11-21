//! `nwld`: the NattoWokLimiter daemon.

mod api;
mod engine;
mod resolver;
mod store;

use anyhow::{bail, Context};
use api::{AppState, Wake};
use clap::Parser;
use engine::Engine;
use nwl_platform::{Enforcer, EnforcerOptions, Monitor, NullEnforcer};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

#[derive(Parser, Debug)]
#[command(version, long_version = nwl_core::LONG_VERSION, about = "NattoWokLimiter daemon: per-app network monitor, firewall and bandwidth limiter")]
struct Args {
    /// Address for the API and web dashboard (loopback only).
    #[arg(long, default_value = "127.0.0.1:7657")]
    listen: SocketAddr,
    /// Where rules, quotas and usage history are stored.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Sampling interval in milliseconds.
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
    /// Number of samples kept for live graphs.
    #[arg(long, default_value_t = 300)]
    history: usize,
    /// Use simulated applications and traffic instead of the real system.
    #[arg(long)]
    demo: bool,
    /// Observe only: never install firewall rules or limits.
    #[arg(long)]
    monitor_only: bool,
    /// Also count and police loopback (localhost) traffic.
    #[arg(long)]
    include_loopback: bool,
    /// Don't look up host names of remote addresses (reverse DNS).
    #[arg(long)]
    no_resolve: bool,
    /// Don't load the eBPF traffic counters (Linux); per-app bytes then
    /// cover TCP only.
    #[arg(long)]
    no_ebpf: bool,
}

/// The monitor, the enforcer, and a warning when enforcement had to be disabled.
type Backends = (Box<dyn Monitor>, Box<dyn Enforcer>, Option<String>);

fn backends(args: &Args) -> anyhow::Result<Backends> {
    if args.demo {
        let (monitor, enforcer) = nwl_platform::sim::simulated();
        return Ok((Box::new(monitor), Box::new(enforcer), None));
    }
    let opts = nwl_platform::MonitorOptions { ebpf: !args.no_ebpf, count_loopback: args.include_loopback };
    let monitor = nwl_platform::native_monitor(opts).context("starting the traffic monitor")?;
    if args.monitor_only {
        return Ok((monitor, Box::new(NullEnforcer), None));
    }
    let opts = EnforcerOptions { include_loopback: args.include_loopback };
    match nwl_platform::native_enforcer(opts) {
        Ok(enforcer) => Ok((monitor, enforcer, None)),
        Err(e) => {
            let warning = format!("enforcement unavailable, running in monitor-only mode: {e}");
            Ok((monitor, Box::new(NullEnforcer), Some(warning)))
        }
    }
}

/// The sampling loop. Runs on its own thread because backends block.
fn run_engine(
    engine: Arc<Mutex<Engine>>,
    mut monitor: Box<dyn Monitor>,
    mut enforcer: Box<dyn Enforcer>,
    updates: broadcast::Sender<Arc<str>>,
    wake: mpsc::Receiver<Wake>,
    interval: Duration,
) {
    let lock = || engine.lock().unwrap_or_else(|p| p.into_inner());
    let apply = |eng: &mut Engine, enforcer: &mut Box<dyn Enforcer>| {
        let result = enforcer.apply(&eng.policy()).map_err(|e| e.to_string());
        if let Err(e) = &result {
            tracing::error!("enforcement failed: {e}");
        }
        eng.record_enforcement(result);
        if let Ok(json) = serde_json::to_string(&eng.overview()) {
            let _ = updates.send(json.into());
        }
    };
    let mut last_save = Instant::now();
    'ticks: loop {
        let started = Instant::now();
        match monitor.snapshot() {
            Ok(snap) => {
                let mut eng = lock();
                eng.ingest(snap, chrono::Local::now());
                apply(&mut eng, &mut enforcer);
                if last_save.elapsed() > Duration::from_secs(30) {
                    if let Err(e) = eng.save() {
                        tracing::error!("saving state: {e:#}");
                    }
                    last_save = Instant::now();
                }
            }
            Err(e) => tracing::warn!("snapshot failed: {e}"),
        }
        let deadline = started + interval;
        loop {
            match wake.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(Wake::Reapply) => apply(&mut lock(), &mut enforcer),
                Ok(Wake::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break 'ticks,
                Err(mpsc::RecvTimeoutError::Timeout) => break,
            }
        }
    }
    if let Err(e) = enforcer.clear() {
        tracing::error!("removing installed rules: {e}");
    }
    if let Err(e) = lock().save() {
        tracing::error!("saving state: {e:#}");
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    if !args.listen.ip().is_loopback() {
        bail!("--listen must be a loopback address: the API has no authentication yet");
    }

    let mut state_dir = args.state_dir.clone().unwrap_or_else(store::default_state_dir);
    if args.demo {
        state_dir = state_dir.join("demo");
    }
    let store = store::Store::open(state_dir.clone())
        .with_context(|| format!("opening state directory {}", state_dir.display()))?;
    let mut engine = Engine::new(store, args.history)?;
    engine.set_count_loopback(args.include_loopback);
    if !args.no_resolve {
        let lookup = if args.demo { nwl_platform::sim::demo_hostname } else { resolver::system_lookup };
        engine.set_resolver(resolver::Resolver::new(4, lookup));
    }

    let (monitor, enforcer, warning) = backends(&args)?;
    engine.status.monitor = monitor.name().to_string();
    engine.status.enforcer = enforcer.name().to_string();
    engine.status.enforcing = !args.monitor_only && warning.is_none();
    for w in monitor.warnings().into_iter().chain(warning) {
        tracing::warn!("{w}");
        engine.add_startup_warning(w);
    }
    tracing::info!(monitor = monitor.name(), enforcer = enforcer.name(), state = %state_dir.display(), "starting");

    let engine = Arc::new(Mutex::new(engine));
    let (updates, _) = broadcast::channel(16);
    let (wake_tx, wake_rx) = mpsc::channel();
    let worker = {
        let (engine, updates) = (engine.clone(), updates.clone());
        let interval = Duration::from_millis(args.interval_ms.max(100));
        std::thread::Builder::new()
            .name("engine".into())
            .spawn(move || run_engine(engine, monitor, enforcer, updates, wake_rx, interval))?
    };

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let state =
        AppState { engine, updates, wake: wake_tx.clone(), started: Instant::now(), shutdown: stop_rx };
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!("dashboard: http://{}", args.listen);
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = stop_tx.send(true);
        })
        .await?;

    tracing::info!("shutting down");
    let _ = wake_tx.send(Wake::Shutdown);
    let _ = tokio::task::spawn_blocking(move || worker.join()).await;
    Ok(())
}
