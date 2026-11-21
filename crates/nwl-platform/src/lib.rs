//! Operating-system backends.
//!
//! A backend has two halves:
//!
//! * a [`Monitor`] that reports sockets, their owning processes and byte
//!   counters as a [`Snapshot`];
//! * an [`Enforcer`] that makes the kernel apply a [`RuleSet`] (block, limit,
//!   exhausted quotas).
//!
//! | Platform | Monitor | Enforcer |
//! |----------|---------|----------|
//! | Linux    | `NETLINK_SOCK_DIAG` + `/proc`, eBPF byte counters | cgroup v2 + nftables |
//! | Windows  | IP Helper (`GetExtendedTcpTable`, TCP EStats) | Windows Firewall + QoS policies |
//! | any      | [`sim::SimulatedMonitor`] (demo data) | [`NullEnforcer`] (monitor only) |
//!
//! [`network`] detects which network the machine is on and whether it is
//! metered.

use nwl_core::model::{AppId, Snapshot};
use nwl_core::rules::{Action, RuleId, RuleSet};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_os = "linux")]
pub mod linux;
pub mod network;
pub mod sim;
#[cfg(windows)]
pub mod windows;
pub mod winplan;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io { context: context.into(), source }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Observes sockets and traffic.
pub trait Monitor: Send {
    fn name(&self) -> &'static str;
    fn snapshot(&mut self) -> Result<Snapshot>;
    /// Degraded capabilities worth telling the user about.
    fn warnings(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Options for constructing the native monitor.
#[derive(Debug, Clone)]
pub struct MonitorOptions {
    /// Use eBPF for exact per-socket counters of every protocol (Linux,
    /// needs root). Falls back to TCP-only counters when unavailable.
    pub ebpf: bool,
    /// Count loopback traffic at the source (eBPF counters skip packets on
    /// the loopback interface otherwise).
    pub count_loopback: bool,
}

impl Default for MonitorOptions {
    fn default() -> Self {
        Self { ebpf: true, count_loopback: false }
    }
}

/// What an enforcer should make the kernel do.
pub struct Policy<'a> {
    pub rules: &'a RuleSet,
    /// Quota rules whose cap is reached in the current period.
    pub exhausted_quotas: &'a [RuleId],
    /// The latest observation, for backends that resolve apps from it.
    pub snapshot: &'a Snapshot,
}

#[derive(Debug, Default, Clone)]
pub struct EnforceReport {
    /// Whether kernel state was modified by this call.
    pub changed: bool,
    /// Rules or features the backend could not apply.
    pub warnings: Vec<String>,
}

/// Applies policies. `apply` is called every tick with the full desired
/// state and must be idempotent and cheap when nothing changed.
pub trait Enforcer: Send {
    fn name(&self) -> &'static str;
    fn apply(&mut self, policy: &Policy<'_>) -> Result<EnforceReport>;
    /// Removes everything this enforcer installed.
    fn clear(&mut self) -> Result<()>;
}

/// Monitor-only mode: never touches the system.
pub struct NullEnforcer;

impl Enforcer for NullEnforcer {
    fn name(&self) -> &'static str {
        "none (monitor only)"
    }
    fn apply(&mut self, _: &Policy<'_>) -> Result<EnforceReport> {
        Ok(EnforceReport::default())
    }
    fn clear(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Options for constructing the native enforcer.
#[derive(Debug, Clone, Default)]
pub struct EnforcerOptions {
    /// Also police loopback traffic (off by default: throttling localhost
    /// breaks local IPC and is almost never what users want).
    pub include_loopback: bool,
}

/// The native monitor for this OS.
pub fn native_monitor(opts: MonitorOptions) -> Result<Box<dyn Monitor>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxMonitor::new(&opts)?))
    }
    #[cfg(windows)]
    {
        let _ = opts;
        Ok(Box::new(windows::WindowsMonitor::new()?))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = opts;
        Err(Error::Unsupported("no native monitor for this OS yet; use --demo".into()))
    }
}

/// The native enforcer for this OS.
pub fn native_enforcer(opts: EnforcerOptions) -> Result<Box<dyn Enforcer>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxEnforcer::new(opts)?))
    }
    #[cfg(windows)]
    {
        let _ = opts;
        Ok(Box::new(windows::WindowsEnforcer::new()?))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = opts;
        Err(Error::Unsupported("no native enforcer for this OS yet".into()))
    }
}

/// Rules that only apply to specific applications.
pub fn app_scoped_rules(rules: &RuleSet) -> impl Iterator<Item = &nwl_core::rules::Rule> {
    rules.enabled().filter(|r| r.matcher.app.is_some())
}

/// Whether a rule has any effect for an enforcer right now.
pub fn rule_is_active(action: &Action, id: RuleId, exhausted: &[RuleId]) -> bool {
    match action {
        Action::Quota { .. } => exhausted.contains(&id),
        _ => true,
    }
}

/// For every application in the snapshot targeted by at least one enabled
/// app-scoped rule: the ids of those rules.
pub fn targeted_apps(rules: &RuleSet, snapshot: &Snapshot) -> BTreeMap<AppId, BTreeSet<RuleId>> {
    let mut out: BTreeMap<AppId, BTreeSet<RuleId>> = BTreeMap::new();
    for process in snapshot.processes.values() {
        for rule in app_scoped_rules(rules) {
            let pattern = rule.matcher.app.as_ref().expect("filtered");
            if pattern.matches_process(process) {
                out.entry(process.app_id()).or_default().insert(rule.id);
            }
        }
    }
    out
}
