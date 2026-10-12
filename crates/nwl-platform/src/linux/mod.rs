//! Linux backend.
//!
//! * Monitoring: `NETLINK_SOCK_DIAG` for sockets with `tcp_info` byte
//!   counters, `/proc/<pid>/fd` for ownership, `/proc/net/dev` for totals.
//! * Enforcement: processes of targeted applications are moved into a child
//!   cgroup (`nwl-<app>`) *inside their current cgroup*, so systemd still sees
//!   them as part of their unit; an nftables table then matches their sockets
//!   with `socket cgroupv2` and drops or polices their packets.

mod cgroup;
pub mod nft;
pub mod procfs;
pub mod sockdiag;

pub use cgroup::CgroupManager;

use crate::{EnforceReport, Enforcer, EnforcerOptions, Error, Monitor, Policy, Result};
use nwl_core::model::{Connection, Snapshot};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

pub struct LinuxMonitor {
    proc_root: PathBuf,
    start: Instant,
    /// Socket inode -> owning pid, kept while the socket exists.
    owners: HashMap<u32, u32>,
}

impl LinuxMonitor {
    pub fn new() -> Result<Self> {
        // Fail early with a clear message if sock_diag is unavailable.
        sockdiag::dump_all().map_err(|e| Error::io("NETLINK_SOCK_DIAG unavailable", e))?;
        Ok(Self { proc_root: PathBuf::from("/proc"), start: Instant::now(), owners: HashMap::new() })
    }
}

impl Monitor for LinuxMonitor {
    fn name(&self) -> &'static str {
        "linux (sock_diag)"
    }

    fn snapshot(&mut self) -> Result<Snapshot> {
        let socks = sockdiag::dump_all().map_err(|e| Error::io("sock_diag dump", e))?;
        let mono_ms = self.start.elapsed().as_millis() as u64;

        let live: HashSet<u32> = socks.iter().map(|s| s.inode).filter(|&i| i != 0).collect();
        self.owners.retain(|inode, _| live.contains(inode));
        let unknown: HashSet<u32> = live.iter().copied().filter(|i| !self.owners.contains_key(i)).collect();
        if !unknown.is_empty() {
            self.owners.extend(procfs::socket_owners(&self.proc_root, &unknown));
        }

        let mut snap = Snapshot { mono_ms, ..Default::default() };
        for s in socks {
            let pid = self.owners.get(&s.inode).copied();
            if let Some(pid) = pid {
                if let std::collections::hash_map::Entry::Vacant(slot) = snap.processes.entry(pid) {
                    match procfs::process_info(&self.proc_root, pid) {
                        Some(info) => {
                            slot.insert(info);
                        }
                        // Process exited; forget so the inode is re-resolved.
                        None => {
                            self.owners.remove(&s.inode);
                        }
                    }
                }
            }
            snap.connections.push(Connection {
                key: s.key,
                state: s.state,
                pid: pid.filter(|p| snap.processes.contains_key(p)),
                uid: Some(s.uid),
                bytes_sent: s.bytes_sent,
                bytes_recv: s.bytes_recv,
                rtt_us: s.rtt_us,
            });
        }
        snap.interfaces = procfs::interface_counters(&self.proc_root);
        Ok(snap)
    }
}

pub struct LinuxEnforcer {
    opts: EnforcerOptions,
    cgroups: CgroupManager,
    last_ruleset: Option<String>,
}

impl LinuxEnforcer {
    pub fn new(opts: EnforcerOptions) -> Result<Self> {
        let status = Command::new("nft")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .map_err(|e| Error::io("cannot run `nft` (install nftables)", e))?;
        if !status.success() {
            return Err(Error::Other("`nft --version` failed".into()));
        }
        let mut cgroups = CgroupManager::detect()?;
        cgroups.release_stale();
        Ok(Self { opts, cgroups, last_ruleset: None })
    }
}

fn run_nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::io("spawn nft", e))?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(script.as_bytes())
        .map_err(|e| Error::io("write nft script", e))?;
    let out = child.wait_with_output().map_err(|e| Error::io("wait for nft", e))?;
    if !out.status.success() {
        return Err(Error::Other(format!(
            "nft rejected the ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

impl Enforcer for LinuxEnforcer {
    fn name(&self) -> &'static str {
        "linux (cgroup v2 + nftables)"
    }

    fn apply(&mut self, policy: &Policy<'_>) -> Result<EnforceReport> {
        let mut report = EnforceReport::default();
        let targets = self.cgroups.sync(policy.rules, &mut report.warnings);
        let ruleset = nft::render(&nft::RenderInput {
            table: nft::TABLE,
            rules: policy.rules,
            exhausted_quotas: policy.exhausted_quotas,
            app_cgroups: &targets,
            include_loopback: self.opts.include_loopback,
        });
        if self.last_ruleset.as_deref() != Some(ruleset.as_str()) {
            run_nft(&ruleset)?;
            self.last_ruleset = Some(ruleset);
            report.changed = true;
        }
        Ok(report)
    }

    fn clear(&mut self) -> Result<()> {
        let result = run_nft(&format!("table inet {0}\ndelete table inet {0}\n", nft::TABLE));
        self.last_ruleset = None;
        self.cgroups.release_all();
        result
    }
}
