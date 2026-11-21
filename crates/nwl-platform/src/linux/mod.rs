//! Linux backend.
//!
//! * Monitoring: `NETLINK_SOCK_DIAG` for sockets with `tcp_info` byte
//!   counters, `/proc/<pid>/fd` for ownership, `/proc/net/dev` for totals.
//! * Enforcement: processes of targeted applications are moved into a child
//!   cgroup (`nwl-<app>`) *inside their current cgroup*, so systemd still sees
//!   them as part of their unit; an nftables table then matches their sockets
//!   with `socket cgroupv2` and drops or polices their packets.

mod cgroup;
pub mod dnswatch;
pub mod ebpf;
pub mod netman;
pub mod nft;
pub mod procfs;
pub mod sockdiag;

pub use cgroup::CgroupManager;

/// Skips a test that needs kernel features or privileges this environment
/// lacks, unless `NWL_E2E=1` says they must be there (as in CI), where a
/// skip would hide a broken setup: then it fails.
#[cfg(test)]
pub(crate) fn skip_unless_required(why: &str) {
    if std::env::var("NWL_E2E").as_deref() == Ok("1") {
        panic!("required by NWL_E2E=1 but unavailable: {why}");
    }
    eprintln!("skipping: {why}");
}

use crate::{EnforceReport, Enforcer, EnforcerOptions, Error, Monitor, MonitorOptions, Policy, Result};
use nwl_core::model::{ConnKey, Connection, ProcessInfo, Protocol, Snapshot};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

pub struct LinuxMonitor {
    proc_root: PathBuf,
    start: Instant,
    /// Socket inode -> owning pid, kept while the socket exists.
    owners: HashMap<u32, u32>,
    /// Per-socket byte counters for all protocols, when eBPF is available.
    counters: Option<ebpf::SocketCounters>,
    /// What we last knew about sockets, by cookie: kept after they close so
    /// their final bytes are reported under the same identity.
    known: HashMap<u64, KnownSocket>,
    /// Recently seen processes, so one that exits right after its last
    /// transfer is still named.
    recent_processes: HashMap<u32, (ProcessInfo, u64)>,
    warnings: Vec<String>,
}

/// A socket the counters saw, for reporting it after it is gone.
struct KnownSocket {
    key: ConnKey,
    pid: Option<u32>,
    /// Counters when last reported.
    reported: (u64, u64),
    /// Monotonic ms of the last change of its counters.
    changed_ms: u64,
}

/// How long a gone socket's counters are kept once they stop changing.
const CLOSED_RETAIN_MS: u64 = 60_000;
/// How long process details are remembered after the process was last seen.
const PROCESS_RETAIN_MS: u64 = 300_000;

impl LinuxMonitor {
    pub fn new(opts: &MonitorOptions) -> Result<Self> {
        // Fail early with a clear message if sock_diag is unavailable.
        sockdiag::dump_all().map_err(|e| Error::io("NETLINK_SOCK_DIAG unavailable", e))?;
        let mut warnings = Vec::new();
        let counters = if opts.ebpf {
            let attached = std::fs::read_to_string("/proc/self/mountinfo")
                .ok()
                .and_then(|m| cgroup::find_cgroup2_mount(&m))
                .ok_or_else(|| Error::Unsupported("cgroup v2 is not mounted".into()))
                .and_then(|root| ebpf::SocketCounters::attach(&root, opts.count_loopback));
            match attached {
                Ok(c) => Some(c),
                Err(e) => {
                    warnings.push(format!(
                        "eBPF traffic counters unavailable ({e}); UDP traffic is not attributed to apps. Run as root to enable."
                    ));
                    None
                }
            }
        } else {
            None
        };
        Ok(Self {
            proc_root: PathBuf::from("/proc"),
            start: Instant::now(),
            owners: HashMap::new(),
            counters,
            known: HashMap::new(),
            recent_processes: HashMap::new(),
            warnings,
        })
    }

    /// Process details for `pid`, from `/proc` or, if it already exited,
    /// from memory or from the name eBPF recorded (`comm`). Records them in
    /// the snapshot.
    fn process(&mut self, snap: &mut Snapshot, pid: u32, comm: Option<String>) -> bool {
        if snap.processes.contains_key(&pid) {
            return true;
        }
        let info = match procfs::process_info(&self.proc_root, pid) {
            Some(info) => {
                self.recent_processes.insert(pid, (info.clone(), snap.mono_ms));
                info
            }
            None => match (self.recent_processes.get(&pid), comm) {
                (Some((info, _)), _) => info.clone(),
                // Exited before we ever saw it (e.g. a 30 ms `getent`): use
                // the name, and the executable of another recent process of
                // that name so it groups with the same application.
                (None, Some(name)) => {
                    let exe = self
                        .recent_processes
                        .values()
                        .find(|(p, _)| p.name == name)
                        .and_then(|(p, _)| p.exe.clone());
                    ProcessInfo { pid, name, exe, uid: None }
                }
                (None, None) => return false,
            },
        };
        snap.processes.insert(pid, info);
        true
    }
}

impl Monitor for LinuxMonitor {
    fn name(&self) -> &'static str {
        if self.counters.is_some() {
            "linux (sock_diag + eBPF)"
        } else {
            "linux (sock_diag)"
        }
    }

    fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }

    fn close(&mut self, key: &ConnKey) -> Result<()> {
        sockdiag::destroy(key).map_err(|e| match e.raw_os_error() {
            Some(libc::EOPNOTSUPP) => {
                Error::Unsupported("this kernel can't close connections (no CONFIG_INET_DIAG_DESTROY)".into())
            }
            Some(libc::EPERM) | Some(libc::EACCES) => {
                Error::Other("closing connections needs nwld to run as root".into())
            }
            Some(libc::ENOENT) => Error::Other("the connection is already closed".into()),
            _ => Error::io("closing the connection", e),
        })
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

        // eBPF counts every protocol at the IP layer; tcp_info is the
        // TCP-only fallback. One source is used for all sockets so the
        // numbers stay comparable.
        let mut counted = self.counters.as_mut().map(|c| c.all());
        let mut snap = Snapshot { mono_ms, ..Default::default() };
        for s in socks {
            let cookie = s.key.cookie;
            let counter = counted.as_mut().map(|all| all.remove(&cookie).unwrap_or_default());
            // Owner from /proc; failing that, the creator eBPF recorded.
            let mut pid = self.owners.get(&s.inode).copied();
            if pid.is_none() {
                pid = counter.map(|c| c.tgid).filter(|&t| t != 0);
            }
            let comm = counter.and_then(|c| c.comm());
            let pid = pid.filter(|&p| self.process(&mut snap, p, comm.clone()));
            let (bytes_sent, bytes_recv) = match counter {
                Some(c) => {
                    let known = self.known.entry(cookie).or_insert(KnownSocket {
                        key: s.key.clone(),
                        pid,
                        reported: (0, 0),
                        changed_ms: mono_ms,
                    });
                    if known.reported != (c.tx, c.rx) {
                        known.changed_ms = mono_ms;
                    }
                    (known.key, known.pid, known.reported) = (s.key.clone(), pid, (c.tx, c.rx));
                    (Some(c.tx), Some(c.rx))
                }
                None => (s.bytes_sent, s.bytes_recv),
            };
            snap.connections.push(Connection {
                key: s.key,
                state: s.state,
                pid,
                uid: Some(s.uid),
                bytes_sent,
                bytes_recv,
                rtt_us: s.rtt_us,
                closed: false,
            });
        }

        // Whatever is left was counted but is not an open socket we can see:
        // it closed since the last sample, or lives in another network
        // namespace (a container). Report it whenever its counters moved.
        if let Some(rest) = counted {
            for (cookie, c) in rest {
                let protocol = match c.protocol {
                    6 => Protocol::Tcp,
                    17 => Protocol::Udp,
                    _ => continue,
                };
                let known = self.known.entry(cookie).or_insert_with(|| KnownSocket {
                    key: ConnKey {
                        protocol,
                        local: SocketAddr::from(([0, 0, 0, 0], 0)),
                        remote: None,
                        cookie,
                    },
                    pid: Some(c.tgid).filter(|&t| t != 0),
                    reported: (0, 0),
                    changed_ms: mono_ms,
                });
                if known.reported == (c.tx, c.rx) {
                    continue;
                }
                known.reported = (c.tx, c.rx);
                known.changed_ms = mono_ms;
                let (key, pid) = (known.key.clone(), known.pid);
                let pid = pid.filter(|&p| self.process(&mut snap, p, c.comm()));
                snap.connections.push(Connection {
                    key,
                    state: None,
                    pid,
                    uid: None,
                    bytes_sent: Some(c.tx),
                    bytes_recv: Some(c.rx),
                    rtt_us: None,
                    closed: true,
                });
            }
            // Forget sockets that are gone and quiet, in the kernel too.
            let open: HashSet<u64> =
                snap.connections.iter().filter(|c| !c.closed).map(|c| c.key.cookie).collect();
            let counters = self.counters.as_ref().expect("counted implies counters");
            self.known.retain(|cookie, k| {
                let keep = open.contains(cookie) || mono_ms.saturating_sub(k.changed_ms) <= CLOSED_RETAIN_MS;
                if !keep {
                    counters.remove(*cookie);
                }
                keep
            });
        }
        self.recent_processes.retain(|_, (_, seen)| mono_ms.saturating_sub(*seen) <= PROCESS_RETAIN_MS);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    /// A socket that opens, transfers and closes between two samples is
    /// still counted and attributed. Needs root (eBPF); skipped otherwise.
    #[test]
    fn short_lived_sockets_are_attributed() {
        let _guard = ebpf::test_lock();
        let opts = MonitorOptions { ebpf: true, count_loopback: true };
        let mut monitor = LinuxMonitor::new(&opts).unwrap();
        if monitor.counters.is_none() {
            return skip_unless_required("eBPF counters");
        }
        monitor.snapshot().unwrap();
        {
            let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            tx.connect(rx.local_addr().unwrap()).unwrap();
            for _ in 0..20 {
                tx.send(&[7u8; 500]).unwrap();
                rx.recv(&mut [0u8; 600]).unwrap();
            }
        } // both sockets closed before the next sample
        let snap = monitor.snapshot().unwrap();
        let me = std::process::id();
        let mine: Vec<&Connection> =
            snap.connections.iter().filter(|c| c.closed && c.pid == Some(me)).collect();
        let sent: u64 = mine.iter().filter_map(|c| c.bytes_sent).sum();
        let received: u64 = mine.iter().filter_map(|c| c.bytes_recv).sum();
        assert_eq!((sent, received), (20 * 528, 20 * 528), "{mine:#?}");
        assert!(mine.iter().all(|c| c.key.protocol == Protocol::Udp));
        assert!(snap.processes.contains_key(&me));

        // Reported once: the next sample does not count them again.
        let again = monitor.snapshot().unwrap();
        assert!(!again.connections.iter().any(|c| c.closed && c.pid == Some(me)));
    }
}
