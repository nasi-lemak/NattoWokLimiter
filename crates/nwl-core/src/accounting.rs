//! Turns successive [`Snapshot`]s into per-application rates, totals and
//! short-term history (for sparklines and graphs).

use crate::model::{AppId, ConnKey, Snapshot};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, VecDeque};

/// Fixed-capacity history of `(upload, download)` rate samples in bytes/s.
#[derive(Debug, Clone, Serialize)]
pub struct History {
    capacity: usize,
    samples: VecDeque<(u64, u64)>,
}

impl History {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, samples: VecDeque::with_capacity(capacity) }
    }

    pub fn push(&mut self, up: u64, down: u64) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back((up, down));
    }

    pub fn samples(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.samples.iter().copied()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AppStats {
    pub app: AppId,
    pub name: String,
    pub pids: BTreeSet<u32>,
    pub connections: usize,
    /// Bytes per second over the last tick.
    pub rate_up: u64,
    pub rate_down: u64,
    /// Bytes since the daemon started.
    pub total_up: u64,
    pub total_down: u64,
    pub history: History,
    /// Monotonic ms of the last tick in which this app had a socket.
    pub last_seen_ms: u64,
}

/// Bytes moved by one connection during one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnDelta {
    pub key: ConnKey,
    pub app: Option<AppId>,
    pub up: u64,
    pub down: u64,
    /// Localhost traffic; only counted in app statistics when
    /// [`Accountant::count_loopback`] is set.
    pub loopback: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemStats {
    /// Interface totals (all protocols, excluding loopback), bytes/s.
    pub rate_up: u64,
    pub rate_down: u64,
    pub total_up: u64,
    pub total_down: u64,
}

pub struct Accountant {
    /// Count localhost traffic in application statistics. Off by default:
    /// it never touches the network, and would distort usage and quotas.
    pub count_loopback: bool,
    history_len: usize,
    /// Forget apps that have had no sockets for this long.
    retain_ms: u64,
    last_ms: Option<u64>,
    prev_conns: HashMap<ConnKey, (u64, u64)>,
    prev_ifaces: HashMap<String, (u64, u64)>,
    apps: HashMap<AppId, AppStats>,
    system: SystemStats,
    system_history: History,
}

impl Accountant {
    pub fn new(history_len: usize, retain_ms: u64) -> Self {
        Self {
            count_loopback: false,
            history_len,
            retain_ms,
            last_ms: None,
            prev_conns: HashMap::new(),
            prev_ifaces: HashMap::new(),
            apps: HashMap::new(),
            system: SystemStats::default(),
            system_history: History::new(history_len),
        }
    }

    /// Ingests a snapshot and returns the per-connection byte deltas since the
    /// previous one.
    ///
    /// The first snapshot only establishes a baseline: sockets that were open
    /// before we started are not counted as if they transferred everything
    /// at once. Sockets that appear later are counted in full, since they were
    /// opened since the previous tick.
    pub fn ingest(&mut self, snap: &Snapshot) -> Vec<ConnDelta> {
        let primed = self.last_ms.is_some();
        let elapsed_ms = self.last_ms.map(|t| snap.mono_ms.saturating_sub(t)).unwrap_or(0);
        self.last_ms = Some(snap.mono_ms);
        let per_sec = |bytes: u64| bytes.saturating_mul(1000).checked_div(elapsed_ms).unwrap_or(0);

        for stats in self.apps.values_mut() {
            stats.pids.clear();
            stats.connections = 0;
            stats.rate_up = 0;
            stats.rate_down = 0;
        }

        let mut deltas = Vec::new();
        let mut next_conns = HashMap::with_capacity(snap.connections.len());
        for conn in &snap.connections {
            let process = snap.process_of(conn);
            let app = process.map(|p| p.app_id());
            let (sent, recv) = (conn.bytes_sent.unwrap_or(0), conn.bytes_recv.unwrap_or(0));
            let (up, down) = match self.prev_conns.get(&conn.key) {
                // Counters only grow for a given socket; a decrease means the
                // platform reused the key, so count from zero.
                Some(&(ps, pr)) => {
                    (if sent >= ps { sent - ps } else { sent }, if recv >= pr { recv - pr } else { recv })
                }
                None if primed => (sent, recv),
                None => (0, 0),
            };
            next_conns.insert(conn.key.clone(), (sent, recv));
            let loopback = conn.is_loopback();
            let counted = !loopback || self.count_loopback;

            if let (Some(app), Some(process)) = (&app, process) {
                let stats = self.apps.entry(app.clone()).or_insert_with(|| AppStats {
                    app: app.clone(),
                    name: app.display_name().to_string(),
                    pids: BTreeSet::new(),
                    connections: 0,
                    rate_up: 0,
                    rate_down: 0,
                    total_up: 0,
                    total_down: 0,
                    history: History::new(self.history_len),
                    last_seen_ms: snap.mono_ms,
                });
                stats.pids.insert(process.pid);
                stats.connections += 1;
                if counted {
                    stats.rate_up += up;
                    stats.rate_down += down;
                }
                stats.last_seen_ms = snap.mono_ms;
            }
            if up > 0 || down > 0 {
                deltas.push(ConnDelta { key: conn.key.clone(), app, up, down, loopback });
            }
        }
        self.prev_conns = next_conns;

        let retain_ms = self.retain_ms;
        self.apps.retain(|_, s| snap.mono_ms.saturating_sub(s.last_seen_ms) <= retain_ms);
        for stats in self.apps.values_mut() {
            // rate_* held raw byte deltas until now.
            stats.total_up += stats.rate_up;
            stats.total_down += stats.rate_down;
            stats.rate_up = per_sec(stats.rate_up);
            stats.rate_down = per_sec(stats.rate_down);
            if primed {
                stats.history.push(stats.rate_up, stats.rate_down);
            }
        }

        let (mut up, mut down) = (0u64, 0u64);
        let mut next_ifaces = HashMap::new();
        for iface in snap.interfaces.iter().filter(|i| !is_loopback(&i.name)) {
            if let Some(&(ptx, prx)) = self.prev_ifaces.get(&iface.name) {
                up += iface.tx_bytes.saturating_sub(ptx);
                down += iface.rx_bytes.saturating_sub(prx);
            }
            next_ifaces.insert(iface.name.clone(), (iface.tx_bytes, iface.rx_bytes));
        }
        self.prev_ifaces = next_ifaces;
        self.system.total_up += up;
        self.system.total_down += down;
        self.system.rate_up = per_sec(up);
        self.system.rate_down = per_sec(down);
        if primed {
            self.system_history.push(self.system.rate_up, self.system.rate_down);
        }

        deltas
    }

    pub fn apps(&self) -> impl Iterator<Item = &AppStats> {
        self.apps.values()
    }

    pub fn system(&self) -> &SystemStats {
        &self.system
    }

    pub fn system_history(&self) -> &History {
        &self.system_history
    }
}

fn is_loopback(name: &str) -> bool {
    name == "lo" || name.starts_with("Loopback")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Connection, InterfaceCounters, ProcessInfo, Protocol};

    fn snap(ms: u64, conns: &[(u64, u64, u64)], iface: (u64, u64)) -> Snapshot {
        let mut s = Snapshot { mono_ms: ms, ..Default::default() };
        s.processes.insert(
            7,
            ProcessInfo { pid: 7, name: "curl".into(), exe: Some("/usr/bin/curl".into()), uid: None },
        );
        for &(cookie, sent, recv) in conns {
            s.connections.push(Connection {
                key: ConnKey {
                    protocol: Protocol::Tcp,
                    local: "10.0.0.1:1000".parse().unwrap(),
                    remote: Some("1.1.1.1:443".parse().unwrap()),
                    cookie,
                },
                state: None,
                pid: Some(7),
                uid: None,
                bytes_sent: Some(sent),
                bytes_recv: Some(recv),
                rtt_us: None,
            });
        }
        s.interfaces = vec![
            InterfaceCounters { name: "eth0".into(), tx_bytes: iface.0, rx_bytes: iface.1 },
            InterfaceCounters { name: "lo".into(), tx_bytes: iface.0 * 9, rx_bytes: iface.1 * 9 },
        ];
        s
    }

    #[test]
    fn baseline_then_rates() {
        let mut acc = Accountant::new(4, 60_000);
        // Pre-existing socket with lots of history: not counted.
        assert!(acc.ingest(&snap(0, &[(1, 5_000, 50_000)], (100, 100))).is_empty());
        let app = acc.apps().next().unwrap();
        assert_eq!((app.total_up, app.total_down), (0, 0));

        // 500 ms later: socket 1 moved 1000/2000 bytes, socket 2 is new.
        let d = acc.ingest(&snap(500, &[(1, 6_000, 52_000), (2, 100, 400)], (1_100, 3_100)));
        assert_eq!(d.len(), 2);
        let app = acc.apps().next().unwrap();
        assert_eq!(app.connections, 2);
        assert_eq!((app.total_up, app.total_down), (1_100, 2_400));
        assert_eq!((app.rate_up, app.rate_down), (2_200, 4_800));
        assert_eq!(app.history.samples().collect::<Vec<_>>(), vec![(2_200, 4_800)]);
        let sys = acc.system();
        assert_eq!((sys.rate_up, sys.rate_down), (2_000, 6_000));
    }

    #[test]
    fn loopback_is_not_counted_by_default() {
        let mut lo = snap(0, &[(1, 0, 0)], (0, 0));
        lo.connections[0].key.local = "127.0.0.1:1000".parse().unwrap();
        lo.connections[0].key.remote = Some("127.0.0.1:2000".parse().unwrap());
        let mut next = lo.clone();
        next.mono_ms = 1000;
        next.connections[0].bytes_sent = Some(500);

        let mut acc = Accountant::new(4, 60_000);
        acc.ingest(&lo);
        let d = acc.ingest(&next);
        assert!(d[0].loopback);
        assert_eq!(acc.apps().next().unwrap().total_up, 0);

        let mut acc = Accountant::new(4, 60_000);
        acc.count_loopback = true;
        acc.ingest(&lo);
        acc.ingest(&next);
        assert_eq!(acc.apps().next().unwrap().total_up, 500);
    }

    #[test]
    fn counter_reset_counts_from_zero() {
        let mut acc = Accountant::new(4, 60_000);
        acc.ingest(&snap(0, &[(1, 5_000, 5_000)], (0, 0)));
        let d = acc.ingest(&snap(1000, &[(1, 10, 20)], (0, 0)));
        assert_eq!((d[0].up, d[0].down), (10, 20));
    }

    #[test]
    fn idle_apps_expire_and_history_is_bounded() {
        let mut acc = Accountant::new(2, 1_500);
        acc.ingest(&snap(0, &[(1, 0, 0)], (0, 0)));
        for t in 1..=3 {
            acc.ingest(&snap(t * 1000, &[(1, t * 10, 0)], (0, 0)));
        }
        assert_eq!(acc.apps().next().unwrap().history.samples().count(), 2);
        acc.ingest(&snap(4_000, &[], (0, 0)));
        assert_eq!(acc.apps().count(), 1, "still within retention");
        acc.ingest(&snap(6_000, &[], (0, 0)));
        assert_eq!(acc.apps().count(), 0);
    }
}
