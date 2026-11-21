//! A simulated machine for demos, UI development and tests.
//!
//! [`SimulatedMonitor`] invents a handful of applications with plausible
//! traffic patterns. Paired with [`SimulatedEnforcer`] it honours blocks,
//! limits and quotas, so the effect of rules is visible in the UI without
//! root privileges or a supported OS.

use crate::{EnforceReport, Enforcer, Error, Monitor, Policy, Result};
use nwl_core::model::{ConnKey, Connection, InterfaceCounters, ProcessInfo, Protocol, Snapshot, TcpState};
use nwl_core::rules::{Action, MatchCtx, RuleId, RuleSet};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Default)]
struct SharedPolicy {
    rules: RuleSet,
    exhausted: Vec<RuleId>,
}

/// Traffic profile of a simulated application, in bytes/second.
struct Profile {
    pid: u32,
    name: &'static str,
    exe: &'static str,
    remotes: &'static [&'static str],
    up: f64,
    down: f64,
    /// 0 = steady, otherwise period in ticks of an on/off burst pattern.
    burst_period: u64,
    /// 0 = never, otherwise every this many ticks the app moves 400x its
    /// usual upload for a while (a backup kicking in: a traffic spike).
    spike_every: u64,
}

/// Length of a simulated upload spike, in ticks.
const SPIKE_TICKS: u64 = 20;

const PROFILES: &[Profile] = &[
    Profile {
        pid: 2101,
        name: "firefox",
        exe: "/usr/lib/firefox/firefox",
        remotes: &["142.250.74.78:443", "151.101.1.140:443", "[2a00:1450:4001:82b::200e]:443"],
        up: 40e3,
        down: 900e3,
        burst_period: 7,
        spike_every: 0,
    },
    Profile {
        pid: 3300,
        name: "steam",
        exe: "/home/demo/.steam/steam/ubuntu12_32/steam",
        remotes: &["23.62.226.10:443", "155.133.248.39:27017"],
        up: 20e3,
        down: 6e6,
        burst_period: 0,
        spike_every: 0,
    },
    Profile {
        pid: 4120,
        name: "Discord",
        exe: "/opt/discord/Discord",
        remotes: &["162.159.135.234:443", "35.214.203.66:50003"],
        up: 60e3,
        down: 120e3,
        burst_period: 0,
        spike_every: 0,
    },
    Profile {
        pid: 5021,
        name: "spotify",
        exe: "/usr/share/spotify/spotify",
        remotes: &["35.186.224.25:443"],
        up: 4e3,
        down: 330e3,
        burst_period: 12,
        spike_every: 0,
    },
    Profile {
        pid: 6100,
        name: "dropbox",
        exe: "/home/demo/.dropbox-dist/dropbox",
        remotes: &["162.125.19.131:443"],
        up: 1.5e6,
        down: 30e3,
        burst_period: 20,
        spike_every: 0,
    },
    Profile {
        pid: 812,
        name: "systemd-resolve",
        exe: "/usr/lib/systemd/systemd-resolved",
        remotes: &["1.1.1.1:53"],
        up: 300.0,
        down: 600.0,
        burst_period: 0,
        spike_every: 0,
    },
    Profile {
        pid: 7330,
        name: "rclone",
        exe: "/usr/bin/rclone",
        remotes: &["52.219.170.33:443"],
        up: 20e3,
        down: 2e3,
        burst_period: 0,
        spike_every: 120,
    },
];

struct SimConn {
    key: ConnKey,
    pid: u32,
    sent: u64,
    recv: u64,
    weight: f64,
}

pub struct SimulatedMonitor {
    start: Instant,
    tick: u64,
    last_ms: u64,
    rng: u64,
    conns: Vec<SimConn>,
    next_cookie: u64,
    next_port: u16,
    iface: (u64, u64),
    policy: Arc<Mutex<SharedPolicy>>,
}

/// Creates a simulated monitor and the enforcer that steers it.
pub fn simulated() -> (SimulatedMonitor, SimulatedEnforcer) {
    let policy = Arc::new(Mutex::new(SharedPolicy::default()));
    let mut monitor = SimulatedMonitor {
        start: Instant::now(),
        tick: 0,
        last_ms: 0,
        rng: 0x9e37_79b9_7f4a_7c15,
        conns: Vec::new(),
        next_cookie: 1,
        next_port: 40000,
        iface: (0, 0),
        policy: policy.clone(),
    };
    for (i, p) in PROFILES.iter().enumerate() {
        for r in p.remotes {
            monitor.open(i, r);
        }
    }
    (monitor, SimulatedEnforcer { policy })
}

impl SimulatedMonitor {
    fn rand(&mut self) -> f64 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }

    fn open(&mut self, profile: usize, remote: &str) {
        let p = &PROFILES[profile];
        let remote: std::net::SocketAddr = remote.parse().expect("valid demo address");
        let local = if remote.is_ipv4() { "192.168.1.23" } else { "2001:db8::23" };
        let protocol =
            if remote.port() == 53 || remote.port() > 27000 { Protocol::Udp } else { Protocol::Tcp };
        self.next_port = self.next_port.wrapping_add(1).max(40000);
        let weight = 0.5 + self.rand();
        self.conns.push(SimConn {
            key: ConnKey {
                protocol,
                local: std::net::SocketAddr::new(local.parse().unwrap(), self.next_port),
                remote: Some(remote),
                cookie: self.next_cookie,
            },
            pid: p.pid,
            sent: 0,
            recv: 0,
            weight,
        });
        self.next_cookie += 1;
    }

    fn process(p: &Profile) -> ProcessInfo {
        ProcessInfo { pid: p.pid, name: p.name.to_string(), exe: Some(p.exe.into()), uid: Some(1000) }
    }
}

impl Monitor for SimulatedMonitor {
    fn name(&self) -> &'static str {
        "simulated (demo data)"
    }

    /// The demo app reconnects at once, as real apps tend to.
    fn close(&mut self, key: &ConnKey) -> Result<()> {
        let i = self
            .conns
            .iter()
            .position(|c| &c.key == key)
            .ok_or_else(|| Error::Other("the connection is already closed".into()))?;
        let old = self.conns.remove(i);
        let profile =
            PROFILES.iter().position(|p| p.pid == old.pid).expect("demo connections have a profile");
        let remote = old.key.remote.expect("demo connections have a remote").to_string();
        self.open(profile, &remote);
        Ok(())
    }

    fn snapshot(&mut self) -> Result<Snapshot> {
        let now_ms = self.start.elapsed().as_millis() as u64;
        let dt = (now_ms.saturating_sub(self.last_ms)) as f64 / 1000.0;
        self.last_ms = now_ms;
        self.tick += 1;

        // Churn: occasionally replace a connection with a fresh one.
        if self.tick % 5 == 0 && !self.conns.is_empty() {
            let idx = (self.rand() * self.conns.len() as f64) as usize % self.conns.len();
            let old = self.conns.remove(idx);
            let profile = PROFILES.iter().position(|p| p.pid == old.pid).unwrap();
            let remote = old.key.remote.unwrap().to_string();
            self.open(profile, &remote);
        }

        let mut processes = HashMap::new();
        for p in PROFILES {
            processes.insert(p.pid, Self::process(p));
        }

        // Desired traffic per connection this tick.
        let mut wanted: Vec<(f64, f64)> = Vec::with_capacity(self.conns.len());
        for i in 0..self.conns.len() {
            let pid = self.conns[i].pid;
            let p = PROFILES.iter().find(|p| p.pid == pid).unwrap();
            let n = p.remotes.len() as f64;
            let on = p.burst_period == 0 || (self.tick / p.burst_period) % 2 == 0;
            let wobble = 0.7 + 0.6 * self.rand();
            let spiking = p.spike_every > 0 && self.tick % p.spike_every >= p.spike_every - SPIKE_TICKS;
            let scale = if on { 1.0 } else { 0.05 } * wobble * self.conns[i].weight * dt / n;
            let up_scale = if spiking { 400.0 } else { 1.0 };
            wanted.push((p.up * scale * up_scale, p.down * scale));
        }

        // Apply the policy the enforcer installed.
        let policy = self.policy.lock().unwrap();
        let views: Vec<Connection> = self.conns.iter().map(|c| to_conn(c, None)).collect();
        let mut limit_use: HashMap<RuleId, (f64, f64, Vec<usize>)> = HashMap::new();
        for (i, conn) in views.iter().enumerate() {
            let ctx = MatchCtx { conn, process: processes.get(&self.conns[i].pid) };
            let decision = policy.rules.decide(&ctx, &policy.exhausted);
            if decision.blocked {
                wanted[i] = (0.0, 0.0);
                continue;
            }
            for id in decision.limits {
                let e = limit_use.entry(id).or_insert((0.0, 0.0, vec![]));
                e.0 += wanted[i].0;
                e.1 += wanted[i].1;
                e.2.push(i);
            }
        }
        for (id, (up, down, members)) in limit_use {
            if let Some(Action::Limit { download, upload }) = policy.rules.get(id).map(|r| &r.action) {
                let fu = upload.map_or(1.0, |r| (r.0 as f64 * dt / up.max(1.0)).min(1.0));
                let fd = download.map_or(1.0, |r| (r.0 as f64 * dt / down.max(1.0)).min(1.0));
                for i in members {
                    wanted[i].0 *= fu;
                    wanted[i].1 *= fd;
                }
            }
        }
        drop(policy);

        let mut connections = Vec::with_capacity(self.conns.len());
        for (c, (up, down)) in self.conns.iter_mut().zip(wanted) {
            c.sent += up as u64;
            c.recv += down as u64;
            self.iface.0 += up as u64 + 40;
            self.iface.1 += down as u64 + 40;
            connections.push(to_conn(c, Some(20_000 + (c.key.cookie % 7) as u32 * 9_000)));
        }

        Ok(Snapshot {
            mono_ms: now_ms,
            processes,
            connections,
            interfaces: vec![InterfaceCounters {
                name: "eth0".into(),
                tx_bytes: self.iface.0,
                rx_bytes: self.iface.1,
            }],
        })
    }
}

/// Host names for the simulated remote addresses (stands in for reverse DNS
/// in demo mode, so the demo works offline).
/// The domains the demo apps "looked up", as if DNS answers had been seen.
pub fn demo_dns() -> Vec<nwl_core::dns::Answer> {
    [
        ("142.250.74.78", "www.google.com"),
        ("151.101.1.140", "www.reddit.com"),
        ("2a00:1450:4001:82b::200e", "www.youtube.com"),
        ("23.62.226.10", "cdn.steamstatic.com"),
        ("155.133.248.39", "cm.steampowered.com"),
        ("162.159.135.234", "discord.com"),
        ("35.214.203.66", "frankfurt.discord.media"),
        ("35.186.224.25", "audio-ak.spotifycdn.com"),
        ("162.125.19.131", "content.dropboxapi.com"),
        ("52.219.170.33", "backups.s3.eu-central-1.amazonaws.com"),
    ]
    .into_iter()
    .map(|(ip, name)| nwl_core::dns::Answer {
        ip: ip.parse().expect("valid demo address"),
        names: vec![name.to_string()],
        ttl: 6 * 3600,
    })
    .collect()
}

pub fn demo_hostname(ip: std::net::IpAddr) -> Option<String> {
    let name = match ip.to_string().as_str() {
        "142.250.74.78" => "fra24s06-in-f14.1e100.net",
        "151.101.1.140" => "reddit.map.fastly.net",
        "2a00:1450:4001:82b::200e" => "fra16s48-in-x0e.1e100.net",
        "23.62.226.10" => "a23-62-226-10.deploy.static.akamaitechnologies.com",
        "155.133.248.39" => "ext1-fra1.steamserver.net",
        "162.159.135.234" => "discord.com",
        "35.214.203.66" => "66.203.214.35.bc.googleusercontent.com",
        "35.186.224.25" => "25.224.186.35.bc.googleusercontent.com",
        "162.125.19.131" => "edge-block-www-env.dropbox-dns.com",
        "1.1.1.1" => "one.one.one.one",
        "52.219.170.33" => "s3-r-w.eu-central-1.amazonaws.com",
        _ => return None,
    };
    Some(name.to_string())
}

fn to_conn(c: &SimConn, rtt_us: Option<u32>) -> Connection {
    Connection {
        key: c.key.clone(),
        state: (c.key.protocol == Protocol::Tcp).then_some(TcpState::Established),
        pid: Some(c.pid),
        uid: Some(1000),
        bytes_sent: Some(c.sent),
        bytes_recv: Some(c.recv),
        rtt_us,
        closed: false,
    }
}

pub struct SimulatedEnforcer {
    policy: Arc<Mutex<SharedPolicy>>,
}

impl Enforcer for SimulatedEnforcer {
    fn name(&self) -> &'static str {
        "simulated"
    }

    fn apply(&mut self, policy: &Policy<'_>) -> Result<EnforceReport> {
        let mut shared = self.policy.lock().unwrap();
        let changed = shared.rules != *policy.rules || shared.exhausted != policy.exhausted_quotas;
        shared.rules = policy.rules.clone();
        shared.exhausted = policy.exhausted_quotas.to_vec();
        Ok(EnforceReport { changed, warnings: vec![] })
    }

    fn clear(&mut self) -> Result<()> {
        *self.policy.lock().unwrap() = SharedPolicy::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nwl_core::accounting::Accountant;

    fn run(mon: &mut SimulatedMonitor, acc: &mut Accountant, ticks: u64) {
        for i in 1..=ticks {
            // Pretend 1 s elapsed per tick regardless of wall time.
            mon.start = Instant::now() - std::time::Duration::from_secs(mon.tick + 1);
            let _ = i;
            let snap = mon.snapshot().unwrap();
            acc.ingest(&snap);
        }
    }

    #[test]
    fn rules_shape_simulated_traffic() {
        let (mut mon, mut enf) = simulated();
        let mut acc = Accountant::new(10, 60_000);
        run(&mut mon, &mut acc, 3);
        let steam = |acc: &Accountant| acc.apps().find(|a| a.name == "steam").unwrap().rate_down;
        assert!(steam(&acc) > 2_000_000, "steam downloads fast by default: {}", steam(&acc));

        let rules = RuleSet::new(vec![serde_json::from_str(
            r#"{"match":{"app":"steam"},"action":{"type":"limit","download":"500kB/s"}}"#,
        )
        .unwrap()])
        .unwrap();
        let snap = Snapshot::default();
        enf.apply(&Policy { rules: &rules, exhausted_quotas: &[], snapshot: &snap }).unwrap();
        run(&mut mon, &mut acc, 3);
        assert!(steam(&acc) <= 520_000, "limited: {}", steam(&acc));

        let block = RuleSet::new(vec![serde_json::from_str(
            r#"{"match":{"app":"steam"},"action":{"type":"block"}}"#,
        )
        .unwrap()])
        .unwrap();
        enf.apply(&Policy { rules: &block, exhausted_quotas: &[], snapshot: &snap }).unwrap();
        run(&mut mon, &mut acc, 3);
        assert_eq!(steam(&acc), 0);
    }
}
