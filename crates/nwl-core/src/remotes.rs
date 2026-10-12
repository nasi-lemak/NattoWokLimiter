//! "Who is this app talking to?": bytes per remote address per application.

use crate::model::{AppId, Protocol};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

/// Traffic exchanged with one remote address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteStats {
    pub up: u64,
    pub down: u64,
    /// Remote ports seen, at most [`MAX_PORTS`].
    pub ports: BTreeSet<u16>,
    pub protocols: BTreeSet<Protocol>,
    /// Monotonic ms of the last traffic.
    pub last_seen_ms: u64,
}

pub const MAX_PORTS: usize = 16;

impl RemoteStats {
    pub fn total(&self) -> u64 {
        self.up + self.down
    }
}

/// Bounded per-application remote statistics for the session.
pub struct RemoteTracker {
    max_per_app: usize,
    per_app: HashMap<AppId, HashMap<IpAddr, RemoteStats>>,
}

/// IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is the same host as `1.2.3.4`.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

impl RemoteTracker {
    pub fn new(max_per_app: usize) -> Self {
        Self { max_per_app: max_per_app.max(1), per_app: HashMap::new() }
    }

    pub fn record(
        &mut self,
        app: &AppId,
        remote: std::net::SocketAddr,
        protocol: Protocol,
        up: u64,
        down: u64,
        now_ms: u64,
    ) {
        let remotes = self.per_app.entry(app.clone()).or_default();
        let ip = canonical(remote.ip());
        if !remotes.contains_key(&ip) && remotes.len() >= self.max_per_app {
            // Make room by forgetting the remote with the least traffic.
            if let Some(smallest) =
                remotes.iter().min_by_key(|(_, s)| (s.total(), s.last_seen_ms)).map(|(ip, _)| *ip)
            {
                remotes.remove(&smallest);
            }
        }
        let stats = remotes.entry(ip).or_default();
        stats.up += up;
        stats.down += down;
        if stats.ports.len() < MAX_PORTS || stats.ports.contains(&remote.port()) {
            stats.ports.insert(remote.port());
        }
        stats.protocols.insert(protocol);
        stats.last_seen_ms = now_ms;
    }

    /// Remotes of one app, most traffic first.
    pub fn of_app(&self, app: &AppId) -> Vec<(IpAddr, &RemoteStats)> {
        let mut out: Vec<_> = self.per_app.get(app).into_iter().flatten().map(|(ip, s)| (*ip, s)).collect();
        out.sort_by_key(|(ip, s)| (std::cmp::Reverse(s.total()), *ip));
        out
    }

    /// Remotes across all apps, merged per address, most traffic first, with
    /// the apps that talked to each.
    pub fn all(&self) -> Vec<(IpAddr, RemoteStats, Vec<AppId>)> {
        let mut merged: HashMap<IpAddr, (RemoteStats, Vec<AppId>)> = HashMap::new();
        for (app, remotes) in &self.per_app {
            for (ip, s) in remotes {
                let (m, apps) = merged.entry(*ip).or_default();
                m.up += s.up;
                m.down += s.down;
                m.ports.extend(s.ports.iter().copied().take(MAX_PORTS.saturating_sub(m.ports.len())));
                m.protocols.extend(&s.protocols);
                m.last_seen_ms = m.last_seen_ms.max(s.last_seen_ms);
                apps.push(app.clone());
            }
        }
        let mut out: Vec<_> = merged
            .into_iter()
            .map(|(ip, (s, mut apps))| {
                apps.sort();
                (ip, s, apps)
            })
            .collect();
        out.sort_by_key(|(ip, s, _)| (std::cmp::Reverse(s.total()), *ip));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(s: &str) -> AppId {
        AppId(s.into())
    }

    #[test]
    fn aggregates_per_app_and_overall() {
        let mut t = RemoteTracker::new(10);
        let (ff, curl) = (app("/usr/bin/firefox"), app("/usr/bin/curl"));
        t.record(&ff, "1.1.1.1:443".parse().unwrap(), Protocol::Tcp, 10, 100, 1);
        t.record(&ff, "[::ffff:1.1.1.1]:443".parse().unwrap(), Protocol::Udp, 5, 50, 2);
        t.record(&ff, "8.8.8.8:53".parse().unwrap(), Protocol::Udp, 1, 1, 3);
        t.record(&curl, "1.1.1.1:80".parse().unwrap(), Protocol::Tcp, 1000, 0, 4);

        let mine = t.of_app(&ff);
        assert_eq!(mine.len(), 2, "mapped IPv6 merges with IPv4");
        assert_eq!(mine[0].0, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!((mine[0].1.up, mine[0].1.down), (15, 150));
        assert_eq!(mine[0].1.protocols.len(), 2);

        let all = t.all();
        assert_eq!(all[0].0, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(all[0].1.total(), 1165);
        assert_eq!(all[0].1.ports.iter().copied().collect::<Vec<_>>(), vec![80, 443]);
        assert_eq!(all[0].2, vec![curl, ff]);
    }

    #[test]
    fn bounded_per_app() {
        let mut t = RemoteTracker::new(2);
        let a = app("a");
        t.record(&a, "1.0.0.1:1".parse().unwrap(), Protocol::Tcp, 100, 0, 1);
        t.record(&a, "1.0.0.2:1".parse().unwrap(), Protocol::Tcp, 5, 0, 2);
        t.record(&a, "1.0.0.3:1".parse().unwrap(), Protocol::Tcp, 50, 0, 3);
        let ips: Vec<String> = t.of_app(&a).iter().map(|(ip, _)| ip.to_string()).collect();
        assert_eq!(ips, vec!["1.0.0.1", "1.0.0.3"], "the smallest remote was dropped");
        for p in 0..40 {
            t.record(&a, format!("1.0.0.1:{p}").parse().unwrap(), Protocol::Tcp, 1, 0, 4);
        }
        assert_eq!(t.of_app(&a)[0].1.ports.len(), MAX_PORTS);
    }
}
