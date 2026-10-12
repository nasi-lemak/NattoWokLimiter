//! The daemon's brain: ingests snapshots, keeps statistics, quotas, usage
//! history and events, and produces the policy the enforcer applies.
//! Free of I/O except through [`Store`], so it is tested with simulated data.

use crate::resolver::Resolver;
use crate::store::{KnownApps, Store, UsageDb};
use chrono::{DateTime, Datelike, Local, Timelike};
use nwl_core::accounting::Accountant;
use nwl_core::api::{
    AppView, ConnView, EnforcementStatus, Event, EventKind, Overview, RemoteView, UsageDay, UsageEntry,
};
use nwl_core::model::{AppId, ConnKey, Connection, Direction, ProcessInfo, Snapshot};
use nwl_core::quota::{QuotaStatus, QuotaTracker};
use nwl_core::remotes::{RemoteStats, RemoteTracker};
use nwl_core::rules::{Action, Day, MatchCtx, Period, Rule, RuleError, RuleId, RuleSet};
use nwl_platform::{EnforceReport, Policy};
use std::collections::{BTreeMap, HashMap, VecDeque};

const RULES: &str = "rules.json";
const QUOTAS: &str = "quotas.json";
const USAGE: &str = "usage.json";
const KNOWN_APPS: &str = "known_apps.json";
const MAX_EVENTS: usize = 500;

pub struct Engine {
    /// Count localhost traffic in app statistics, usage and quotas.
    count_loopback: bool,
    resolver: Option<Resolver>,
    /// Bytes per remote address per app, for this session.
    remotes: RemoteTracker,
    store: Store,
    /// Rules as configured.
    pub rules: RuleSet,
    /// `rules` with schedules applied for the current local time; this is
    /// what decisions, quotas and enforcement use.
    effective: RuleSet,
    /// Local weekday and minute of the last tick.
    clock: Option<(Day, u16)>,
    /// Quota rule -> period in which its 80% warning was raised.
    warned: HashMap<RuleId, String>,
    accountant: Accountant,
    quotas: QuotaTracker,
    usage: UsageDb,
    known_apps: KnownApps,
    snapshot: Snapshot,
    /// Per-connection rate (up, down) in bytes/s over the last tick.
    conn_rates: HashMap<ConnKey, (u64, u64)>,
    /// A representative process per app, for matching app patterns.
    app_samples: HashMap<AppId, ProcessInfo>,
    exhausted: Vec<RuleId>,
    events: VecDeque<Event>,
    next_event_id: u64,
    pub status: EnforcementStatus,
    /// Warnings fixed at startup (degraded backends), shown alongside the
    /// enforcer's per-tick warnings.
    startup_warnings: Vec<String>,
    period_keys: BTreeMap<&'static str, String>,
    /// On the very first run every app is "new"; don't flood the event log.
    suppress_new_app_events: bool,
    dirty: bool,
}

pub fn period_key(period: Period, now: &DateTime<Local>) -> String {
    match period {
        Period::Day => now.format("%Y-%m-%d").to_string(),
        Period::Week => {
            let w = now.iso_week();
            format!("{}-W{:02}", w.year(), w.week())
        }
        Period::Month => now.format("%Y-%m").to_string(),
    }
}

fn period_name(p: Period) -> &'static str {
    match p {
        Period::Day => "day",
        Period::Week => "week",
        Period::Month => "month",
    }
}

/// A matcher that only selects an application (the UI's one-click rules).
fn app_only(rule: &Rule) -> bool {
    let m = &rule.matcher;
    m.app.is_some()
        && m.protocol.is_none()
        && m.remote.is_empty()
        && m.remote_ports.is_empty()
        && m.local_ports.is_empty()
        && m.uid.is_none()
}

impl Engine {
    pub fn new(store: Store, history_len: usize) -> anyhow::Result<Self> {
        let rules: Vec<Rule> = store.load(RULES)?.unwrap_or_default();
        let rules = RuleSet::new(rules).map_err(|e| anyhow::anyhow!("{RULES}: {e}"))?;
        let suppress_new_app_events = !store.exists(KNOWN_APPS);
        Ok(Self {
            count_loopback: false,
            resolver: None,
            remotes: RemoteTracker::new(1000),
            effective: rules.clone(),
            clock: None,
            warned: HashMap::new(),
            rules,
            accountant: Accountant::new(history_len, 5 * 60 * 1000),
            quotas: store.load(QUOTAS)?.unwrap_or_default(),
            usage: store.load(USAGE)?.unwrap_or_default(),
            known_apps: store.load(KNOWN_APPS)?.unwrap_or_default(),
            store,
            snapshot: Snapshot::default(),
            conn_rates: HashMap::new(),
            app_samples: HashMap::new(),
            exhausted: Vec::new(),
            events: VecDeque::new(),
            // Event ids keep increasing across restarts (clients poll with
            // `after=<last id seen>`), with room for a million events a second.
            next_event_id: (chrono::Utc::now().timestamp().max(1) as u64) * 1_000_000,
            status: EnforcementStatus::default(),
            startup_warnings: Vec::new(),
            period_keys: BTreeMap::new(),
            suppress_new_app_events,
            dirty: false,
        })
    }

    pub fn add_startup_warning(&mut self, warning: String) {
        self.status.warnings.push(warning.clone());
        self.startup_warnings.push(warning);
    }

    pub fn set_resolver(&mut self, resolver: Resolver) {
        self.resolver = Some(resolver);
    }

    pub fn set_count_loopback(&mut self, on: bool) {
        self.count_loopback = on;
        self.accountant.count_loopback = on;
    }

    fn push_event(&mut self, kind: EventKind) {
        let event = Event { id: self.next_event_id, time: chrono::Utc::now().timestamp_millis(), kind };
        self.next_event_id += 1;
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn key_for(&self, period: Period) -> String {
        self.period_keys.get(period_name(period)).cloned().unwrap_or_default()
    }

    fn refresh_effective(&mut self) {
        self.effective = match self.clock {
            Some((day, minute)) => self.rules.effective_at(day, minute),
            None => self.rules.clone(),
        };
    }

    pub fn ingest(&mut self, snap: Snapshot, now: DateTime<Local>) {
        for p in [Period::Day, Period::Week, Period::Month] {
            self.period_keys.insert(period_name(p), period_key(p, &now));
        }
        let day = Day::from_index(now.weekday().num_days_from_monday() as usize);
        self.clock = Some((day, (now.hour() * 60 + now.minute()) as u16));
        self.refresh_effective();
        let day = self.key_for(Period::Day);
        let elapsed_ms = snap.mono_ms.saturating_sub(self.snapshot.mono_ms).max(1);
        let deltas = self.accountant.ingest(&snap);

        let conns: HashMap<&ConnKey, &Connection> = snap.connections.iter().map(|c| (&c.key, c)).collect();
        self.conn_rates.clear();
        for d in &deltas {
            self.conn_rates.insert(d.key.clone(), (d.up * 1000 / elapsed_ms, d.down * 1000 / elapsed_ms));
            if d.loopback && !self.count_loopback {
                continue;
            }
            if let Some(app) = &d.app {
                self.usage.record(&day, app, d.up, d.down);
                if let Some(remote) = d.key.remote {
                    self.remotes.record(app, remote, d.key.protocol, d.up, d.down, snap.mono_ms);
                }
            }
            let Some(conn) = conns.get(&d.key) else { continue };
            let ctx = MatchCtx { conn, process: snap.process_of(conn) };
            for id in self.effective.decide(&ctx, &[]).quotas {
                if let Some(Action::Quota { period, direction, .. }) =
                    self.effective.get(id).map(|r| &r.action)
                {
                    let bytes = match direction {
                        Direction::In => d.down,
                        Direction::Out => d.up,
                        Direction::Both => d.up + d.down,
                    };
                    let key = self.key_for(*period);
                    self.quotas.record(id, &key, bytes);
                }
            }
        }

        let mut new_apps = Vec::new();
        for process in snap.processes.values() {
            let app = process.app_id();
            if self.known_apps.insert(app.clone()) && !self.suppress_new_app_events {
                new_apps.push((app.clone(), app.display_name().to_string()));
            }
            self.app_samples.insert(app, process.clone());
        }
        self.suppress_new_app_events = false;
        for (app, name) in new_apps {
            self.push_event(EventKind::NewApp { app, name });
        }
        self.app_samples.retain(|app, _| self.accountant.apps().any(|a| &a.app == app));

        self.refresh_exhausted();
        self.snapshot = snap;
        self.dirty = true;
    }

    fn refresh_exhausted(&mut self) {
        let keys = self.period_keys.clone();
        let status =
            self.quotas.status(&self.effective, |p| keys.get(period_name(p)).cloned().unwrap_or_default());
        let mut exhausted = Vec::new();
        for s in &status {
            let name = self.rules.get(s.rule).map(|r| r.name.clone()).unwrap_or_default();
            if s.exhausted {
                exhausted.push(s.rule);
                if !self.exhausted.contains(&s.rule) {
                    self.push_event(EventKind::QuotaExhausted { rule: s.rule, name });
                }
            } else if s.used * 10 >= s.limit * 8 && self.warned.get(&s.rule) != Some(&s.period_key) {
                self.warned.insert(s.rule, s.period_key.clone());
                self.push_event(EventKind::QuotaWarning { rule: s.rule, name, percent: 80 });
            }
        }
        self.exhausted = exhausted;
    }

    pub fn policy(&self) -> Policy<'_> {
        Policy { rules: &self.effective, exhausted_quotas: &self.exhausted, snapshot: &self.snapshot }
    }

    pub fn record_enforcement(&mut self, result: Result<EnforceReport, String>) {
        match result {
            Ok(report) => {
                if self.status.error.take().is_some() {
                    self.push_event(EventKind::EnforcementRecovered);
                }
                self.status.warnings = self.startup_warnings.iter().cloned().chain(report.warnings).collect();
            }
            Err(message) => {
                if self.status.error.as_deref() != Some(message.as_str()) {
                    self.push_event(EventKind::EnforcementError { message: message.clone() });
                }
                self.status.error = Some(message);
            }
        }
    }

    /// Persists statistics if they changed. Rules are saved on every change.
    pub fn save(&mut self) -> anyhow::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.store.save(QUOTAS, &self.quotas)?;
        self.store.save(USAGE, &self.usage)?;
        self.store.save(KNOWN_APPS, &self.known_apps)?;
        self.dirty = false;
        Ok(())
    }

    fn save_rules(&self) -> anyhow::Result<()> {
        self.store.save(RULES, &self.rules.rules)
    }

    pub fn add_rule(&mut self, rule: Rule) -> Result<RuleId, RuleError> {
        let id = self.rules.add(rule)?;
        self.rules_changed();
        let name = self.rules.get(id).map(|r| r.name.clone()).unwrap_or_default();
        self.push_event(EventKind::RuleAdded { rule: id, name });
        Ok(id)
    }

    pub fn replace_rule(&mut self, id: RuleId, rule: Rule) -> Result<(), RuleError> {
        let name = rule.name.clone();
        self.rules.replace(id, rule)?;
        self.rules_changed();
        self.push_event(EventKind::RuleChanged { rule: id, name });
        Ok(())
    }

    pub fn remove_rule(&mut self, id: RuleId) -> Result<Rule, RuleError> {
        let rule = self.rules.remove(id)?;
        self.rules_changed();
        self.push_event(EventKind::RuleRemoved { rule: id, name: rule.name.clone() });
        Ok(rule)
    }

    /// Moves a rule to `index` in evaluation order.
    pub fn move_rule(&mut self, id: RuleId, index: usize) -> Result<(), RuleError> {
        let rule = self.rules.remove(id)?;
        let index = index.min(self.rules.rules.len());
        self.rules.rules.insert(index, rule);
        self.rules_changed();
        Ok(())
    }

    fn rules_changed(&mut self) {
        self.quotas.retain_rules(&self.rules);
        self.warned.retain(|id, _| self.rules.get(*id).is_some());
        self.refresh_effective();
        self.refresh_exhausted();
        if let Err(e) = self.save_rules() {
            tracing::error!("saving rules: {e:#}");
        }
    }

    pub fn apps(&self) -> Vec<AppView> {
        let mut apps: Vec<AppView> = self
            .accountant
            .apps()
            .map(|s| {
                let sample = self.app_samples.get(&s.app);
                let scoped: Vec<&Rule> = self
                    .rules
                    .enabled()
                    .filter(|r| match (&r.matcher.app, sample) {
                        (Some(p), Some(proc_)) => p.matches_process(proc_),
                        (Some(p), None) => p.matches_app(&s.app),
                        (None, _) => false,
                    })
                    .collect();
                // The one-click toggles control unscheduled app-wide rules.
                let one_click = |r: &&&Rule| app_only(r) && r.schedule.is_none();
                let block_rule = scoped
                    .iter()
                    .filter(one_click)
                    .find(|r| matches!(r.action, Action::Block { direction: Direction::Both }))
                    .map(|r| r.id);
                let limit_rule = scoped
                    .iter()
                    .filter(one_click)
                    .find(|r| matches!(r.action, Action::Limit { .. }))
                    .map(|r| r.id);
                let active = |r: &&&Rule| self.effective.get(r.id).is_some_and(|e| e.enabled);
                let blocked = scoped.iter().filter(active).any(|r| {
                    app_only(r)
                        && (matches!(r.action, Action::Block { direction: Direction::Both })
                            || self.exhausted.contains(&r.id))
                });
                AppView {
                    app: s.app.clone(),
                    name: s.name.clone(),
                    pids: s.pids.iter().copied().collect(),
                    connections: s.connections,
                    rate_up: s.rate_up,
                    rate_down: s.rate_down,
                    total_up: s.total_up,
                    total_down: s.total_down,
                    history: s.history.samples().collect(),
                    rules: scoped.iter().map(|r| r.id).collect(),
                    block_rule,
                    limit_rule,
                    blocked,
                }
            })
            .collect();
        apps.sort_by(|a, b| {
            (b.rate_up + b.rate_down)
                .cmp(&(a.rate_up + a.rate_down))
                .then((b.total_up + b.total_down).cmp(&(a.total_up + a.total_down)))
                .then(a.name.cmp(&b.name))
        });
        apps
    }

    pub fn connections(&self, app: Option<&str>) -> Vec<ConnView> {
        let mut out: Vec<ConnView> = self
            .snapshot
            .connections
            .iter()
            // Closed sockets are only reported so their last bytes count.
            .filter(|conn| !conn.closed)
            .filter_map(|conn| {
                let process = self.snapshot.process_of(conn);
                let app_id = process.map(|p| p.app_id());
                if let Some(filter) = app {
                    if app_id.as_ref().map(|a| a.0.as_str()) != Some(filter) {
                        return None;
                    }
                }
                let decision = self.effective.decide(&MatchCtx { conn, process }, &self.exhausted);
                let (rate_up, rate_down) = self.conn_rates.get(&conn.key).copied().unwrap_or((0, 0));
                let remote_host =
                    self.resolver.as_ref().zip(conn.key.remote).and_then(|(r, addr)| r.lookup(addr.ip()));
                Some(ConnView {
                    conn: conn.clone(),
                    remote_host,
                    name: app_id.as_ref().map(|a| a.display_name().to_string()),
                    app: app_id,
                    rate_up,
                    rate_down,
                    blocked: decision.blocked,
                    access_rule: decision.access_rule,
                    limits: decision.limits,
                })
            })
            .collect();
        out.sort_by(|a, b| {
            (b.rate_up + b.rate_down).cmp(&(a.rate_up + a.rate_down)).then(a.conn.key.cmp(&b.conn.key))
        });
        out
    }

    /// Remote addresses by traffic: of one app (full path), or of all apps.
    pub fn remotes(&self, app: Option<&str>, limit: usize) -> Vec<RemoteView> {
        let canonical = |ip: std::net::IpAddr| match ip {
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        let open = |ip: std::net::IpAddr, app: Option<&AppId>| {
            self.snapshot
                .connections
                .iter()
                .filter(|c| !c.closed && c.key.remote.is_some_and(|r| canonical(r.ip()) == ip))
                .filter(|c| app.is_none() || self.snapshot.process_of(c).map(|p| p.app_id()).as_ref() == app)
                .count()
        };
        let view = |ip, s: &RemoteStats, apps: Vec<AppId>, app: Option<&AppId>| RemoteView {
            ip,
            host: self.resolver.as_ref().and_then(|r| r.lookup(ip)),
            up: s.up,
            down: s.down,
            ports: s.ports.iter().copied().collect(),
            protocols: s.protocols.iter().copied().collect(),
            apps,
            open_connections: open(ip, app),
            idle_secs: self.snapshot.mono_ms.saturating_sub(s.last_seen_ms) / 1000,
        };
        match app {
            Some(path) => {
                let app = AppId(path.to_string());
                self.remotes
                    .of_app(&app)
                    .into_iter()
                    .take(limit)
                    .map(|(ip, s)| view(ip, s, vec![], Some(&app)))
                    .collect()
            }
            None => self
                .remotes
                .all()
                .into_iter()
                .take(limit)
                .map(|(ip, s, apps)| view(ip, &s, apps, None))
                .collect(),
        }
    }

    pub fn quota_status(&self) -> Vec<QuotaStatus> {
        let keys = &self.period_keys;
        self.quotas.status(&self.rules, |p| keys.get(period_name(p)).cloned().unwrap_or_default())
    }

    pub fn events_since(&self, after: u64) -> Vec<Event> {
        self.events.iter().filter(|e| e.id > after).cloned().collect()
    }

    pub fn usage(&self, days: usize) -> Vec<UsageDay> {
        self.usage
            .last_days(days)
            .map(|(day, apps)| {
                let mut apps: Vec<UsageEntry> = apps
                    .iter()
                    .map(|(app, [up, down])| UsageEntry {
                        name: app.display_name().to_string(),
                        app: app.clone(),
                        up: *up,
                        down: *down,
                    })
                    .collect();
                apps.sort_by_key(|a| std::cmp::Reverse(a.up + a.down));
                UsageDay { day: day.clone(), apps }
            })
            .collect()
    }

    pub fn system_history(&self) -> Vec<(u64, u64)> {
        self.accountant.system_history().samples().collect()
    }

    /// Compact per-tick state for live updates (no per-app history).
    pub fn overview(&self) -> Overview {
        let mut apps = self.apps();
        for app in &mut apps {
            app.history = Vec::new();
        }
        Overview {
            mono_ms: self.snapshot.mono_ms,
            system: self.accountant.system().clone(),
            apps,
            quotas: self.quota_status(),
            status: self.status.clone(),
            last_event: self.next_event_id - 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use nwl_core::model::{ConnKey, Protocol};

    fn temp_store(tag: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("nwld-engine-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Store::open(dir).unwrap()
    }

    fn snap(ms: u64, sent: u64, recv: u64) -> Snapshot {
        let mut s = Snapshot { mono_ms: ms, ..Default::default() };
        s.processes.insert(
            9,
            ProcessInfo { pid: 9, name: "steam".into(), exe: Some("/opt/steam/steam".into()), uid: None },
        );
        s.connections.push(Connection {
            key: ConnKey {
                protocol: Protocol::Tcp,
                local: "10.0.0.2:5000".parse().unwrap(),
                remote: Some("1.2.3.4:443".parse().unwrap()),
                cookie: 1,
            },
            state: None,
            pid: Some(9),
            uid: None,
            bytes_sent: Some(sent),
            bytes_recv: Some(recv),
            rtt_us: None,
            closed: false,
        });
        s
    }

    fn at(day: u32) -> DateTime<Local> {
        Local.with_ymd_and_hms(2026, 10, day, 12, 0, 0).unwrap()
    }

    #[test]
    fn quota_exhausts_and_resets_next_day() {
        let mut e = Engine::new(temp_store("quota"), 10).unwrap();
        let id = e
            .add_rule(
                serde_json::from_str(
                    r#"{"name":"steam daily","match":{"app":"steam"},"action":{"type":"quota","limit":1000,"period":"day","direction":"in"}}"#,
                )
                .unwrap(),
            )
            .unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        e.ingest(snap(1000, 50, 600), at(12));
        assert!(e.policy().exhausted_quotas.is_empty());
        assert_eq!(e.quota_status()[0].used, 600);
        e.ingest(snap(2000, 100, 1200), at(12));
        assert_eq!(e.policy().exhausted_quotas, &[id]);
        assert!(e.apps()[0].blocked);
        assert!(e.connections(None)[0].blocked);
        assert!(e.events_since(0).iter().any(|ev| matches!(ev.kind, EventKind::QuotaExhausted { .. })));

        e.ingest(snap(3000, 100, 1300), at(13));
        assert!(e.policy().exhausted_quotas.is_empty(), "new day, new quota");
        assert_eq!(e.quota_status()[0].used, 100);
    }

    #[test]
    fn scheduled_rules_and_quota_warning() {
        let mut e = Engine::new(temp_store("schedule"), 10).unwrap();
        // 2026-10-12 is a Monday.
        e.add_rule(
            serde_json::from_str(
                r#"{"match":{"app":"steam"},"action":{"type":"block"},"schedule":{"days":["mon"],"from":"09:00","until":"13:00"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        e.ingest(snap(0, 0, 0), at(12)); // Monday 12:00: inside the window
        assert!(e.apps()[0].blocked);
        assert_eq!(e.apps()[0].block_rule, None, "scheduled rules are not one-click toggles");
        assert_eq!(e.policy().rules.enabled().count(), 1);
        e.ingest(snap(1000, 0, 0), Local.with_ymd_and_hms(2026, 10, 12, 14, 0, 0).unwrap());
        assert!(!e.apps()[0].blocked);
        assert_eq!(e.policy().rules.enabled().count(), 0);

        e.add_rule(
            serde_json::from_str(
                r#"{"match":{"app":"steam"},"action":{"type":"quota","limit":1000,"period":"day"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        e.ingest(snap(2000, 0, 850), at(12));
        e.ingest(snap(3000, 0, 900), at(12));
        let warnings =
            e.events_since(0).iter().filter(|ev| matches!(ev.kind, EventKind::QuotaWarning { .. })).count();
        assert_eq!(warnings, 1, "warned once per period");
    }

    #[test]
    fn usage_rates_and_app_rules() {
        let mut e = Engine::new(temp_store("usage"), 10).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        e.ingest(snap(500, 1000, 4000), at(12));
        let apps = e.apps();
        assert_eq!((apps[0].rate_up, apps[0].rate_down), (2000, 8000));
        assert_eq!(e.connections(Some("/opt/steam/steam"))[0].rate_down, 8000);
        assert!(e.connections(Some("/nope")).is_empty());
        let usage = e.usage(7);
        assert_eq!(usage[0].day, "2026-10-12");
        assert_eq!((usage[0].apps[0].up, usage[0].apps[0].down), (1000, 4000));

        let id = e
            .add_rule(
                serde_json::from_str(r#"{"match":{"app":"/opt/steam/steam"},"action":{"type":"block"}}"#)
                    .unwrap(),
            )
            .unwrap();
        let app = &e.apps()[0];
        assert_eq!(app.block_rule, Some(id));
        assert!(app.blocked);
        e.remove_rule(id).unwrap();
        assert!(!e.apps()[0].blocked);
    }

    #[test]
    fn state_persists_and_first_run_is_quiet() {
        let store = temp_store("persist");
        let dir = store.dir().to_path_buf();
        let mut e = Engine::new(store, 10).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        assert!(!e.events_since(0).iter().any(|ev| matches!(ev.kind, EventKind::NewApp { .. })));
        let before_restart = e.overview().last_event;
        e.add_rule(serde_json::from_str(r#"{"name":"x","action":{"type":"allow"}}"#).unwrap()).unwrap();
        e.save().unwrap();

        let mut e = Engine::new(Store::open(dir.clone()).unwrap(), 10).unwrap();
        assert_eq!(e.rules.rules.len(), 1);
        assert!(e.overview().last_event >= before_restart, "event ids never go backwards");
        let mut s = snap(0, 0, 0);
        s.processes.insert(
            10,
            ProcessInfo { pid: 10, name: "new".into(), exe: Some("/usr/bin/new".into()), uid: None },
        );
        e.ingest(s, at(12));
        let new: Vec<_> = e
            .events_since(0)
            .into_iter()
            .filter_map(|ev| match ev.kind {
                EventKind::NewApp { name, .. } => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(new, vec!["new".to_string()]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_warnings_survive_enforcement_reports() {
        let mut e = Engine::new(temp_store("warn"), 10).unwrap();
        e.add_startup_warning("eBPF unavailable".into());
        e.record_enforcement(Ok(EnforceReport { changed: false, warnings: vec!["rule 3: x".into()] }));
        assert_eq!(e.status.warnings, vec!["eBPF unavailable".to_string(), "rule 3: x".to_string()]);
        e.record_enforcement(Ok(EnforceReport::default()));
        assert_eq!(e.status.warnings, vec!["eBPF unavailable".to_string()]);
    }

    #[test]
    fn remotes_per_app() {
        let mut e = Engine::new(temp_store("remotes"), 10).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        e.ingest(snap(1000, 300, 2000), at(12));
        let r = e.remotes(Some("/opt/steam/steam"), 10);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].ip.to_string(), r[0].up, r[0].down), ("1.2.3.4".to_string(), 300, 2000));
        assert_eq!((r[0].ports.clone(), r[0].open_connections, r[0].idle_secs), (vec![443], 1, 0));
        let all = e.remotes(None, 10);
        assert_eq!(all[0].apps, vec![AppId("/opt/steam/steam".into())]);
        assert!(e.remotes(Some("/nope"), 10).is_empty());
    }

    #[test]
    fn period_keys() {
        let t = at(12);
        assert_eq!(period_key(Period::Day, &t), "2026-10-12");
        assert_eq!(period_key(Period::Week, &t), "2026-W42");
        assert_eq!(period_key(Period::Month, &t), "2026-10");
    }
}
