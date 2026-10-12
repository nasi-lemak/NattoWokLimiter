//! The daemon's brain: ingests snapshots, keeps statistics, quotas, usage
//! history and events, and produces the policy the enforcer applies.
//! Free of I/O except through [`Store`], so it is tested with simulated data.

use crate::store::{KnownApps, Store, UsageDb};
use chrono::{DateTime, Datelike, Local};
use nwl_core::accounting::Accountant;
use nwl_core::model::{AppId, ConnKey, Connection, Direction, ProcessInfo, Snapshot};
use nwl_core::quota::{QuotaStatus, QuotaTracker};
use nwl_core::rules::{Action, MatchCtx, Period, Rule, RuleError, RuleId, RuleSet};
use nwl_platform::{EnforceReport, Policy};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};

const RULES: &str = "rules.json";
const QUOTAS: &str = "quotas.json";
const USAGE: &str = "usage.json";
const KNOWN_APPS: &str = "known_apps.json";
const MAX_EVENTS: usize = 500;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// An application used the network for the first time.
    NewApp {
        app: AppId,
        name: String,
    },
    QuotaExhausted {
        rule: RuleId,
        name: String,
    },
    RuleAdded {
        rule: RuleId,
        name: String,
    },
    RuleChanged {
        rule: RuleId,
        name: String,
    },
    RuleRemoved {
        rule: RuleId,
        name: String,
    },
    EnforcementError {
        message: String,
    },
    EnforcementRecovered,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub id: u64,
    /// Unix time in milliseconds.
    pub time: i64,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EnforcementStatus {
    pub monitor: String,
    pub enforcer: String,
    pub enforcing: bool,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

pub struct Engine {
    /// Count localhost traffic in app statistics, usage and quotas.
    count_loopback: bool,
    store: Store,
    pub rules: RuleSet,
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

/// An application row in the UI.
#[derive(Debug, Clone, Serialize)]
pub struct AppView {
    pub app: AppId,
    pub name: String,
    pub pids: Vec<u32>,
    pub connections: usize,
    pub rate_up: u64,
    pub rate_down: u64,
    pub total_up: u64,
    pub total_down: u64,
    /// Recent `(up, down)` rate samples; omitted in live updates.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<(u64, u64)>,
    /// Rules scoped to this app.
    pub rules: Vec<RuleId>,
    /// The app-wide block rule, if any (what the UI's block toggle controls).
    pub block_rule: Option<RuleId>,
    /// The app-wide limit rule, if any.
    pub limit_rule: Option<RuleId>,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnView {
    #[serde(flatten)]
    pub conn: Connection,
    pub app: Option<AppId>,
    pub name: Option<String>,
    pub rate_up: u64,
    pub rate_down: u64,
    pub blocked: bool,
    pub access_rule: Option<RuleId>,
    pub limits: Vec<RuleId>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub mono_ms: u64,
    pub system: nwl_core::accounting::SystemStats,
    pub apps: Vec<AppView>,
    pub quotas: Vec<QuotaStatus>,
    pub status: EnforcementStatus,
    pub last_event: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageDay {
    pub day: String,
    pub apps: Vec<UsageEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageEntry {
    pub app: AppId,
    pub name: String,
    pub up: u64,
    pub down: u64,
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
            next_event_id: 1,
            status: EnforcementStatus::default(),
            period_keys: BTreeMap::new(),
            suppress_new_app_events,
            dirty: false,
        })
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

    pub fn ingest(&mut self, snap: Snapshot, now: DateTime<Local>) {
        for p in [Period::Day, Period::Week, Period::Month] {
            self.period_keys.insert(period_name(p), period_key(p, &now));
        }
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
            }
            let Some(conn) = conns.get(&d.key) else { continue };
            let ctx = MatchCtx { conn, process: snap.process_of(conn) };
            for id in self.rules.decide(&ctx, &[]).quotas {
                if let Some(Action::Quota { period, direction, .. }) = self.rules.get(id).map(|r| &r.action) {
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
            self.quotas.status(&self.rules, |p| keys.get(period_name(p)).cloned().unwrap_or_default());
        let exhausted: Vec<RuleId> = status.iter().filter(|s| s.exhausted).map(|s| s.rule).collect();
        for id in &exhausted {
            if !self.exhausted.contains(id) {
                let name = self.rules.get(*id).map(|r| r.name.clone()).unwrap_or_default();
                self.push_event(EventKind::QuotaExhausted { rule: *id, name });
            }
        }
        self.exhausted = exhausted;
    }

    pub fn policy(&self) -> Policy<'_> {
        Policy { rules: &self.rules, exhausted_quotas: &self.exhausted, snapshot: &self.snapshot }
    }

    pub fn record_enforcement(&mut self, result: Result<EnforceReport, String>) {
        match result {
            Ok(report) => {
                if self.status.error.take().is_some() {
                    self.push_event(EventKind::EnforcementRecovered);
                }
                self.status.warnings = report.warnings;
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
                let block_rule = scoped
                    .iter()
                    .find(|r| app_only(r) && matches!(r.action, Action::Block { direction: Direction::Both }))
                    .map(|r| r.id);
                let limit_rule = scoped
                    .iter()
                    .find(|r| app_only(r) && matches!(r.action, Action::Limit { .. }))
                    .map(|r| r.id);
                let quota_blocked = scoped.iter().any(|r| app_only(r) && self.exhausted.contains(&r.id));
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
                    blocked: block_rule.is_some() || quota_blocked,
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
            .filter_map(|conn| {
                let process = self.snapshot.process_of(conn);
                let app_id = process.map(|p| p.app_id());
                if let Some(filter) = app {
                    if app_id.as_ref().map(|a| a.0.as_str()) != Some(filter) {
                        return None;
                    }
                }
                let decision = self.rules.decide(&MatchCtx { conn, process }, &self.exhausted);
                let (rate_up, rate_down) = self.conn_rates.get(&conn.key).copied().unwrap_or((0, 0));
                Some(ConnView {
                    conn: conn.clone(),
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
        e.add_rule(serde_json::from_str(r#"{"name":"x","action":{"type":"allow"}}"#).unwrap()).unwrap();
        e.save().unwrap();

        let mut e = Engine::new(Store::open(dir.clone()).unwrap(), 10).unwrap();
        assert_eq!(e.rules.rules.len(), 1);
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
    fn period_keys() {
        let t = at(12);
        assert_eq!(period_key(Period::Day, &t), "2026-10-12");
        assert_eq!(period_key(Period::Week, &t), "2026-W42");
        assert_eq!(period_key(Period::Month, &t), "2026-10");
    }
}
