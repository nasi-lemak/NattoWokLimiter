//! The daemon's brain: ingests snapshots, keeps statistics, quotas, usage
//! history and events, and produces the policy the enforcer applies.
//! Free of I/O except through [`Store`], so it is tested with simulated data.

use crate::identity::{Fingerprint, Hasher};
use crate::resolver::Resolver;
use crate::store::{KnownApps, Store, UsageDb};
use chrono::{DateTime, Datelike, Local, Timelike};
use nwl_core::accounting::Accountant;
use nwl_core::api::{
    Answer, Backup, DaemonSettings, ImportResult, NetworkView, Prompt, BACKUP_FORMAT, BACKUP_VERSION,
};
use nwl_core::api::{
    AppView, ConnView, EnforcementStatus, Event, EventKind, Overview, RemoteView, UsageDay, UsageEntry,
};
use nwl_core::dns::DnsCache;
use nwl_core::model::{AppId, ConnKey, Connection, Direction, ProcessInfo, Snapshot};
use nwl_core::network::{Detected, Network, Overrides};
use nwl_core::quota::{QuotaStatus, QuotaTracker, QuotaUsage};
use nwl_core::remotes::{RemoteStats, RemoteTracker};
use nwl_core::rules::{Action, AppPattern, Day, MatchCtx, Matcher, Period, Rule, RuleError, RuleId, RuleSet};
use nwl_core::spikes::SpikeDetector;
use nwl_platform::appinfo::{AppCatalog, AppInfo};
use nwl_platform::{EnforceReport, Policy};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

const RULES: &str = "rules.json";
const QUOTAS: &str = "quotas.json";
const USAGE: &str = "usage.json";
const HISTORY: &str = "history.json";
const KNOWN_APPS: &str = "known_apps.json";
const NETWORK: &str = "network.json";
const SETTINGS: &str = "settings.json";
const IDENTITIES: &str = "identities.json";
/// How often an active app's program file is checked for changes.
const IDENTITY_CHECK_SECS: i64 = 60;
/// Ids of the temporary rules that hold apps waiting for an answer, far
/// above any user rule's.
const WAITING_RULE_BASE: RuleId = 1 << 48;
const MAX_EVENTS: usize = 500;

pub struct Engine {
    /// Count localhost traffic in app statistics, usage and quotas.
    count_loopback: bool,
    resolver: Option<Resolver>,
    /// Bytes per remote address per app, for this session.
    remotes: RemoteTracker,
    spikes: SpikeDetector,
    store: Store,
    /// Rules as configured.
    pub rules: RuleSet,
    /// What the enforcer gets while paused.
    no_rules: RuleSet,
    /// `rules` with schedules applied for the current local time; this is
    /// what decisions, quotas and enforcement use.
    effective: RuleSet,
    /// Local weekday and minute of the last tick.
    clock: Option<(Day, u16)>,
    /// The network as detected, the user's per-network "metered" choices,
    /// and the result rules are evaluated against.
    detected: Detected,
    overrides: Overrides,
    network: Network,
    /// How the network is detected; empty until the first detection.
    network_source: String,
    settings: DaemonSettings,
    /// New apps held until the user answers, oldest first.
    pending: Vec<Prompt>,
    /// Apps allowed "this time": not asked again until nwld restarts.
    allowed_once: std::collections::HashSet<AppId>,
    /// Names of remote addresses from DNS answers; filled by the DNS
    /// watcher and forward lookups, read here.
    dns: Arc<Mutex<DnsCache>>,
    /// Program fingerprints per app, and when each app was last checked.
    identities: BTreeMap<AppId, Fingerprint>,
    hasher: Option<Hasher>,
    identity_checked: HashMap<AppId, i64>,
    /// Country and network owner of remote addresses, if a database is installed.
    geo: Option<crate::geo::GeoDb>,
    /// Quota rule -> period in which its 80% warning was raised.
    warned: HashMap<RuleId, String>,
    /// Whether quota states have been taken in since startup. The first
    /// tick only records them: quotas reached (or past 80%) before a restart
    /// were announced then and are not announced again.
    quotas_primed: bool,
    accountant: Accountant,
    quotas: QuotaTracker,
    usage: UsageDb,
    /// Per-minute and per-hour traffic, machine-wide and per app.
    history: nwl_core::history::TrafficHistory,
    known_apps: KnownApps,
    snapshot: Snapshot,
    /// Per-connection rate (up, down) in bytes/s over the last tick.
    conn_rates: HashMap<ConnKey, (u64, u64)>,
    /// A representative process per app, for matching app patterns.
    app_samples: HashMap<AppId, ProcessInfo>,
    /// Friendly names and icons (from `.desktop` entries), looked up once
    /// per app; `None` when there is nothing better than the program name.
    catalog: Option<Box<dyn AppCatalog>>,
    app_info: HashMap<AppId, Option<AppInfo>>,
    exhausted: Vec<RuleId>,
    /// Recently deleted quota rules and their usage, so that undoing a
    /// delete (re-adding the identical rule) keeps what was counted.
    removed_quotas: VecDeque<(Rule, QuotaUsage)>,
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
        && m.domains.is_empty()
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
            spikes: SpikeDetector::default(),
            effective: rules.clone(),
            no_rules: RuleSet::default(),
            clock: None,
            detected: Detected::default(),
            overrides: store.load(NETWORK)?.unwrap_or_default(),
            network: Network::default(),
            network_source: String::new(),
            settings: store.load(SETTINGS)?.unwrap_or_default(),
            pending: Vec::new(),
            allowed_once: Default::default(),
            identities: store.load(IDENTITIES)?.unwrap_or_default(),
            dns: Arc::default(),
            hasher: None,
            identity_checked: HashMap::new(),
            geo: None,
            warned: HashMap::new(),
            quotas_primed: false,
            rules,
            accountant: Accountant::new(history_len, 5 * 60 * 1000),
            quotas: store.load(QUOTAS)?.unwrap_or_default(),
            usage: store.load(USAGE)?.unwrap_or_default(),
            history: store.load(HISTORY)?.unwrap_or_default(),
            known_apps: store.load(KNOWN_APPS)?.unwrap_or_default(),
            store,
            snapshot: Snapshot::default(),
            conn_rates: HashMap::new(),
            app_samples: HashMap::new(),
            catalog: None,
            app_info: HashMap::new(),
            exhausted: Vec::new(),
            removed_quotas: VecDeque::new(),
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

    pub fn set_geo(&mut self, geo: crate::geo::GeoDb) {
        self.geo = Some(geo);
    }

    /// The GeoIP database files in use.
    pub fn geo_sources(&self) -> Vec<String> {
        self.geo.as_ref().map(|g| g.sources.clone()).unwrap_or_default()
    }

    fn locate(&self, ip: std::net::IpAddr) -> nwl_core::api::Location {
        self.geo.as_ref().map(|g| g.lookup(ip)).unwrap_or_default()
    }

    /// The DNS cache, for the threads that fill it.
    pub fn dns_cache(&self) -> Arc<Mutex<DnsCache>> {
        self.dns.clone()
    }

    /// Domains in rules that can be looked up directly (no wildcard), so
    /// rules for them work even where DNS answers can't be watched.
    pub fn rule_domains(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .rules
            .enabled()
            .flat_map(|r| r.matcher.domains.iter())
            .filter(|d| !d.is_glob())
            .map(|d| d.0.trim().to_ascii_lowercase())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Starts fingerprinting app programs (a worker thread).
    pub fn enable_fingerprints(&mut self) {
        let known =
            self.identities.iter().map(|(app, fp)| (std::path::PathBuf::from(&app.0), fp.clone())).collect();
        self.hasher = Some(Hasher::new(known));
    }

    /// A program file's fingerprint was computed.
    fn fingerprint_ready(&mut self, app: AppId, fp: Fingerprint) {
        match self.identities.get(&app) {
            Some(old) if old.sha256 == fp.sha256 => return,
            Some(_) => {
                let name = self.app_name(&app);
                self.push_event(EventKind::ProgramChanged { app: app.clone(), name });
            }
            None => {}
        }
        self.identities.insert(app, fp);
        self.dirty = true;
    }

    fn check_identities(&mut self, now: i64) {
        let Some(hasher) = &self.hasher else { return };
        for (path, fp) in hasher.results() {
            self.fingerprint_ready(AppId(path.display().to_string()), fp);
        }
        let Some(hasher) = &self.hasher else { return };
        for a in self.accountant.apps() {
            let path = std::path::Path::new(&a.app.0);
            let due = self.identity_checked.get(&a.app).is_none_or(|t| now - t >= IDENTITY_CHECK_SECS);
            if path.is_absolute() && due {
                hasher.check(path.to_path_buf());
                self.identity_checked.insert(a.app.clone(), now);
            }
        }
    }

    pub fn set_catalog(&mut self, catalog: Box<dyn AppCatalog>) {
        self.catalog = Some(catalog);
        self.app_info.clear();
    }

    /// Looks up apps not seen before in the catalog.
    fn learn_apps(&mut self, apps: impl IntoIterator<Item = AppId>) {
        let Some(catalog) = &mut self.catalog else { return };
        for app in apps {
            if let std::collections::hash_map::Entry::Vacant(slot) = self.app_info.entry(app) {
                let info = catalog.lookup(slot.key());
                slot.insert(info);
            }
        }
    }

    /// The app's display name: its catalog name, or the program's.
    fn app_name(&self, app: &AppId) -> String {
        match self.app_info.get(app) {
            Some(Some(info)) => info.name.clone(),
            _ => app.display_name().to_string(),
        }
    }

    /// The icon file of an app, if the catalog found one.
    pub fn icon(&self, app: &str) -> Option<std::path::PathBuf> {
        self.app_info.get(&AppId(app.to_string()))?.as_ref()?.icon.clone()
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
            Some((day, minute)) => self.rules.effective_at(day, minute, &self.network),
            None => self.rules.clone(),
        };
        // Apps waiting for an answer are blocked, before any other rule.
        // Domain rules apply to the addresses their domains resolve to now.
        {
            let now = chrono::Utc::now().timestamp();
            let dns = self.dns.lock().unwrap_or_else(|p| p.into_inner());
            self.effective.resolve_domains(|patterns| dns.addresses(patterns, now));
        }
        let waiting = self.pending.iter().enumerate().map(|(i, p)| Rule {
            id: WAITING_RULE_BASE + i as RuleId,
            name: format!("Waiting for your answer: {}", p.name),
            enabled: true,
            matcher: Matcher { app: Some(AppPattern(p.app.0.clone())), ..Matcher::default() },
            action: Action::Block { direction: Direction::Both },
            schedule: None,
            network: None,
        });
        self.effective.rules.splice(0..0, waiting);
    }

    pub fn settings(&self) -> DaemonSettings {
        self.settings.clone()
    }

    pub fn set_settings(&mut self, settings: DaemonSettings) -> anyhow::Result<()> {
        // Turning asking off lets waiting apps go.
        if !settings.ask_new_apps {
            for p in std::mem::take(&mut self.pending) {
                self.known_apps.insert(p.app);
            }
            self.refresh_effective();
        }
        self.settings = settings;
        self.store.save(SETTINGS, &self.settings)
    }

    pub fn prompts(&self) -> Vec<Prompt> {
        self.pending.clone()
    }

    /// The user's answer about a new app.
    pub fn answer(&mut self, app: &AppId, answer: Answer) -> Result<(), String> {
        let i = self.pending.iter().position(|p| &p.app == app).ok_or("no app with this name is waiting")?;
        let prompt = self.pending.remove(i);
        match answer {
            Answer::Allow => {
                self.known_apps.insert(prompt.app);
            }
            // Not remembered: asked again after a restart.
            Answer::Once => {
                self.allowed_once.insert(prompt.app);
            }
            Answer::Block => {
                self.known_apps.insert(prompt.app.clone());
                let rule = serde_json::json!({
                    "name": format!("Block {}", prompt.name),
                    "match": {"app": prompt.app.0},
                    "action": {"type": "block"},
                });
                let rule: Rule = serde_json::from_value(rule).map_err(|e| e.to_string())?;
                self.add_rule(rule).map_err(|e| e.to_string())?;
            }
        }
        self.refresh_effective();
        self.dirty = true;
        Ok(())
    }

    /// Takes in the latest network detection (polled by the daemon).
    pub fn set_network(&mut self, source: &str, detected: Detected) {
        let first = self.network_source.is_empty();
        self.network_source = source.to_string();
        self.detected = detected;
        self.update_network(!first);
    }

    /// Everything the user configured, for a backup file.
    pub fn export(&self) -> Backup {
        Backup {
            format: BACKUP_FORMAT.into(),
            version: BACKUP_VERSION,
            exported: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            rules: self.rules.rules.clone(),
            network: self.overrides.clone(),
        }
    }

    /// Restores a backup. `merge` adds the rules and network choices that
    /// aren't here yet; otherwise the backup replaces them. Nothing changes
    /// unless the whole backup is valid.
    pub fn import(&mut self, backup: Backup, merge: bool) -> Result<ImportResult, String> {
        if backup.format != BACKUP_FORMAT {
            return Err("this is not a NattoWok Limiter backup".into());
        }
        if backup.version > BACKUP_VERSION {
            return Err("this backup was made by a newer version of NattoWok Limiter".into());
        }
        let result = if merge {
            // A rule is already here if it does the same thing, whatever its id.
            let same = |a: &Rule, b: &Rule| {
                a.matcher == b.matcher
                    && a.action == b.action
                    && a.schedule == b.schedule
                    && a.network == b.network
            };
            let mut rules = self.rules.clone();
            let (mut added, mut skipped) = (0, 0);
            for mut rule in backup.rules {
                if rules.rules.iter().any(|r| same(r, &rule)) {
                    skipped += 1;
                    continue;
                }
                rule.id = 0;
                rules.add(rule).map_err(|e| e.to_string())?;
                added += 1;
            }
            self.rules = rules;
            for (name, metered) in backup.network.metered {
                self.overrides.metered.entry(name).or_insert(metered);
            }
            ImportResult { rules: added, skipped, replaced: false }
        } else {
            let rules = RuleSet::new(backup.rules).map_err(|e| e.to_string())?;
            let count = rules.rules.len();
            self.rules = rules;
            self.overrides = backup.network;
            ImportResult { rules: count, skipped: 0, replaced: true }
        };
        self.rules_changed();
        if let Err(e) = self.store.save(NETWORK, &self.overrides) {
            tracing::error!("saving network choices: {e:#}");
        }
        self.update_network(true);
        self.push_event(EventKind::Imported { rules: result.rules, replaced: result.replaced });
        Ok(result)
    }

    /// Treats the current network as metered or not (`None`: as detected),
    /// remembered for this network.
    pub fn set_metered(&mut self, metered: Option<bool>) -> anyhow::Result<()> {
        self.overrides.set(self.detected.name.as_deref(), metered);
        self.update_network(true);
        self.store.save(NETWORK, &self.overrides)
    }

    fn update_network(&mut self, announce: bool) {
        let network = self.overrides.resolve(&self.detected);
        if network == self.network {
            return;
        }
        self.network = network;
        self.refresh_effective();
        if announce {
            let rules = self.effective.rules.iter().filter(|r| r.enabled && r.network.is_some()).count();
            let Network { name, metered } = self.network.clone();
            self.push_event(EventKind::NetworkChanged { name, metered, rules });
        }
    }

    pub fn network_view(&self) -> NetworkView {
        NetworkView {
            name: self.network.name.clone(),
            metered: self.network.metered,
            detected: self.detected.metered,
            overridden: self.overrides.get(self.detected.name.as_deref()),
            source: self.network_source.clone(),
        }
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
        let system_before = (self.accountant.system().total_up, self.accountant.system().total_down);
        let deltas = self.accountant.ingest(&snap);
        let system = self.accountant.system();
        let system_delta = [system.total_up - system_before.0, system.total_down - system_before.1];
        let mut app_deltas: HashMap<AppId, [u64; 2]> = HashMap::new();

        let conns: HashMap<&ConnKey, &Connection> = snap.connections.iter().map(|c| (&c.key, c)).collect();
        self.conn_rates.clear();
        for d in &deltas {
            self.conn_rates.insert(d.key.clone(), (d.up * 1000 / elapsed_ms, d.down * 1000 / elapsed_ms));
            if d.loopback && !self.count_loopback {
                continue;
            }
            if let Some(app) = &d.app {
                self.usage.record(&day, app, d.up, d.down);
                let entry = app_deltas.entry(app.clone()).or_default();
                entry[0] += d.up;
                entry[1] += d.down;
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

        self.history.record(now.timestamp(), system_delta, app_deltas.iter().map(|(app, b)| (app, *b)));

        let mut new_apps = Vec::new();
        let seen: Vec<AppId> = snap.processes.values().map(|p| p.app_id()).collect();
        self.learn_apps(seen);
        let mut asked = false;
        for process in snap.processes.values() {
            let app = process.app_id();
            let waiting = self.pending.iter().any(|p| p.app == app);
            if !waiting && self.known_apps.insert(app.clone()) && !self.suppress_new_app_events {
                let name = self.app_name(&app);
                if self.settings.ask_new_apps && !self.allowed_once.contains(&app) {
                    // Known only once answered: a restart asks again.
                    self.known_apps.remove(&app);
                    let since = chrono::Utc::now().timestamp_millis();
                    self.pending.push(Prompt { app: app.clone(), name: name.clone(), since });
                    self.push_event(EventKind::AskNewApp { app: app.clone(), name });
                    asked = true;
                } else {
                    new_apps.push((app.clone(), name));
                }
            }
            self.app_samples.insert(app, process.clone());
        }
        self.suppress_new_app_events = false;
        for (app, name) in new_apps {
            self.push_event(EventKind::NewApp { app, name });
        }
        if asked {
            self.refresh_effective();
        }
        self.app_samples.retain(|app, _| self.accountant.apps().any(|a| &a.app == app));

        let mut spikes = Vec::new();
        for a in self.accountant.apps() {
            spikes.extend(self.spikes.observe(&a.app, a.rate_up, a.rate_down, snap.mono_ms));
        }
        let accountant = &self.accountant;
        self.spikes.retain(|app| accountant.apps().any(|a| &a.app == app));
        for s in spikes {
            let name = self.app_name(&s.app);
            self.push_event(EventKind::TrafficSpike {
                app: s.app,
                name,
                direction: s.direction,
                rate: s.rate,
                usual: s.usual,
            });
        }

        self.check_identities(now.timestamp());
        self.refresh_exhausted();
        self.quotas_primed = true;
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
            let announce = self.quotas_primed;
            if s.exhausted {
                exhausted.push(s.rule);
                if !self.exhausted.contains(&s.rule) && announce {
                    self.push_event(EventKind::QuotaExhausted { rule: s.rule, name });
                }
            } else if s.used * 10 >= s.limit * 8 && self.warned.get(&s.rule) != Some(&s.period_key) {
                self.warned.insert(s.rule, s.period_key.clone());
                if announce {
                    self.push_event(EventKind::QuotaWarning { rule: s.rule, name, percent: 80 });
                }
            }
        }
        self.exhausted = exhausted;
    }

    pub fn policy(&self) -> Policy<'_> {
        if self.status.paused {
            return Policy { rules: &self.no_rules, exhausted_quotas: &[], snapshot: &self.snapshot };
        }
        Policy { rules: &self.effective, exhausted_quotas: &self.exhausted, snapshot: &self.snapshot }
    }

    /// Pauses or resumes all rules. While paused nothing is blocked or
    /// limited, but traffic and quotas are still counted. Not persisted: a
    /// restart resumes, so a forgotten pause cannot outlive the daemon.
    pub fn set_paused(&mut self, paused: bool) {
        if self.status.paused != paused {
            self.status.paused = paused;
            self.push_event(if paused { EventKind::Paused } else { EventKind::Resumed });
        }
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
        self.store.save(HISTORY, &self.history)?;
        self.store.save(KNOWN_APPS, &self.known_apps)?;
        self.store.save(IDENTITIES, &self.identities)?;
        self.dirty = false;
        Ok(())
    }

    fn save_rules(&self) -> anyhow::Result<()> {
        self.store.save(RULES, &self.rules.rules)
    }

    pub fn add_rule(&mut self, rule: Rule) -> Result<RuleId, RuleError> {
        // The same quota rule coming back (an undo) gets its usage back.
        let removed = self.removed_quotas.iter().position(|(r, _)| {
            r.id == rule.id
                && r.matcher == rule.matcher
                && r.action == rule.action
                && r.schedule == rule.schedule
        });
        let id = self.rules.add(rule)?;
        if let Some((old, usage)) = removed.and_then(|i| self.removed_quotas.remove(i)) {
            if old.id == id {
                self.quotas.restore(id, usage);
            }
        }
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
        if let Some(usage) = self.quotas.take(id) {
            if self.removed_quotas.len() == 16 {
                self.removed_quotas.pop_front();
            }
            self.removed_quotas.push_back((rule.clone(), usage));
        }
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
                // The one-click toggles control unconditional app-wide rules.
                let one_click = |r: &&&Rule| app_only(r) && r.schedule.is_none() && r.network.is_none();
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
                let info = self.app_info.get(&s.app).and_then(Option::as_ref);
                let waiting = self.pending.iter().any(|p| p.app == s.app);
                AppView {
                    app: s.app.clone(),
                    name: info.map_or_else(|| s.name.clone(), |i| i.name.clone()),
                    icon: info.is_some_and(|i| i.icon.is_some()),
                    waiting,
                    sha256: self.identities.get(&s.app).map(|f| f.sha256.clone()),
                    program_since: self.identities.get(&s.app).map(|f| f.since),
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
                    blocked: blocked || waiting,
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
        let dns = self.dns.lock().unwrap_or_else(|p| p.into_inner());
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
                let domain = conn.key.remote.and_then(|r| {
                    let now = chrono::Utc::now().timestamp();
                    dns.names(r.ip(), now).first().map(|n| n.to_string())
                });
                let location = conn.key.remote.map(|r| self.locate(r.ip())).unwrap_or_default();
                Some(ConnView {
                    conn: conn.clone(),
                    remote_host,
                    domain,
                    location,
                    name: app_id.as_ref().map(|a| self.app_name(a)),
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
        let dns = self.dns.lock().unwrap_or_else(|p| p.into_inner());
        let now = chrono::Utc::now().timestamp();
        let view = |ip, s: &RemoteStats, apps: Vec<AppId>, app: Option<&AppId>| RemoteView {
            ip,
            host: self.resolver.as_ref().and_then(|r| r.lookup(ip)),
            domain: dns.names(ip, now).first().map(|n| n.to_string()),
            location: self.locate(ip),
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

    /// Traffic over `range`, machine-wide or for one app (full path).
    pub fn history(&self, range: nwl_core::history::Range, app: Option<&str>) -> nwl_core::api::HistoryView {
        let now = chrono::Utc::now().timestamp();
        let app = app.map(|a| AppId(a.to_string()));
        nwl_core::api::HistoryView {
            range,
            step_secs: range.geometry().1,
            points: self.history.series(range, app.as_ref(), now),
            apps: self
                .history
                .top_apps(range, now)
                .into_iter()
                .map(|(app, [up, down])| UsageEntry { name: app.display_name().to_string(), app, up, down })
                .collect(),
        }
    }

    /// The history of `range` as CSV (see [`nwl_core::history::to_csv`]).
    pub fn history_csv(&self, range: nwl_core::history::Range, app: Option<&str>) -> String {
        let points = self.history.aggregate(range, chrono::Utc::now().timestamp());
        nwl_core::history::to_csv(&points, app.map(|a| AppId(a.to_string())).as_ref())
    }

    /// Daily usage per app as CSV: `day,app,upload_bytes,download_bytes`.
    pub fn usage_csv(&self, days: usize) -> String {
        let mut out = String::from("day,app,upload_bytes,download_bytes\n");
        for d in self.usage(days) {
            for a in d.apps {
                let app = if a.app.0.contains([',', '"', '\n']) {
                    format!("\"{}\"", a.app.0.replace('"', "\"\""))
                } else {
                    a.app.0.clone()
                };
                out += &format!("{},{app},{},{}\n", d.day, a.up, a.down);
            }
        }
        out
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
            network: self.network_view(),
            prompts: self.pending.clone(),
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
    fn traffic_spikes_become_events() {
        let mut e = Engine::new(temp_store("spike"), 10).unwrap();
        let (mut sent, mut ms) = (0u64, 0u64);
        // 30 s at ~1 kB/s upload, then 5 s at 8 MB/s.
        for step in 0..35 {
            sent += if step < 30 { 1_000 } else { 8_000_000 };
            e.ingest(snap(ms, sent, 0), at(12));
            ms += 1000;
        }
        let spikes: Vec<_> = e
            .events_since(0)
            .into_iter()
            .filter_map(|ev| match ev.kind {
                EventKind::TrafficSpike { name, direction, rate, .. } => Some((name, direction, rate)),
                _ => None,
            })
            .collect();
        assert_eq!(spikes, vec![("steam".to_string(), Direction::Out, 8_000_000)]);
    }

    #[test]
    fn reached_quotas_are_not_announced_again_after_a_restart() {
        let store = temp_store("quota-restart");
        let dir = store.dir().to_path_buf();
        let mut e = Engine::new(store, 10).unwrap();
        e.add_rule(
            serde_json::from_str(
                r#"{"match":{"app":"steam"},"action":{"type":"quota","limit":1000,"period":"day"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        e.ingest(snap(1000, 0, 5000), at(12));
        let reached = |e: &Engine| {
            e.events_since(0).iter().filter(|ev| matches!(ev.kind, EventKind::QuotaExhausted { .. })).count()
        };
        assert_eq!(reached(&e), 1);
        e.save().unwrap();

        let mut e = Engine::new(Store::open(dir.clone()).unwrap(), 10).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        e.ingest(snap(1000, 0, 0), at(12));
        assert_eq!(e.policy().exhausted_quotas.len(), 1, "still enforced");
        assert_eq!(reached(&e), 0, "but not announced again");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pausing_lifts_all_enforcement_but_keeps_counting() {
        let mut e = Engine::new(temp_store("pause"), 10).unwrap();
        e.add_rule(serde_json::from_str(r#"{"match":{"app":"steam"},"action":{"type":"block"}}"#).unwrap())
            .unwrap();
        e.add_rule(
            serde_json::from_str(
                r#"{"match":{"app":"steam"},"action":{"type":"quota","limit":10,"period":"day"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        e.ingest(snap(1000, 0, 100), at(12));
        assert_eq!(e.policy().rules.enabled().count(), 2);
        assert_eq!(e.policy().exhausted_quotas.len(), 1);

        e.set_paused(true);
        assert!(e.policy().rules.enabled().next().is_none());
        assert!(e.policy().exhausted_quotas.is_empty());
        e.ingest(snap(2000, 0, 300), at(12));
        assert_eq!(e.quota_status()[0].used, 300, "still counted while paused");

        e.set_paused(false);
        assert_eq!(e.policy().rules.enabled().count(), 2);
        let toggles = e
            .events_since(0)
            .iter()
            .filter(|ev| matches!(ev.kind, EventKind::Paused | EventKind::Resumed))
            .count();
        assert_eq!(toggles, 2);
    }

    #[test]
    fn history_and_csv_exports() {
        let mut e = Engine::new(temp_store("history"), 10).unwrap();
        let now = Local::now();
        e.ingest(snap(0, 0, 0), now);
        e.ingest(snap(1000, 300, 4000), now);
        let h = e.history(nwl_core::history::Range::Hour, Some("/opt/steam/steam"));
        assert_eq!((h.points.len(), h.step_secs), (60, 60));
        assert_eq!(
            h.points.iter().map(|p| (p.up, p.down)).fold((0, 0), |a, p| (a.0 + p.0, a.1 + p.1)),
            (300, 4000)
        );
        assert_eq!(h.apps[0].name, "steam");
        let csv = e.history_csv(nwl_core::history::Range::Hour, None);
        assert!(csv.lines().any(|l| l.ends_with(",/opt/steam/steam,300,4000")), "{csv}");
        let usage = e.usage_csv(7);
        assert!(usage.starts_with("day,app,upload_bytes,download_bytes\n"));
        assert!(usage.contains(",/opt/steam/steam,300,4000\n"), "{usage}");
    }

    #[test]
    fn rules_follow_the_network() {
        let store = temp_store("network");
        let dir = store.dir().to_path_buf();
        let mut e = Engine::new(store, 10).unwrap();
        e.add_rule(
            serde_json::from_str(
                r#"{"match":{"app":"steam"},"action":{"type":"block"},"network":{"metered":true}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let home = Detected { name: Some("Home".into()), metered: Some(false) };
        let hotspot = Detected { name: Some("Pixel".into()), metered: Some(true) };
        let changes = |e: &Engine| {
            e.events_since(0)
                .into_iter()
                .filter_map(|ev| match ev.kind {
                    EventKind::NetworkChanged { name, metered, rules } => {
                        Some((name.unwrap(), metered, rules))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        e.set_network("test", home.clone());
        e.ingest(snap(0, 0, 0), at(12));
        assert!(!e.apps()[0].blocked);
        assert_eq!(e.apps()[0].block_rule, None, "network rules are not one-click toggles");
        assert!(changes(&e).is_empty(), "the first detection is not a change");

        e.set_network("test", hotspot.clone());
        e.ingest(snap(1000, 0, 0), at(12));
        assert!(e.apps()[0].blocked, "on the hotspot the rule applies");
        assert_eq!(changes(&e), vec![("Pixel".to_string(), true, 1)]);
        e.set_network("test", hotspot.clone());
        assert_eq!(changes(&e).len(), 1, "no event without a change");

        // The user says this hotspot is unlimited.
        e.set_metered(Some(false)).unwrap();
        assert_eq!(e.policy().rules.enabled().count(), 0);
        let view = e.network_view();
        assert_eq!((view.metered, view.detected, view.overridden), (false, Some(true), Some(false)));
        assert_eq!(changes(&e).last(), Some(&("Pixel".to_string(), false, 0)));

        // Remembered per network, across restarts.
        let mut e = Engine::new(Store::open(dir).unwrap(), 10).unwrap();
        e.set_network("test", hotspot);
        assert!(!e.network_view().metered);
        e.set_network("test", Detected { name: Some("Cafe".into()), metered: Some(true) });
        assert!(e.network_view().metered, "other networks follow detection");
        assert_eq!(e.overview().network.name.as_deref(), Some("Cafe"));
    }

    #[test]
    fn undoing_a_quota_delete_keeps_its_usage() {
        let mut e = Engine::new(temp_store("undo-quota"), 10).unwrap();
        let quota: Rule = serde_json::from_str(
            r#"{"match":{"app":"steam"},"action":{"type":"quota","limit":10000,"period":"day"}}"#,
        )
        .unwrap();
        let id = e.add_rule(quota).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        e.ingest(snap(1000, 0, 4000), at(12));
        assert_eq!(e.quota_status()[0].used, 4000);
        let removed = e.remove_rule(id).unwrap();
        assert!(e.quota_status().is_empty());
        assert_eq!(e.add_rule(removed).unwrap(), id, "same id back");
        assert_eq!(e.quota_status()[0].used, 4000, "usage restored");

        // A different rule that happens to get the same id starts from zero.
        let removed = e.remove_rule(id).unwrap();
        let mut other = removed.clone();
        other.action = Action::Quota {
            limit: nwl_core::rate::ByteSize(99),
            period: Period::Day,
            direction: Direction::Both,
        };
        e.add_rule(other).unwrap();
        assert_eq!(e.quota_status()[0].used, 0);
    }

    #[test]
    fn apps_get_catalog_names_and_icons() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Fake(std::sync::Arc<AtomicUsize>);
        impl AppCatalog for Fake {
            fn lookup(&mut self, app: &AppId) -> Option<AppInfo> {
                self.0.fetch_add(1, Ordering::Relaxed);
                (app.0 == "/opt/steam/steam")
                    .then(|| AppInfo { name: "Steam".into(), icon: Some("/icons/steam.png".into()) })
            }
        }
        let lookups = std::sync::Arc::new(AtomicUsize::new(0));
        let mut e = Engine::new(temp_store("catalog"), 10).unwrap();
        e.set_catalog(Box::new(Fake(lookups.clone())));
        e.ingest(snap(0, 0, 0), at(12));
        e.ingest(snap(1000, 10, 10), at(12));
        let app = &e.apps()[0];
        assert_eq!((app.name.as_str(), app.icon), ("Steam", true));
        assert_eq!(e.icon("/opt/steam/steam"), Some("/icons/steam.png".into()));
        assert_eq!(e.icon("/usr/bin/other"), None);
        assert_eq!(lookups.load(Ordering::Relaxed), 1, "looked up once per app");
    }

    #[test]
    fn backups_restore_and_merge() {
        let mut e = Engine::new(temp_store("backup"), 10).unwrap();
        let rule = |json: &str| -> Rule { serde_json::from_str(json).unwrap() };
        e.add_rule(rule(r#"{"name":"a","match":{"app":"steam"},"action":{"type":"block"}}"#)).unwrap();
        e.set_network("test", Detected { name: Some("Pixel".into()), metered: Some(false) });
        e.set_metered(Some(true)).unwrap();
        let backup = e.export();
        let text = serde_json::to_string(&backup).unwrap();
        assert!(text.contains(r#""format":"nattowok-backup""#));

        // Merge into a machine that has one of the rules already.
        let mut other = Engine::new(temp_store("backup-merge"), 10).unwrap();
        other
            .add_rule(rule(r#"{"name":"same thing","match":{"app":"steam"},"action":{"type":"block"}}"#))
            .unwrap();
        other.add_rule(rule(r#"{"name":"mine","action":{"type":"allow"}}"#)).unwrap();
        let r = other.import(serde_json::from_str(&text).unwrap(), true).unwrap();
        assert_eq!((r.rules, r.skipped, r.replaced), (0, 1, false));
        assert_eq!(other.rules.rules.len(), 2);
        assert_eq!(other.overrides.get(Some("Pixel")), Some(true), "network choices merged");

        // Replace.
        let r = other.import(backup.clone(), false).unwrap();
        assert_eq!((r.rules, r.replaced), (1, true));
        assert_eq!(other.rules.rules[0].name, "a");
        assert_eq!(other.rules.rules[0].id, backup.rules[0].id, "ids kept on replace");

        // Bad files change nothing.
        let mut bad = backup.clone();
        bad.format = "something else".into();
        assert!(other.import(bad, false).is_err());
        let mut newer = backup.clone();
        newer.version = 99;
        assert!(other.import(newer, false).unwrap_err().contains("newer version"));
        let mut invalid = backup;
        invalid.rules.push(rule(r#"{"action":{"type":"limit"}}"#));
        assert!(other.import(invalid, false).is_err());
        assert_eq!(other.rules.rules.len(), 1, "unchanged after a failed import");
    }

    #[test]
    fn new_apps_wait_for_an_answer() {
        let store = temp_store("ask");
        let dir = store.dir().to_path_buf();
        let mut e = Engine::new(store, 10).unwrap();
        e.ingest(Snapshot::default(), at(12)); // first run: nothing is new
        e.set_settings(DaemonSettings { ask_new_apps: true }).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        let steam = AppId("/opt/steam/steam".into());
        assert_eq!(e.prompts().len(), 1);
        assert!(e.apps()[0].waiting && e.apps()[0].blocked);
        let rules = e.policy().rules.enabled().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(rules, [WAITING_RULE_BASE], "held by a temporary rule");
        assert!(e.events_since(0).iter().any(|ev| matches!(ev.kind, EventKind::AskNewApp { .. })));
        e.ingest(snap(1000, 0, 0), at(12));
        assert_eq!(e.prompts().len(), 1, "asked once");
        e.save().unwrap();

        // Unanswered when nwld restarts: asked again.
        let mut e = Engine::new(Store::open(dir.clone()).unwrap(), 10).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        assert_eq!(e.prompts().len(), 1);
        e.answer(&steam, Answer::Once).unwrap();
        assert!(e.prompts().is_empty() && !e.apps()[0].blocked);
        assert_eq!(e.policy().rules.enabled().count(), 0);
        e.save().unwrap();

        // "This time" is forgotten on restart; "Block" adds a rule.
        let mut e = Engine::new(Store::open(dir.clone()).unwrap(), 10).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        assert_eq!(e.prompts().len(), 1);
        e.answer(&steam, Answer::Block).unwrap();
        assert_eq!(e.rules.rules[0].name, "Block steam");
        assert!(e.answer(&steam, Answer::Allow).is_err(), "nothing waiting any more");
        e.save().unwrap();
        let mut e = Engine::new(Store::open(dir).unwrap(), 10).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        assert!(e.prompts().is_empty(), "a blocked app is known");

        // Turning asking off releases waiting apps.
        let mut e = Engine::new(temp_store("ask-off"), 10).unwrap();
        e.ingest(Snapshot::default(), at(12));
        e.set_settings(DaemonSettings { ask_new_apps: true }).unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        e.set_settings(DaemonSettings { ask_new_apps: false }).unwrap();
        assert!(e.prompts().is_empty() && e.policy().rules.enabled().count() == 0);
    }

    #[test]
    fn changed_programs_are_reported() {
        let mut e = Engine::new(temp_store("identity"), 10).unwrap();
        let steam = AppId("/opt/steam/steam".into());
        let fp = |sha: &str| Fingerprint { sha256: sha.into(), size: 1, modified: 1, since: 1 };
        e.fingerprint_ready(steam.clone(), fp("aaa"));
        e.fingerprint_ready(steam.clone(), fp("aaa"));
        let changes = |e: &Engine| {
            e.events_since(0).iter().filter(|ev| matches!(ev.kind, EventKind::ProgramChanged { .. })).count()
        };
        assert_eq!(changes(&e), 0, "first sight and unchanged programs aren't news");
        e.fingerprint_ready(steam.clone(), fp("bbb"));
        assert_eq!(changes(&e), 1);
        e.ingest(snap(0, 0, 0), at(12));
        assert_eq!(e.apps()[0].sha256.as_deref(), Some("bbb"));
    }

    #[test]
    fn domain_rules_follow_dns_answers() {
        let mut e = Engine::new(temp_store("domains"), 10).unwrap();
        e.add_rule(
            serde_json::from_str(r#"{"match":{"domains":["example.com"]},"action":{"type":"block"}}"#)
                .unwrap(),
        )
        .unwrap();
        e.ingest(snap(0, 0, 0), at(12));
        assert_eq!(e.policy().rules.enabled().count(), 0, "off until the domain resolves");
        assert!(!e.connections(None)[0].blocked);
        assert_eq!(e.rule_domains(), ["example.com"]);

        let answer = nwl_core::dns::Answer {
            ip: "1.2.3.4".parse().unwrap(),
            names: vec!["cdn.example.com".into()],
            ttl: 300,
        };
        e.dns_cache().lock().unwrap().insert(&answer, chrono::Utc::now().timestamp());
        e.ingest(snap(1000, 0, 0), at(12));
        let conn = &e.connections(None)[0];
        assert!(conn.blocked, "the app's connection to that address is blocked");
        assert_eq!(conn.domain.as_deref(), Some("cdn.example.com"));
    }

    #[test]
    fn period_keys() {
        let t = at(12);
        assert_eq!(period_key(Period::Day, &t), "2026-10-12");
        assert_eq!(period_key(Period::Week, &t), "2026-W42");
        assert_eq!(period_key(Period::Month, &t), "2026-10");
    }
}
