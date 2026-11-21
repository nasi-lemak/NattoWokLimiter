//! Rules: what to allow, block, throttle or cap.
//!
//! Semantics, chosen to be predictable and to translate 1:1 into kernel
//! firewalls (nftables, WFP):
//!
//! * **Access** rules (`allow` / `block`) are evaluated top to bottom and the
//!   first enabled match wins. No match means allow.
//! * **Limit** rules always apply, independent of order and of access rules.
//!   Every matching limit applies at once, so an app can be capped at 1 MB/s
//!   while a global rule caps all traffic at 10 MB/s. A limit is an aggregate
//!   budget shared by everything the rule matches.
//! * **Quota** rules count the traffic they match per period; once the cap is
//!   reached the matched traffic is blocked until the period rolls over.

use crate::model::{AppId, Connection, Direction, ProcessInfo, Protocol};
use crate::rate::{ByteSize, Rate};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

pub type RuleId = u64;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub id: RuleId,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, rename = "match")]
    pub matcher: Matcher,
    pub action: Action,
    /// When set, the rule only applies inside this weekly time window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
    /// When set, the rule only applies on matching networks (e.g. metered).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<crate::network::NetworkCondition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Day {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Day {
    pub const ALL: [Day; 7] = [Day::Mon, Day::Tue, Day::Wed, Day::Thu, Day::Fri, Day::Sat, Day::Sun];

    /// 0 = Monday.
    pub fn from_index(i: usize) -> Day {
        Day::ALL[i % 7]
    }

    pub fn prev(self) -> Day {
        Day::from_index(self as usize + 6)
    }
}

impl FromStr for Day {
    type Err = String;
    /// Accepts `mon`, `Monday`, `TUE`, ...
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_ascii_lowercase();
        const NAMES: [&str; 7] =
            ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
        NAMES
            .iter()
            .position(|n| lower.len() >= 3 && n.starts_with(&lower))
            .map(Day::from_index)
            .ok_or_else(|| format!("invalid day `{s}`"))
    }
}

/// Minutes since local midnight, written `HH:MM`; `24:00` is the end of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeOfDay(pub u16);

impl FromStr for TimeOfDay {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || format!("invalid time `{s}`, expected HH:MM");
        let (h, m) = s.trim().split_once(':').ok_or_else(err)?;
        let (h, m): (u16, u16) = (h.parse().map_err(|_| err())?, m.parse().map_err(|_| err())?);
        if m >= 60 || h > 24 || (h == 24 && m != 0) {
            return Err(err());
        }
        Ok(TimeOfDay(h * 60 + m))
    }
}

impl fmt::Display for TimeOfDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.0 / 60, self.0 % 60)
    }
}

impl Serialize for TimeOfDay {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TimeOfDay {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// A weekly window, e.g. weekdays 09:00–17:00. A window whose end is before
/// its start runs overnight (22:00–06:00), and `days` then names the day it
/// starts on. Empty `days` means every day; missing times mean all day.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Schedule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<Day>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<TimeOfDay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<TimeOfDay>,
}

impl Schedule {
    fn on(&self, day: Day) -> bool {
        self.days.is_empty() || self.days.contains(&day)
    }

    /// Whether the window covers `minute` (since midnight) on `day`.
    pub fn active(&self, day: Day, minute: u16) -> bool {
        let from = self.from.map_or(0, |t| t.0);
        let until = self.until.map_or(24 * 60, |t| t.0);
        match from.cmp(&until) {
            std::cmp::Ordering::Less => self.on(day) && (from..until).contains(&minute),
            std::cmp::Ordering::Equal => self.on(day),
            std::cmp::Ordering::Greater => {
                (minute >= from && self.on(day)) || (minute < until && self.on(day.prev()))
            }
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block {
        #[serde(default)]
        direction: Direction,
    },
    Limit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        download: Option<Rate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        upload: Option<Rate>,
    },
    Quota {
        limit: ByteSize,
        period: Period,
        #[serde(default)]
        direction: Direction,
    },
}

impl Action {
    pub fn is_access(&self) -> bool {
        matches!(self, Action::Allow | Action::Block { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Period {
    Day,
    Week,
    Month,
}

/// Conditions a socket must satisfy for a rule to apply. Empty fields match
/// anything, so the default matcher matches all traffic.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppPattern>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_ports: Vec<PortRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_ports: Vec<PortRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Remote domains (`example.com` includes its subdomains; `*` globs).
    /// They stand for the addresses DNS answers gave for them, added to
    /// `remote`; see [`RuleSet::resolve_domains`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<crate::dns::DomainPattern>,
}

/// What a matcher is evaluated against.
#[derive(Debug, Clone, Copy)]
pub struct MatchCtx<'a> {
    pub conn: &'a Connection,
    pub process: Option<&'a ProcessInfo>,
}

impl Matcher {
    pub fn matches(&self, ctx: &MatchCtx<'_>) -> bool {
        let key = &ctx.conn.key;
        if let Some(app) = &self.app {
            match ctx.process {
                Some(p) if app.matches_process(p) => {}
                _ => return false,
            }
        }
        if self.protocol.is_some_and(|p| p != key.protocol) {
            return false;
        }
        // Domains without known addresses match nothing (an empty `remote`
        // would mean every address).
        if !self.domains.is_empty() && self.remote.is_empty() {
            return false;
        }
        if !self.remote.is_empty() {
            let Some(remote) = key.remote else { return false };
            let ip = normalize_ip(remote.ip());
            if !self.remote.iter().any(|net| net.contains(&ip)) {
                return false;
            }
        }
        if !self.remote_ports.is_empty() {
            let Some(remote) = key.remote else { return false };
            if !self.remote_ports.iter().any(|r| r.contains(remote.port())) {
                return false;
            }
        }
        if !self.local_ports.is_empty() && !self.local_ports.iter().any(|r| r.contains(key.local.port())) {
            return false;
        }
        if let Some(uid) = self.uid {
            let owner = ctx.conn.uid.or(ctx.process.and_then(|p| p.uid));
            if owner != Some(uid) {
                return false;
            }
        }
        true
    }
}

/// IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`, common on dual-stack
/// sockets) are matched as the IPv4 address users actually wrote rules for.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// An inclusive port range; `"443"` or `"8000-8100"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

impl FromStr for PortRange {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse = |p: &str| p.trim().parse::<u16>().map_err(|_| format!("invalid port `{p}`"));
        let (start, end) = match s.split_once('-') {
            Some((a, b)) => (parse(a)?, parse(b)?),
            None => {
                let p = parse(s)?;
                (p, p)
            }
        };
        if start > end {
            return Err(format!("invalid port range `{s}`: start is after end"));
        }
        Ok(PortRange { start, end })
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.start == self.end {
            s.serialize_u16(self.start)
        } else {
            s.serialize_str(&self.to_string())
        }
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(u16),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(p) => Ok(PortRange { start: p, end: p }),
            Raw::Str(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

/// Selects applications by executable.
///
/// A pattern containing a path separator is matched against the full
/// executable path; otherwise it is matched against the file name, so
/// `firefox` and `*/firefox` both work. `*` and `?` wildcards are supported.
/// Name matching is case-insensitive; path matching is case-insensitive on
/// Windows only, mirroring the file systems.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppPattern(pub String);

impl AppPattern {
    pub fn is_path(&self) -> bool {
        self.0.contains(['/', '\\'])
    }

    pub fn matches_app(&self, app: &AppId) -> bool {
        if self.is_path() {
            glob_match(&self.0, &app.0, cfg!(windows))
        } else {
            glob_match(&self.0, app.display_name(), true)
        }
    }

    pub fn matches_process(&self, process: &ProcessInfo) -> bool {
        if self.matches_app(&process.app_id()) {
            return true;
        }
        // Fall back to the short process name (e.g. when exe is unknown, or
        // for interpreters whose comm differs from the binary).
        !self.is_path() && glob_match(&self.0, &process.name, true)
    }
}

/// Minimal glob matcher supporting `*` (any run) and `?` (any one char).
pub fn glob_match(pattern: &str, text: &str, case_insensitive: bool) -> bool {
    let norm = |s: &str| -> Vec<char> {
        if case_insensitive {
            s.chars().flat_map(char::to_lowercase).collect()
        } else {
            s.chars().collect()
        }
    };
    let (p, t) = (norm(pattern), norm(text));
    let (mut pi, mut ti) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            backtrack = Some((pi, ti));
            pi += 1;
        } else if let Some((bp, bt)) = backtrack {
            pi = bp + 1;
            ti = bt + 1;
            backtrack = Some((bp, bt + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

impl fmt::Display for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        let mut days: Vec<Day> = self.days.clone();
        days.sort();
        days.dedup();
        match days.as_slice() {
            [] => f.write_str("daily")?,
            d if d == &Day::ALL[..5] => f.write_str("weekdays")?,
            d if d == &Day::ALL[5..] => f.write_str("weekends")?,
            d => f.write_str(&d.iter().map(|d| names[*d as usize]).collect::<Vec<_>>().join(","))?,
        }
        if let (Some(from), Some(until)) = (self.from, self.until) {
            write!(f, " {from}-{until}")?;
        }
        Ok(())
    }
}

impl Rule {
    /// What the rule does, e.g. `limit down 1.00 MB/s`.
    pub fn action_summary(&self) -> String {
        let dir = |d: Direction| match d {
            Direction::In => " incoming",
            Direction::Out => " outgoing",
            Direction::Both => "",
        };
        match &self.action {
            Action::Allow => "allow".into(),
            Action::Block { direction } => format!("block{}", dir(*direction)),
            Action::Limit { download, upload } => {
                let mut s = "limit".to_string();
                if let Some(r) = download {
                    s += &format!(" down {r}");
                }
                if let Some(r) = upload {
                    s += &format!(" up {r}");
                }
                s
            }
            Action::Quota { limit, period, direction } => {
                let period = match period {
                    Period::Day => "day",
                    Period::Week => "week",
                    Period::Month => "month",
                };
                format!("quota {limit} per {period}{}", dir(*direction))
            }
        }
    }

    /// What the rule applies to, e.g. `app steam · TCP · port 443 · weekdays 09:00-17:00`.
    pub fn scope_summary(&self) -> String {
        let m = &self.matcher;
        let mut parts = vec![m.app.as_ref().map_or("all apps".to_string(), |a| format!("app {}", a.0))];
        if let Some(p) = m.protocol {
            parts.push(p.to_string().to_uppercase());
        }
        let join = |items: Vec<String>| items.join(",");
        if !m.domains.is_empty() {
            parts.push(format!("domain {}", join(m.domains.iter().map(|d| d.to_string()).collect())));
        }
        if !m.remote.is_empty() {
            parts.push(format!("to {}", join(m.remote.iter().map(|n| n.to_string()).collect())));
        }
        if !m.remote_ports.is_empty() {
            parts.push(format!("port {}", join(m.remote_ports.iter().map(|p| p.to_string()).collect())));
        }
        if !m.local_ports.is_empty() {
            parts.push(format!("local port {}", join(m.local_ports.iter().map(|p| p.to_string()).collect())));
        }
        if let Some(uid) = m.uid {
            parts.push(format!("uid {uid}"));
        }
        if let Some(s) = &self.schedule {
            parts.push(s.to_string());
        }
        if let Some(n) = &self.network {
            parts.push(n.to_string());
        }
        parts.join(" · ")
    }
}

/// Outcome of evaluating the rule set against one socket.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Decision {
    /// `None` means allowed by default (no access rule matched).
    pub access_rule: Option<RuleId>,
    pub blocked: bool,
    /// Every limit rule that applies.
    pub limits: Vec<RuleId>,
    /// Every quota rule that counts this traffic.
    pub quotas: Vec<RuleId>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    #[error("rule {0} not found")]
    NotFound(RuleId),
    #[error("rule `{name}`: {reason}")]
    Invalid { name: String, reason: String },
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Result<Self, RuleError> {
        let mut set = RuleSet { rules: Vec::with_capacity(rules.len()) };
        for rule in rules {
            set.add(rule)?;
        }
        Ok(set)
    }

    fn next_id(&self) -> RuleId {
        self.rules.iter().map(|r| r.id).max().unwrap_or(0) + 1
    }

    /// Validates and appends a rule, assigning an id when it has none (0) or a
    /// duplicate one. Returns the id.
    pub fn add(&mut self, mut rule: Rule) -> Result<RuleId, RuleError> {
        validate(&rule)?;
        if rule.id == 0 || self.get(rule.id).is_some() {
            rule.id = self.next_id();
        }
        let id = rule.id;
        self.rules.push(rule);
        Ok(id)
    }

    pub fn get(&self, id: RuleId) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn replace(&mut self, id: RuleId, mut rule: Rule) -> Result<(), RuleError> {
        validate(&rule)?;
        let slot = self.rules.iter_mut().find(|r| r.id == id).ok_or(RuleError::NotFound(id))?;
        rule.id = id;
        *slot = rule;
        Ok(())
    }

    pub fn remove(&mut self, id: RuleId) -> Result<Rule, RuleError> {
        let idx = self.rules.iter().position(|r| r.id == id).ok_or(RuleError::NotFound(id))?;
        Ok(self.rules.remove(idx))
    }

    pub fn enabled(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    /// The rules in effect at a local time on a network: rules whose
    /// schedule or network condition doesn't hold are disabled. Everything
    /// downstream (decisions, quotas, enforcement) works on this view.
    pub fn effective_at(&self, day: Day, minute: u16, network: &crate::network::Network) -> RuleSet {
        let mut set = self.clone();
        for rule in &mut set.rules {
            if let Some(schedule) = &rule.schedule {
                rule.enabled &= schedule.active(day, minute);
            }
            if let Some(condition) = &rule.network {
                rule.enabled &= condition.active(network);
            }
        }
        set
    }

    /// Turns domain conditions into addresses: each rule's `domains` add the
    /// addresses `resolve` currently knows for them to its `remote`. A
    /// domain rule with no address yet is disabled, since an empty `remote`
    /// would cover every address.
    pub fn resolve_domains(&mut self, resolve: impl Fn(&[crate::dns::DomainPattern]) -> Vec<IpAddr>) {
        for rule in self.rules.iter_mut().filter(|r| !r.matcher.domains.is_empty()) {
            for ip in resolve(&rule.matcher.domains) {
                let ip = normalize_ip(ip);
                if !rule.matcher.remote.iter().any(|n| n.contains(&ip)) {
                    rule.matcher.remote.push(IpNet::from(ip));
                }
            }
            if rule.matcher.remote.is_empty() {
                rule.enabled = false;
            }
        }
    }

    /// Evaluates the rules against one socket. `exhausted_quotas` lists quota
    /// rules whose cap has been reached in the current period; they block.
    pub fn decide(&self, ctx: &MatchCtx<'_>, exhausted_quotas: &[RuleId]) -> Decision {
        let mut decision = Decision { access_rule: None, blocked: false, limits: vec![], quotas: vec![] };
        for rule in self.enabled().filter(|r| r.matcher.matches(ctx)) {
            match &rule.action {
                Action::Limit { .. } => decision.limits.push(rule.id),
                Action::Quota { .. } => {
                    decision.quotas.push(rule.id);
                    if exhausted_quotas.contains(&rule.id) && !decision.blocked {
                        decision.blocked = true;
                        decision.access_rule = Some(rule.id);
                    }
                }
                Action::Allow | Action::Block { .. } if decision.access_rule.is_none() => {
                    decision.access_rule = Some(rule.id);
                    decision.blocked = matches!(rule.action, Action::Block { .. });
                }
                _ => {}
            }
        }
        decision
    }
}

fn validate(rule: &Rule) -> Result<(), RuleError> {
    let invalid =
        |reason: &str| Err(RuleError::Invalid { name: rule.name.clone(), reason: reason.to_string() });
    match &rule.action {
        Action::Limit { download: None, upload: None } => {
            invalid("a limit needs a download and/or upload rate")
        }
        Action::Limit { download, upload }
            if download.is_some_and(|r| r.0 == 0) || upload.is_some_and(|r| r.0 == 0) =>
        {
            invalid("a limit rate of 0 would block everything; use a block rule instead")
        }
        Action::Quota { limit, .. } if limit.0 == 0 => invalid("a quota must be larger than 0"),
        Action::Quota { .. } if rule.matcher.app.is_none() && rule.matcher.remote.is_empty() => {
            invalid("a quota must be scoped to an app or remote network")
        }
        _ if rule.schedule.as_ref().is_some_and(|s| s.from.is_some() != s.until.is_some()) => {
            invalid("a schedule needs both `from` and `until`, or neither")
        }
        _ if rule.matcher.domains.iter().any(|d| !d.is_valid()) => {
            invalid("domains look like `example.com` or `*.example.com`")
        }
        _ if rule.network.as_ref().is_some_and(|n| n.is_empty()) => {
            invalid("a network condition needs `metered` and/or network `names`")
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ConnKey;

    fn conn(remote: &str, local_port: u16) -> Connection {
        Connection {
            key: ConnKey {
                protocol: Protocol::Tcp,
                local: format!("192.168.1.10:{local_port}").parse().unwrap(),
                remote: Some(remote.parse().unwrap()),
                cookie: 1,
            },
            state: None,
            pid: Some(42),
            uid: Some(1000),
            bytes_sent: None,
            bytes_recv: None,
            rtt_us: None,
            closed: false,
        }
    }

    fn proc_(exe: &str) -> ProcessInfo {
        ProcessInfo { pid: 42, name: "x".into(), exe: Some(exe.into()), uid: Some(1000) }
    }

    fn rule(json: &str) -> Rule {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn glob() {
        assert!(glob_match("*", "", false));
        assert!(glob_match("fire*", "firefox", false));
        assert!(glob_match("*fox", "firefox", false));
        assert!(glob_match("f?ref*x", "firefox", false));
        assert!(glob_match("*/bin/*", "/usr/bin/curl", false));
        assert!(!glob_match("fire", "firefox", false));
        assert!(glob_match("STEAM.EXE", "steam.exe", true));
        assert!(!glob_match("STEAM.EXE", "steam.exe", false));
        assert!(glob_match("a*b*c", "axxbyyc", false));
        assert!(!glob_match("a*b*c", "axxbyy", false));
    }

    #[test]
    fn app_patterns() {
        let p = proc_("/usr/lib/firefox/firefox");
        assert!(AppPattern("firefox".into()).matches_process(&p));
        assert!(AppPattern("Fire*".into()).matches_process(&p));
        assert!(AppPattern("/usr/lib/*/firefox".into()).matches_process(&p));
        assert!(!AppPattern("/usr/bin/firefox".into()).matches_process(&p));
        assert!(!AppPattern("chrome".into()).matches_process(&p));
    }

    #[test]
    fn matcher_fields() {
        let c = conn("1.2.3.4:443", 50000);
        let p = proc_("/usr/bin/curl");
        let ctx = MatchCtx { conn: &c, process: Some(&p) };
        let m = |json: &str| serde_json::from_str::<Matcher>(json).unwrap().matches(&ctx);
        assert!(m("{}"));
        assert!(m(r#"{"app": "curl", "remote": ["1.2.0.0/16"], "remote_ports": [443]}"#));
        assert!(m(r#"{"remote_ports": ["400-500"], "protocol": "tcp", "uid": 1000}"#));
        assert!(!m(r#"{"protocol": "udp"}"#));
        assert!(!m(r#"{"remote": ["10.0.0.0/8"]}"#));
        assert!(!m(r#"{"local_ports": [80]}"#));
        assert!(!m(r#"{"uid": 0}"#));
        assert!(!m(r#"{"app": "wget"}"#));
        // No process info: app matchers cannot match.
        let anon = MatchCtx { conn: &c, process: None };
        assert!(!serde_json::from_str::<Matcher>(r#"{"app":"curl"}"#).unwrap().matches(&anon));
    }

    #[test]
    fn v4_mapped_remote_matches_v4_net() {
        let c = conn("[::ffff:10.1.2.3]:80", 1);
        let ctx = MatchCtx { conn: &c, process: None };
        let m: Matcher = serde_json::from_str(r#"{"remote": ["10.0.0.0/8"]}"#).unwrap();
        assert!(m.matches(&ctx));
    }

    #[test]
    fn first_access_rule_wins_and_limits_stack() {
        let set = RuleSet::new(vec![
            rule(r#"{"name":"cap all","action":{"type":"limit","download":"10MB/s"}}"#),
            rule(r#"{"name":"lan ok","match":{"remote":["1.2.3.0/24"]},"action":{"type":"allow"}}"#),
            rule(r#"{"name":"no curl","match":{"app":"curl"},"action":{"type":"block"}}"#),
            rule(r#"{"name":"curl slow","match":{"app":"curl"},"action":{"type":"limit","upload":"1MB/s"}}"#),
        ])
        .unwrap();
        let p = proc_("/usr/bin/curl");

        let lan = conn("1.2.3.4:443", 1);
        let d = set.decide(&MatchCtx { conn: &lan, process: Some(&p) }, &[]);
        assert_eq!(d.access_rule, Some(2));
        assert!(!d.blocked);
        assert_eq!(d.limits, vec![1, 4]);

        let wan = conn("8.8.8.8:443", 1);
        let d = set.decide(&MatchCtx { conn: &wan, process: Some(&p) }, &[]);
        assert_eq!(d.access_rule, Some(3));
        assert!(d.blocked);
    }

    #[test]
    fn disabled_rules_are_ignored() {
        let set =
            RuleSet::new(vec![rule(r#"{"enabled":false,"match":{"app":"curl"},"action":{"type":"block"}}"#)])
                .unwrap();
        let (c, p) = (conn("8.8.8.8:443", 1), proc_("/usr/bin/curl"));
        assert!(!set.decide(&MatchCtx { conn: &c, process: Some(&p) }, &[]).blocked);
    }

    #[test]
    fn exhausted_quota_blocks() {
        let set = RuleSet::new(vec![
            rule(r#"{"match":{"app":"curl"},"action":{"type":"quota","limit":"1GB","period":"day"}}"#),
            rule(r#"{"action":{"type":"allow"}}"#),
        ])
        .unwrap();
        let (c, p) = (conn("8.8.8.8:443", 1), proc_("/usr/bin/curl"));
        let ctx = MatchCtx { conn: &c, process: Some(&p) };
        let d = set.decide(&ctx, &[]);
        assert!(!d.blocked);
        assert_eq!(d.quotas, vec![1]);
        let d = set.decide(&ctx, &[1]);
        assert!(d.blocked);
        assert_eq!(d.access_rule, Some(1));
    }

    #[test]
    fn validation_and_ids() {
        let mut set = RuleSet::default();
        assert!(set.add(rule(r#"{"action":{"type":"limit"}}"#)).is_err());
        assert!(set.add(rule(r#"{"action":{"type":"limit","download":0}}"#)).is_err());
        assert!(set.add(rule(r#"{"action":{"type":"quota","limit":"1GB","period":"day"}}"#)).is_err());
        assert_eq!(set.add(rule(r#"{"id":7,"action":{"type":"allow"}}"#)).unwrap(), 7);
        assert_eq!(set.add(rule(r#"{"id":7,"action":{"type":"allow"}}"#)).unwrap(), 8);
        assert_eq!(set.add(rule(r#"{"action":{"type":"allow"}}"#)).unwrap(), 9);
        set.remove(8).unwrap();
        assert_eq!(set.remove(8), Err(RuleError::NotFound(8)));
    }

    #[test]
    fn schedules() {
        let s: Schedule =
            serde_json::from_str(r#"{"days":["mon","tue"],"from":"09:00","until":"17:30"}"#).unwrap();
        assert!(s.active(Day::Mon, 9 * 60));
        assert!(s.active(Day::Tue, 17 * 60 + 29));
        assert!(!s.active(Day::Tue, 17 * 60 + 30));
        assert!(!s.active(Day::Wed, 12 * 60));
        assert!(!s.active(Day::Mon, 8 * 60 + 59));

        // Overnight, starting Friday: covers Fri 23:00 and Sat 05:00, not Fri 05:00.
        let night: Schedule =
            serde_json::from_str(r#"{"days":["fri"],"from":"22:00","until":"06:00"}"#).unwrap();
        assert!(night.active(Day::Fri, 23 * 60));
        assert!(night.active(Day::Sat, 5 * 60));
        assert!(!night.active(Day::Fri, 5 * 60));
        assert!(!night.active(Day::Sat, 23 * 60));

        let weekend: Schedule = serde_json::from_str(r#"{"days":["sat","sun"]}"#).unwrap();
        assert!(weekend.active(Day::Sun, 0) && !weekend.active(Day::Mon, 600));
        assert_eq!(Day::Mon.prev(), Day::Sun);
        assert_eq!("Wednesday".parse::<Day>(), Ok(Day::Wed));
        assert_eq!("sat".parse::<Day>(), Ok(Day::Sat));
        assert!("su".parse::<Day>().is_err() && "funday".parse::<Day>().is_err());

        assert_eq!("24:00".parse::<TimeOfDay>().unwrap().0, 1440);
        for bad in ["24:01", "9", "09:60", "ab:cd"] {
            assert!(bad.parse::<TimeOfDay>().is_err(), "{bad}");
        }
        assert_eq!(serde_json::to_string(&TimeOfDay(9 * 60 + 5)).unwrap(), r#""09:05""#);
    }

    #[test]
    fn summaries() {
        let r = rule(
            r#"{"match":{"app":"steam","protocol":"tcp","remote_ports":[443,"27000-27100"]},"action":{"type":"limit","download":"1MB/s"},"schedule":{"days":["fri","mon","tue","wed","thu"],"from":"09:00","until":"17:00"}}"#,
        );
        assert_eq!(r.action_summary(), "limit down 1.00 MB/s");
        assert_eq!(r.scope_summary(), "app steam · TCP · port 443,27000-27100 · weekdays 09:00-17:00");
        let q = rule(
            r#"{"action":{"type":"quota","limit":"20GB","period":"month","direction":"in"},"match":{"remote":["10.0.0.0/8"]},"schedule":{"days":["sat"]}}"#,
        );
        assert_eq!(q.action_summary(), "quota 20.00 GB per month incoming");
        assert_eq!(q.scope_summary(), "all apps · to 10.0.0.0/8 · Sat");
    }

    #[test]
    fn effective_rules_follow_schedules() {
        let set = RuleSet::new(vec![rule(
            r#"{"match":{"app":"steam"},"action":{"type":"block"},"schedule":{"days":["mon"],"from":"09:00","until":"17:00"}}"#,
        )])
        .unwrap();
        let net = crate::network::Network::default();
        assert_eq!(set.effective_at(Day::Mon, 600, &net).enabled().count(), 1);
        assert_eq!(set.effective_at(Day::Mon, 1200, &net).enabled().count(), 0);
        assert!(set.rules[0].enabled, "the stored rule is untouched");
        let half = r#"{"action":{"type":"allow"},"schedule":{"from":"09:00"}}"#;
        assert!(RuleSet::default().add(rule(half)).is_err());
    }

    #[test]
    fn domain_rules_become_addresses() {
        use crate::dns::DomainPattern;
        let mut set = RuleSet::new(vec![
            rule(r#"{"match":{"domains":["ads.example"]},"action":{"type":"block"}}"#),
            rule(r#"{"match":{"domains":["unknown.example"]},"action":{"type":"block"}}"#),
            rule(
                r#"{"match":{"domains":["cdn.example"],"remote":["10.0.0.0/8"]},"action":{"type":"allow"}}"#,
            ),
        ])
        .unwrap();
        assert_eq!(set.rules[0].scope_summary(), "all apps · domain ads.example");
        let unresolved = conn("192.0.2.1:443", 5000);
        let ctx = MatchCtx { conn: &unresolved, process: None };
        assert!(!set.rules[1].matcher.matches(&ctx), "an unresolved domain matches nothing");
        set.resolve_domains(|d: &[DomainPattern]| match d[0].0.as_str() {
            "ads.example" => vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            "cdn.example" => vec!["10.1.2.3".parse().unwrap(), "192.0.2.9".parse().unwrap()],
            _ => vec![],
        });
        assert_eq!(set.rules[0].matcher.remote.len(), 2);
        assert!(set.rules[0].matcher.matches(&ctx));
        assert!(!set.rules[1].enabled, "disabled until its domain resolves");
        let cdn: Vec<String> = set.rules[2].matcher.remote.iter().map(|n| n.to_string()).collect();
        assert_eq!(cdn, ["10.0.0.0/8", "192.0.2.9/32"], "addresses inside `remote` aren't repeated");
        assert!(RuleSet::default()
            .add(rule(r#"{"match":{"domains":["bad domain"]},"action":{"type":"block"}}"#))
            .is_err());
    }

    #[test]
    fn effective_rules_follow_the_network() {
        use crate::network::Network;
        let set = RuleSet::new(vec![rule(
            r#"{"match":{"app":"steam"},"action":{"type":"block"},"network":{"metered":true}}"#,
        )])
        .unwrap();
        let hotspot = Network { name: Some("Pixel".into()), metered: true };
        let home = Network { name: Some("Home".into()), metered: false };
        assert_eq!(set.effective_at(Day::Mon, 600, &hotspot).enabled().count(), 1);
        assert_eq!(set.effective_at(Day::Mon, 600, &home).enabled().count(), 0);
        assert_eq!(set.rules[0].scope_summary(), "app steam · on metered networks");
        let empty = r#"{"action":{"type":"block"},"network":{}}"#;
        assert!(RuleSet::default().add(rule(empty)).is_err());
    }

    #[test]
    fn port_ranges() {
        assert_eq!("80".parse::<PortRange>().unwrap(), PortRange { start: 80, end: 80 });
        assert_eq!("1-1024".parse::<PortRange>().unwrap(), PortRange { start: 1, end: 1024 });
        assert!("90-80".parse::<PortRange>().is_err());
        assert!("70000".parse::<PortRange>().is_err());
        let json =
            serde_json::to_string(&vec![PortRange { start: 1, end: 2 }, PortRange { start: 5, end: 5 }])
                .unwrap();
        assert_eq!(json, r#"["1-2",5]"#);
    }
}
