//! Types exchanged over the daemon's HTTP API, shared by the daemon and its
//! clients (CLI, desktop app).

use crate::accounting::SystemStats;
use crate::model::{AppId, Connection, Protocol};
use crate::quota::QuotaStatus;
use crate::rules::RuleId;
use serde::{Deserialize, Serialize};

/// A remote address an application exchanged data with this session
/// (`GET /api/remotes`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteView {
    pub ip: std::net::IpAddr,
    /// Reverse-DNS name, once resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The domain apps looked up for it (from DNS answers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(flatten)]
    pub location: Location,
    pub up: u64,
    pub down: u64,
    pub ports: Vec<u16>,
    pub protocols: Vec<Protocol>,
    /// Applications that talked to it (only when not filtered by app).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<AppId>,
    /// Sockets connected to it right now.
    pub open_connections: usize,
    /// Seconds since the last traffic.
    pub idle_secs: u64,
}

/// `GET /api/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub uptime_secs: u64,
    pub enforcement: EnforcementStatus,
    /// Country/ASN database files in use (empty: none installed).
    #[serde(default)]
    pub geoip: Vec<String>,
}

/// Where a remote address is: country and network owner, when a GeoIP
/// database is installed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// ISO 3166 country code, e.g. `DE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// The network's owner, e.g. `Google LLC`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// An app is moving data far above its usual rate.
    TrafficSpike {
        app: AppId,
        name: String,
        /// `in` for downloads, `out` for uploads.
        direction: crate::model::Direction,
        /// Bytes/s now.
        rate: u64,
        /// Bytes/s before the spike.
        usual: u64,
    },
    /// A quota passed 80% of its cap in the current period.
    QuotaWarning {
        rule: RuleId,
        name: String,
        percent: u8,
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
    /// The user paused all rules: nothing is blocked or limited.
    Paused,
    /// The user resumed all rules.
    Resumed,
    /// A new app wants to use the network and is held until the user
    /// answers ("ask about new apps" is on).
    AskNewApp {
        app: AppId,
        name: String,
    },
    /// An app's program file changed: usually an update, possibly a
    /// replaced binary.
    ProgramChanged {
        app: AppId,
        name: String,
    },
    /// Rules were restored from a backup.
    Imported {
        /// Rules added (merge) or now in place (replace).
        rules: usize,
        replaced: bool,
    },
    /// The machine moved to another network, or its metered state changed.
    NetworkChanged {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        metered: bool,
        /// Rules with a network condition that apply now.
        rules: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    /// Unix time in milliseconds.
    pub time: i64,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementStatus {
    pub monitor: String,
    pub enforcer: String,
    pub enforcing: bool,
    pub warnings: Vec<String>,
    pub error: Option<String>,
    /// All rules are paused by the user (traffic is still counted).
    #[serde(default)]
    pub paused: bool,
}

/// An application row in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppView {
    pub app: AppId,
    /// Display name: the app's own ("Firefox") when known, else the program's.
    pub name: String,
    /// Whether `GET /api/icon?app=` has an icon for it.
    #[serde(default)]
    pub icon: bool,
    /// Held until the user answers whether it may use the network.
    #[serde(default)]
    pub waiting: bool,
    /// SHA-256 of its program file, once computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// When that program first appeared (unix seconds): changes when the
    /// program is updated or replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_since: Option<i64>,
    pub pids: Vec<u32>,
    pub connections: usize,
    pub rate_up: u64,
    pub rate_down: u64,
    pub total_up: u64,
    pub total_down: u64,
    /// Recent `(up, down)` rate samples; omitted in live updates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<(u64, u64)>,
    /// Rules scoped to this app.
    pub rules: Vec<RuleId>,
    /// The app-wide block rule, if any (what the UI's block toggle controls).
    pub block_rule: Option<RuleId>,
    /// The app-wide limit rule, if any.
    pub limit_rule: Option<RuleId>,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnView {
    #[serde(flatten)]
    pub conn: Connection,
    /// Reverse-DNS name of the remote address, once resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    /// The domain the app looked up for this address (from DNS answers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(flatten)]
    pub location: Location,
    pub app: Option<AppId>,
    pub name: Option<String>,
    pub rate_up: u64,
    pub rate_down: u64,
    pub blocked: bool,
    pub access_rule: Option<RuleId>,
    pub limits: Vec<RuleId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overview {
    pub mono_ms: u64,
    pub system: SystemStats,
    pub apps: Vec<AppView>,
    pub quotas: Vec<QuotaStatus>,
    pub status: EnforcementStatus,
    pub last_event: u64,
    #[serde(default)]
    pub network: NetworkView,
    /// New apps waiting for the user's answer, oldest first.
    #[serde(default)]
    pub prompts: Vec<Prompt>,
}

/// A new app held until the user decides (`GET /api/prompts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    pub app: AppId,
    pub name: String,
    /// When it was first seen, unix milliseconds.
    pub since: i64,
}

/// The user's answer to a [`Prompt`] (`POST /api/prompts/answer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    /// Allow it from now on.
    Allow,
    /// Allow it until nwld restarts; ask again after that.
    Once,
    /// Block it (adds a rule).
    Block,
}

/// Daemon settings (`GET/PUT /api/settings`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonSettings {
    /// Hold apps using the network for the first time until the user answers.
    #[serde(default)]
    pub ask_new_apps: bool,
}

/// The current network, what was detected and what the user overrode
/// (`GET /api/network`; part of the overview).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether rules treat it as metered.
    pub metered: bool,
    /// What the operating system says (`None`: it can't tell).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected: Option<bool>,
    /// The user's choice for this network (`None`: follow detection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
    /// How the network is detected, e.g. `NetworkManager`.
    #[serde(default)]
    pub source: String,
}

/// `GET /api/history`: traffic over a time range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryView {
    pub range: crate::history::Range,
    /// Seconds each point covers.
    pub step_secs: i64,
    /// The machine's traffic, or one app's when filtered, oldest first.
    pub points: Vec<crate::history::Point>,
    /// Per-app totals over the range, most traffic first.
    pub apps: Vec<UsageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageDay {
    pub day: String,
    pub apps: Vec<UsageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEntry {
    pub app: AppId,
    pub name: String,
    pub up: u64,
    pub down: u64,
}

/// Recognizes a backup file.
pub const BACKUP_FORMAT: &str = "nattowok-backup";
/// The newest backup version this build reads.
pub const BACKUP_VERSION: u32 = 1;

/// `GET /api/export`, `POST /api/import`: everything the user configured,
/// to keep a copy or move to another computer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Backup {
    /// Always [`BACKUP_FORMAT`].
    pub format: String,
    pub version: u32,
    /// When it was made (RFC 3339), for people reading the file.
    #[serde(default)]
    pub exported: String,
    #[serde(default)]
    pub rules: Vec<crate::rules::Rule>,
    /// Networks the user marked metered or not.
    #[serde(default)]
    pub network: crate::network::Overrides,
}

/// The outcome of `POST /api/import`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportResult {
    /// Rules added (merge) or now in place (replace).
    pub rules: usize,
    /// Rules of the backup already present (merge only).
    pub skipped: usize,
    pub replaced: bool,
}
