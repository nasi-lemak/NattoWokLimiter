//! Types exchanged over the daemon's HTTP API, shared by the daemon and its
//! clients (CLI, desktop app).

use crate::accounting::SystemStats;
use crate::model::{AppId, Connection};
use crate::quota::QuotaStatus;
use crate::rules::RuleId;
use serde::{Deserialize, Serialize};

/// `GET /api/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub uptime_secs: u64,
    pub enforcement: EnforcementStatus,
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
}

/// An application row in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
