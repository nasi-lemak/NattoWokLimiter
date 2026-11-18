//! Desktop notifications for daemon events.
//!
//! The daemon usually runs as root, outside the user's desktop session, so
//! notifications are shown by the desktop app: the poller hands it every new
//! event and those the user enabled become system notifications (the
//! freedesktop notification service on Linux, toasts on Windows, the
//! Notification Center on macOS).

use nwl_core::api::EventKind;
use nwl_core::model::Direction;
use nwl_core::rate::format_bytes;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Which events become notifications. Saved per user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub enabled: bool,
    pub new_app: bool,
    pub traffic_spike: bool,
    pub quota_warning: bool,
    pub quota_exhausted: bool,
    pub enforcement: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            new_app: true,
            traffic_spike: true,
            quota_warning: true,
            quota_exhausted: true,
            enforcement: true,
        }
    }
}

fn config_path() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("NattoWokLimiter"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/NattoWokLimiter"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|c| c.join("nattowok"))
    };
    base.map(|b| b.join("desktop.json"))
}

impl Settings {
    pub fn load() -> Self {
        config_path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path().ok_or("no configuration directory")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| format!("saving {}: {e}", path.display()))
    }

    pub fn wants(&self, kind: &EventKind) -> bool {
        self.enabled
            && match kind {
                EventKind::NewApp { .. } => self.new_app,
                EventKind::TrafficSpike { .. } => self.traffic_spike,
                EventKind::QuotaWarning { .. } => self.quota_warning,
                EventKind::QuotaExhausted { .. } => self.quota_exhausted,
                EventKind::EnforcementError { .. } | EventKind::EnforcementRecovered => self.enforcement,
                // The user made these changes themselves.
                EventKind::RuleAdded { .. }
                | EventKind::RuleChanged { .. }
                | EventKind::RuleRemoved { .. }
                | EventKind::Paused
                | EventKind::Resumed => false,
            }
    }
}

fn rule_label(rule: u64, name: &str) -> String {
    if name.is_empty() {
        format!("Rule #{rule}")
    } else {
        format!("“{name}”")
    }
}

/// Title and body for an event, or `None` for events never shown.
pub fn text(kind: &EventKind) -> Option<(String, String)> {
    Some(match kind {
        EventKind::NewApp { app, name } => {
            (format!("{name} is using the network"), format!("First connection from {app}."))
        }
        EventKind::TrafficSpike { name, direction, rate, usual, .. } => {
            let verb = if *direction == Direction::Out { "uploading" } else { "downloading" };
            (
                format!("{name} is {verb} at {}/s", format_bytes(*rate)),
                format!("Usually about {}/s.", format_bytes(*usual)),
            )
        }
        EventKind::QuotaWarning { rule, name, percent } => (
            format!("{percent}% of quota used"),
            format!("{} is close to its limit for this period.", rule_label(*rule, name)),
        ),
        EventKind::QuotaExhausted { rule, name } => (
            "Quota reached".to_string(),
            format!(
                "{} is used up; its traffic is blocked until the period resets.",
                rule_label(*rule, name)
            ),
        ),
        EventKind::EnforcementError { message } => {
            ("Rules are not being applied".to_string(), message.clone())
        }
        EventKind::EnforcementRecovered => {
            ("Rules are applied again".to_string(), "Blocks and limits are active.".to_string())
        }
        EventKind::RuleAdded { .. }
        | EventKind::RuleChanged { .. }
        | EventKind::RuleRemoved { .. }
        | EventKind::Paused
        | EventKind::Resumed => return None,
    })
}

/// Shows a system notification.
pub fn show(title: &str, body: &str) -> Result<(), String> {
    notify_rust::Notification::new()
        .appname("NattoWok Limiter")
        .summary(title)
        .body(body)
        .icon("network-transmit-receive")
        .show()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nwl_core::model::AppId;

    #[test]
    fn texts_and_filters() {
        let spike = EventKind::TrafficSpike {
            app: AppId("/usr/bin/dropbox".into()),
            name: "dropbox".into(),
            direction: Direction::Out,
            rate: 8_000_000,
            usual: 12_000,
        };
        assert_eq!(
            text(&spike),
            Some(("dropbox is uploading at 8.00 MB/s".into(), "Usually about 12.00 kB/s.".into()))
        );
        let rule = EventKind::RuleAdded { rule: 1, name: "x".into() };
        assert_eq!(text(&rule), None);

        let mut s = Settings::default();
        assert!(s.wants(&spike) && !s.wants(&rule));
        s.traffic_spike = false;
        assert!(!s.wants(&spike));
        s = Settings { enabled: false, ..Settings::default() };
        assert!(!s.wants(&EventKind::EnforcementRecovered));
        // Older or partial files fill missing switches with defaults.
        let partial: Settings = serde_json::from_str(r#"{"new_app": false}"#).unwrap();
        assert!(!partial.new_app && partial.traffic_spike);
    }
}
