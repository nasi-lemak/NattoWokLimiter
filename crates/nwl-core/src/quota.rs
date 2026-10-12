//! Per-period data caps (e.g. "Steam may use 20 GB per month").
//!
//! The tracker is calendar-agnostic: the caller supplies a period key such as
//! `2026-10-12` (day), `2026-W41` (week) or `2026-10` (month), computed in the
//! user's local time. When the key for a rule changes, its usage resets.

use crate::rules::{Action, Period, RuleId, RuleSet};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaUsage {
    pub period_key: String,
    pub used: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuotaTracker {
    usage: HashMap<RuleId, QuotaUsage>,
}

/// Status of one quota rule, for display.
#[derive(Debug, Clone, Serialize)]
pub struct QuotaStatus {
    pub rule: RuleId,
    pub period: Period,
    pub period_key: String,
    pub used: u64,
    pub limit: u64,
    pub exhausted: bool,
}

impl QuotaTracker {
    /// Adds traffic counted against `rule` in the period identified by `key`.
    pub fn record(&mut self, rule: RuleId, key: &str, bytes: u64) {
        let entry =
            self.usage.entry(rule).or_insert_with(|| QuotaUsage { period_key: key.to_string(), used: 0 });
        if entry.period_key != key {
            *entry = QuotaUsage { period_key: key.to_string(), used: 0 };
        }
        entry.used = entry.used.saturating_add(bytes);
    }

    pub fn used(&self, rule: RuleId, key: &str) -> u64 {
        self.usage.get(&rule).filter(|u| u.period_key == key).map_or(0, |u| u.used)
    }

    /// Reports every enabled quota rule. `key_for` maps a period to the
    /// current period key.
    pub fn status(&self, rules: &RuleSet, key_for: impl Fn(Period) -> String) -> Vec<QuotaStatus> {
        rules
            .enabled()
            .filter_map(|r| match r.action {
                Action::Quota { limit, period, .. } => {
                    let key = key_for(period);
                    let used = self.used(r.id, &key);
                    Some(QuotaStatus {
                        rule: r.id,
                        period,
                        period_key: key,
                        used,
                        limit: limit.0,
                        exhausted: used >= limit.0,
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// Drops usage for rules that no longer exist.
    pub fn retain_rules(&mut self, rules: &RuleSet) {
        self.usage.retain(|id, _| rules.get(*id).is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_on_new_period() {
        let mut q = QuotaTracker::default();
        q.record(1, "2026-10-12", 100);
        q.record(1, "2026-10-12", 50);
        assert_eq!(q.used(1, "2026-10-12"), 150);
        assert_eq!(q.used(1, "2026-10-13"), 0);
        q.record(1, "2026-10-13", 5);
        assert_eq!(q.used(1, "2026-10-13"), 5);
    }

    #[test]
    fn status_reports_exhaustion() {
        let rules = RuleSet::new(vec![serde_json::from_str(
            r#"{"id":3,"match":{"app":"steam"},"action":{"type":"quota","limit":1000,"period":"month"}}"#,
        )
        .unwrap()])
        .unwrap();
        let mut q = QuotaTracker::default();
        q.record(3, "2026-10", 999);
        assert!(!q.status(&rules, |_| "2026-10".into())[0].exhausted);
        q.record(3, "2026-10", 1);
        let s = q.status(&rules, |_| "2026-10".into());
        assert!(s[0].exhausted);
        assert!(!q.status(&rules, |_| "2026-11".into())[0].exhausted);
    }
}
