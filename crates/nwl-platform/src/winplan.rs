//! Translates a [`RuleSet`] into Windows Firewall rules and QoS policies, as
//! one PowerShell script. Pure and platform-independent, so it is unit tested
//! everywhere; `windows::WindowsEnforcer` runs the script.
//!
//! Mapping and its limits (reported as warnings, never silently dropped):
//!
//! * `block` and exhausted quotas → `New-NetFirewallRule -Action Block`.
//!   Windows Firewall gives block rules precedence over allow rules, so an
//!   `allow` rule cannot carve an exception out of a later `block` rule.
//! * `limit` upload → `New-NetQosPolicy -ThrottleRateActionBitsPerSecond`
//!   (built-in QoS packet scheduler). Download limits need a packet-level
//!   driver (WinDivert/WFP callout) and are not supported yet.
//! * App patterns are resolved to the executables seen so far; a pattern that
//!   is a full path without wildcards is used directly.

use nwl_core::model::{AppId, Direction, Protocol};
use nwl_core::rules::{Action, AppPattern, Matcher, Rule, RuleId, RuleSet};
use std::collections::BTreeSet;
use std::fmt::Write;

/// Firewall rule group and QoS policy name prefix owned by NattoWokLimiter.
pub const GROUP: &str = "NattoWokLimiter";

#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    /// PowerShell statements creating the desired state.
    pub statements: Vec<String>,
    pub warnings: Vec<String>,
}

/// Single-quoted PowerShell string literal.
fn ps(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn ps_list(items: &[String]) -> String {
    items.iter().map(|i| ps(i)).collect::<Vec<_>>().join(",")
}

/// Executables a pattern refers to.
fn programs(pattern: &AppPattern, known_apps: &BTreeSet<AppId>) -> Vec<String> {
    let mut out: Vec<String> = known_apps
        .iter()
        .filter(|a| pattern.matches_app(a) && a.0.contains(['\\', '/']))
        .map(|a| a.0.clone())
        .collect();
    if out.is_empty() && pattern.is_path() && !pattern.0.contains(['*', '?']) {
        out.push(pattern.0.clone());
    }
    out
}

pub fn plan(rules: &RuleSet, exhausted: &[RuleId], known_apps: &BTreeSet<AppId>) -> Plan {
    let mut plan = Plan::default();
    let mut seen_allow: Option<&Rule> = None;
    for rule in rules.enabled() {
        let targets: Vec<Option<String>> = match &rule.matcher.app {
            Some(p) => programs(p, known_apps).into_iter().map(Some).collect(),
            None => vec![None],
        };
        if rule.matcher.uid.is_some() {
            plan.warnings.push(format!("rule {}: matching by uid is not supported on Windows", rule.id));
            continue;
        }
        if !rule.matcher.local_ports.is_empty() && matches!(rule.action, Action::Limit { .. }) {
            plan.warnings.push(format!("rule {}: local ports are ignored for limits on Windows", rule.id));
        }
        match &rule.action {
            Action::Allow => {
                seen_allow.get_or_insert(rule);
            }
            Action::Block { direction } => {
                if let Some(allow) = seen_allow {
                    plan.warnings.push(format!(
                        "rule {}: Windows Firewall applies block rules before allow rules, so allow rule {} does not override it",
                        rule.id, allow.id
                    ));
                }
                for t in &targets {
                    firewall(&mut plan, rule, *direction, t.as_deref());
                }
            }
            Action::Quota { .. } if exhausted.contains(&rule.id) => {
                for t in &targets {
                    firewall(&mut plan, rule, Direction::Both, t.as_deref());
                }
            }
            Action::Quota { .. } => {}
            Action::Limit { download, upload } => {
                if download.is_some() {
                    plan.warnings.push(format!(
                        "rule {}: download limits are not supported on Windows yet (needs a packet driver)",
                        rule.id
                    ));
                }
                if let Some(rate) = upload {
                    for (i, t) in targets.iter().enumerate() {
                        let bits = rate.bytes_per_sec().saturating_mul(8);
                        qos(&mut plan, rule, bits, t.as_deref(), i + 1);
                    }
                }
            }
        }
    }
    plan
}

fn firewall(plan: &mut Plan, rule: &Rule, direction: Direction, program: Option<&str>) {
    let m = &rule.matcher;
    let protocols: Vec<Option<Protocol>> = match m.protocol {
        Some(p) => vec![Some(p)],
        // Port filters require a concrete protocol.
        None if !m.remote_ports.is_empty() || !m.local_ports.is_empty() => {
            vec![Some(Protocol::Tcp), Some(Protocol::Udp)]
        }
        None => vec![None],
    };
    let dirs: Vec<&str> = [("Outbound", direction.includes_out()), ("Inbound", direction.includes_in())]
        .into_iter()
        .filter_map(|(d, on)| on.then_some(d))
        .collect();
    for dir in dirs {
        for proto in &protocols {
            let mut s = format!(
                "New-NetFirewallRule -Group {} -DisplayName {} -Direction {dir} -Action Block",
                ps(GROUP),
                ps(&display_name(rule))
            );
            if let Some(p) = program {
                let _ = write!(s, " -Program {}", ps(p));
            }
            if !m.remote.is_empty() {
                let nets: Vec<String> = m.remote.iter().map(|n| n.to_string()).collect();
                let _ = write!(s, " -RemoteAddress {}", ps_list(&nets));
            }
            if let Some(p) = proto {
                let _ = write!(s, " -Protocol {}", p.to_string().to_uppercase());
            }
            if !m.remote_ports.is_empty() {
                let ports: Vec<String> = m.remote_ports.iter().map(|r| r.to_string()).collect();
                let _ = write!(s, " -RemotePort {}", ps_list(&ports));
            }
            if !m.local_ports.is_empty() {
                let ports: Vec<String> = m.local_ports.iter().map(|r| r.to_string()).collect();
                let _ = write!(s, " -LocalPort {}", ps_list(&ports));
            }
            s.push_str(" | Out-Null");
            plan.statements.push(s);
        }
    }
}

fn qos(plan: &mut Plan, rule: &Rule, bits_per_sec: u64, program: Option<&str>, n: usize) {
    let m: &Matcher = &rule.matcher;
    if program.is_none() && m.remote.is_empty() && m.remote_ports.is_empty() {
        plan.warnings.push(format!(
            "rule {}: a global upload limit is not supported on Windows; scope it to an app or network",
            rule.id
        ));
        return;
    }
    if m.remote.len() > 1 || m.remote_ports.len() > 1 {
        plan.warnings.push(format!(
            "rule {}: Windows QoS policies take one network and one port range; using the first",
            rule.id
        ));
    }
    let mut s = format!(
        "New-NetQosPolicy -Name {} -PolicyStore ActiveStore -ThrottleRateActionBitsPerSecond {bits_per_sec}",
        ps(&format!("{} #{n}", display_name(rule)))
    );
    if let Some(p) = program {
        let _ = write!(s, " -AppPathNameMatchCondition {}", ps(p));
    }
    if let Some(net) = m.remote.first() {
        let _ = write!(s, " -IPDstPrefixMatchCondition {}", ps(&net.to_string()));
    }
    if let Some(p) = m.protocol {
        let _ = write!(s, " -IPProtocolMatchCondition {}", p.to_string().to_uppercase());
    }
    if let Some(r) = m.remote_ports.first() {
        let _ = write!(s, " -IPDstPortStartMatchCondition {} -IPDstPortEndMatchCondition {}", r.start, r.end);
    }
    s.push_str(" -Confirm:$false | Out-Null");
    plan.statements.push(s);
}

fn display_name(rule: &Rule) -> String {
    if rule.name.is_empty() {
        format!("{GROUP} rule {}", rule.id)
    } else {
        format!("{GROUP} rule {}: {}", rule.id, rule.name)
    }
}

/// Removes everything NattoWokLimiter installed.
pub fn clear_script() -> String {
    format!(
        "Get-NetFirewallRule -Group {g} -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n\
         Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.Name -like {p} }} | Remove-NetQosPolicy -PolicyStore ActiveStore -Confirm:$false\n",
        g = ps(GROUP),
        p = ps(&format!("{GROUP} *"))
    )
}

/// Full script: stop on errors, clear our previous state, install the plan.
pub fn script(plan: &Plan) -> String {
    let mut s = String::from("$ErrorActionPreference = 'Stop'\n");
    s.push_str(&clear_script());
    for st in &plan.statements {
        s.push_str(st);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(json: &str) -> RuleSet {
        RuleSet::new(serde_json::from_str(json).unwrap()).unwrap()
    }

    fn apps(list: &[&str]) -> BTreeSet<AppId> {
        list.iter().map(|s| AppId(s.to_string())).collect()
    }

    #[test]
    fn blocks_and_upload_limits() {
        let set = rules(
            r#"[
            {"id":1,"name":"no steam","match":{"app":"steam.exe","remote_ports":[443]},"action":{"type":"block","direction":"out"}},
            {"id":2,"match":{"app":"Dropbox.exe"},"action":{"type":"limit","upload":"1MB/s","download":"5MB/s"}}
        ]"#,
        );
        let known = apps(&[
            r"C:\Program Files (x86)\Steam\steam.exe",
            r"C:\Users\o'neil\Dropbox\Dropbox.exe",
            "System",
        ]);
        let p = plan(&set, &[], &known);
        assert_eq!(
            p.statements,
            vec![
                r"New-NetFirewallRule -Group 'NattoWokLimiter' -DisplayName 'NattoWokLimiter rule 1: no steam' -Direction Outbound -Action Block -Program 'C:\Program Files (x86)\Steam\steam.exe' -Protocol TCP -RemotePort '443' | Out-Null",
                r"New-NetFirewallRule -Group 'NattoWokLimiter' -DisplayName 'NattoWokLimiter rule 1: no steam' -Direction Outbound -Action Block -Program 'C:\Program Files (x86)\Steam\steam.exe' -Protocol UDP -RemotePort '443' | Out-Null",
                r"New-NetQosPolicy -Name 'NattoWokLimiter rule 2 #1' -PolicyStore ActiveStore -ThrottleRateActionBitsPerSecond 8000000 -AppPathNameMatchCondition 'C:\Users\o''neil\Dropbox\Dropbox.exe' -Confirm:$false | Out-Null",
            ]
        );
        assert_eq!(p.warnings.len(), 1, "{:?}", p.warnings);
        assert!(p.warnings[0].contains("download limits"));
    }

    #[test]
    fn exhausted_quota_blocks_both_directions() {
        let set = rules(
            r#"[{"id":5,"match":{"app":"C:\\Games\\game.exe"},"action":{"type":"quota","limit":"1GB","period":"day"}}]"#,
        );
        assert!(plan(&set, &[], &BTreeSet::new()).statements.is_empty());
        let p = plan(&set, &[5], &BTreeSet::new());
        assert_eq!(p.statements.len(), 2);
        assert!(
            p.statements[0].contains("-Direction Outbound") && p.statements[1].contains("-Direction Inbound")
        );
        assert!(p.statements[0].contains(r"-Program 'C:\Games\game.exe'"));
    }

    #[test]
    fn warns_about_unsupported_semantics() {
        let set = rules(
            r#"[{"id":1,"match":{"remote":["10.0.0.0/8"]},"action":{"type":"allow"}},
                {"id":2,"action":{"type":"block"}},
                {"id":3,"action":{"type":"limit","upload":"1MB/s"}}]"#,
        );
        let p = plan(&set, &[], &BTreeSet::new());
        assert_eq!(p.statements.len(), 2);
        assert_eq!(p.warnings.len(), 2, "{:?}", p.warnings);
    }

    #[test]
    fn script_clears_first() {
        let s = script(&Plan { statements: vec!["X".into()], warnings: vec![] });
        assert!(
            s.starts_with("$ErrorActionPreference = 'Stop'\nGet-NetFirewallRule -Group 'NattoWokLimiter'")
        );
        assert!(s.ends_with("X\n"));
    }
}
