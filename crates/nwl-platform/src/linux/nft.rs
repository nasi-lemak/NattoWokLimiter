//! Renders a [`RuleSet`] into one atomic nftables script.
//!
//! Layout of the generated `inet` table:
//!
//! 1. loopback is accepted first unless loopback policing is enabled;
//! 2. every limit rule (they all apply, see `nwl_core::rules`), each backed by
//!    a named `limit` object so a rule spanning several cgroups or address
//!    families shares one budget;
//! 3. drops for exhausted quotas;
//! 4. access rules in order, `accept` / `drop`, first match wins.
//!
//! Egress is policed in the `output` hook, ingress in `input`. Policing
//! (dropping above the rate) is used instead of queueing: TCP reacts to the
//! drops by slowing down, and it works identically in both directions without
//! an IFB device.

use nwl_core::model::Direction;
use nwl_core::rules::{Action, Matcher, PortRange, Rule, RuleId, RuleSet};
use std::collections::BTreeMap;
use std::fmt::Write;

pub const TABLE: &str = "nattowok";

/// A cgroup as nftables addresses it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CgroupRef {
    /// Path relative to `/sys/fs/cgroup`.
    pub path: String,
    /// Depth in the cgroup2 hierarchy.
    pub level: usize,
}

pub struct RenderInput<'a> {
    pub table: &'a str,
    pub rules: &'a RuleSet,
    pub exhausted_quotas: &'a [RuleId],
    /// cgroups holding the processes each app-scoped rule targets.
    pub app_cgroups: &'a BTreeMap<RuleId, Vec<CgroupRef>>,
    pub include_loopback: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hook {
    Output,
    Input,
}

pub fn render(input: &RenderInput<'_>) -> String {
    let mut objects = String::new();
    let mut chains: [(Hook, String); 2] = [(Hook::Output, String::new()), (Hook::Input, String::new())];

    let enabled: Vec<&Rule> = input.rules.enabled().collect();
    let limits = enabled.iter().filter(|r| matches!(r.action, Action::Limit { .. }));
    let quotas = enabled
        .iter()
        .filter(|r| matches!(r.action, Action::Quota { .. }) && input.exhausted_quotas.contains(&r.id));
    let access = enabled.iter().filter(|r| r.action.is_access());

    for rule in limits.chain(quotas).chain(access) {
        let cgroups = input.app_cgroups.get(&rule.id).map(Vec::as_slice).unwrap_or(&[]);
        for (hook, out) in chains.iter_mut() {
            let Some(verdict) = verdict(rule, *hook, &mut objects) else { continue };
            for sel in selectors(&rule.matcher, *hook, cgroups) {
                let sel = if sel.is_empty() { String::new() } else { format!("{sel} ") };
                let _ = writeln!(out, "\t\t{sel}{verdict} comment \"{}\"", comment(rule));
            }
        }
    }

    let mut s = String::new();
    // Creating then deleting makes the script work whether or not the table
    // exists; the whole file is applied as one atomic transaction.
    let _ = writeln!(s, "table inet {0}\ndelete table inet {0}\ntable inet {0} {{", input.table);
    s.push_str(&objects);
    for (hook, body) in &chains {
        let (name, iface) = match hook {
            Hook::Output => ("output", "oifname"),
            Hook::Input => ("input", "iifname"),
        };
        let _ = writeln!(s, "\tchain {name} {{");
        let _ = writeln!(s, "\t\ttype filter hook {name} priority filter; policy accept;");
        if !input.include_loopback {
            let _ = writeln!(s, "\t\t{iface} \"lo\" accept");
        }
        s.push_str(body);
        s.push_str("\t}\n");
    }
    s.push_str("}\n");
    s
}

/// The verdict a rule contributes to a hook, declaring named objects it
/// needs. `None` when the rule has no effect in that direction.
fn verdict(rule: &Rule, hook: Hook, objects: &mut String) -> Option<String> {
    match &rule.action {
        Action::Allow => Some("accept".into()),
        Action::Block { direction } => applies(*direction, hook).then(|| "drop".into()),
        Action::Quota { .. } => Some("drop".into()),
        Action::Limit { download, upload } => {
            let (rate, suffix) = match hook {
                Hook::Output => (upload.as_ref()?, "up"),
                Hook::Input => (download.as_ref()?, "down"),
            };
            let name = format!("r{}_{suffix}", rule.id);
            // No explicit burst: in byte mode the kernel's bucket already
            // holds one second worth of the rate, which absorbs TCP bursts.
            // The long-run rate is exact; the first second may overshoot.
            let bps = rate.bytes_per_sec();
            let _ = writeln!(objects, "\tlimit {name} {{ rate over {bps} bytes/second; }}");
            Some(format!("limit name \"{name}\" drop"))
        }
    }
}

fn applies(direction: Direction, hook: Hook) -> bool {
    match hook {
        Hook::Output => direction.includes_out(),
        Hook::Input => direction.includes_in(),
    }
}

fn comment(rule: &Rule) -> String {
    let name: String =
        rule.name.chars().filter(|c| !c.is_control() && *c != '"' && *c != '\\').take(100).collect();
    if name.is_empty() {
        format!("nwl rule {}", rule.id)
    } else {
        format!("nwl rule {}: {name}", rule.id)
    }
}

/// Match expressions for a rule in one hook; one entry per nft rule needed.
/// Empty when the rule cannot currently match anything (app not running).
fn selectors(m: &Matcher, hook: Hook, cgroups: &[CgroupRef]) -> Vec<String> {
    let cg_parts: Vec<String> = if m.app.is_some() {
        cgroups.iter().map(|c| format!("socket cgroupv2 level {} \"{}\"", c.level, c.path)).collect()
    } else {
        vec![String::new()]
    };

    let (addr_dir, remote_port_dir, local_port_dir) = match hook {
        Hook::Output => ("daddr", "dport", "sport"),
        Hook::Input => ("saddr", "sport", "dport"),
    };
    let v4: Vec<String> = m.remote.iter().filter(|n| n.addr().is_ipv4()).map(|n| n.to_string()).collect();
    let v6: Vec<String> = m.remote.iter().filter(|n| n.addr().is_ipv6()).map(|n| n.to_string()).collect();
    let mut fam_parts = Vec::new();
    if m.remote.is_empty() {
        fam_parts.push(String::new());
    }
    if !v4.is_empty() {
        fam_parts.push(format!("ip {addr_dir} {}", set(&v4)));
    }
    if !v6.is_empty() {
        fam_parts.push(format!("ip6 {addr_dir} {}", set(&v6)));
    }

    let mut l4 = Vec::new();
    let has_ports = !m.remote_ports.is_empty() || !m.local_ports.is_empty();
    let kw = match m.protocol {
        Some(p) => p.to_string(),
        None => "th".to_string(),
    };
    match (m.protocol, has_ports) {
        (Some(p), false) => l4.push(format!("meta l4proto {p}")),
        (None, true) => l4.push("meta l4proto { tcp, udp }".to_string()),
        _ => {}
    }
    if !m.remote_ports.is_empty() {
        l4.push(format!("{kw} {remote_port_dir} {}", ports(&m.remote_ports)));
    }
    if !m.local_ports.is_empty() {
        l4.push(format!("{kw} {local_port_dir} {}", ports(&m.local_ports)));
    }
    if let Some(uid) = m.uid {
        l4.push(format!("meta skuid {uid}"));
    }
    let tail = l4.join(" ");

    let mut out = Vec::new();
    for cg in &cg_parts {
        for fam in &fam_parts {
            let parts: Vec<&str> =
                [cg.as_str(), fam.as_str(), tail.as_str()].into_iter().filter(|p| !p.is_empty()).collect();
            out.push(parts.join(" "));
        }
    }
    out
}

fn set(items: &[String]) -> String {
    if items.len() == 1 {
        items[0].clone()
    } else {
        format!("{{ {} }}", items.join(", "))
    }
}

fn ports(ranges: &[PortRange]) -> String {
    set(&ranges.iter().map(|r| r.to_string()).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(json: &str) -> RuleSet {
        RuleSet::new(serde_json::from_str(json).unwrap()).unwrap()
    }

    fn cg(path: &str, level: usize) -> CgroupRef {
        CgroupRef { path: path.into(), level }
    }

    fn render_with(set: &RuleSet, exhausted: &[RuleId], cgs: BTreeMap<RuleId, Vec<CgroupRef>>) -> String {
        render(&RenderInput {
            table: "nwltest",
            rules: set,
            exhausted_quotas: exhausted,
            app_cgroups: &cgs,
            include_loopback: false,
        })
    }

    #[test]
    fn empty_ruleset_is_a_passthrough_table() {
        let out = render_with(&RuleSet::default(), &[], BTreeMap::new());
        assert!(out.starts_with("table inet nwltest\ndelete table inet nwltest\ntable inet nwltest {\n"));
        assert!(out.contains("oifname \"lo\" accept"));
        assert!(out.contains("iifname \"lo\" accept"));
        assert!(!out.contains("drop"));
    }

    #[test]
    fn orders_limits_quotas_then_access() {
        let set = rules(
            r#"[
            {"id":1,"name":"no telemetry","match":{"remote":["10.0.0.0/8","fd00::/8"],"remote_ports":[443]},"action":{"type":"block","direction":"out"}},
            {"id":2,"name":"slow \"curl\"","match":{"app":"curl"},"action":{"type":"limit","download":"1MB/s","upload":"100kB/s"}},
            {"id":3,"match":{"app":"steam"},"action":{"type":"quota","limit":"1GB","period":"day"}},
            {"id":4,"match":{"protocol":"udp","local_ports":["5000-5100"]},"action":{"type":"allow"}}
        ]"#,
        );
        let mut cgs = BTreeMap::new();
        cgs.insert(2, vec![cg("a/nwl-curl-1", 2), cg("b/nwl-curl-1", 2)]);
        cgs.insert(3, vec![cg("nwl-steam-2", 1)]);
        let out = render_with(&set, &[3], cgs);
        let expected = "\
table inet nwltest
delete table inet nwltest
table inet nwltest {
\tlimit r2_up { rate over 100000 bytes/second; }
\tlimit r2_down { rate over 1000000 bytes/second; }
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t\toifname \"lo\" accept
\t\tsocket cgroupv2 level 2 \"a/nwl-curl-1\" limit name \"r2_up\" drop comment \"nwl rule 2: slow curl\"
\t\tsocket cgroupv2 level 2 \"b/nwl-curl-1\" limit name \"r2_up\" drop comment \"nwl rule 2: slow curl\"
\t\tsocket cgroupv2 level 1 \"nwl-steam-2\" drop comment \"nwl rule 3\"
\t\tip daddr 10.0.0.0/8 meta l4proto { tcp, udp } th dport 443 drop comment \"nwl rule 1: no telemetry\"
\t\tip6 daddr fd00::/8 meta l4proto { tcp, udp } th dport 443 drop comment \"nwl rule 1: no telemetry\"
\t\tudp sport 5000-5100 accept comment \"nwl rule 4\"
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname \"lo\" accept
\t\tsocket cgroupv2 level 2 \"a/nwl-curl-1\" limit name \"r2_down\" drop comment \"nwl rule 2: slow curl\"
\t\tsocket cgroupv2 level 2 \"b/nwl-curl-1\" limit name \"r2_down\" drop comment \"nwl rule 2: slow curl\"
\t\tsocket cgroupv2 level 1 \"nwl-steam-2\" drop comment \"nwl rule 3\"
\t\tudp dport 5000-5100 accept comment \"nwl rule 4\"
\t}
}
";
        assert_eq!(out, expected);
    }

    #[test]
    fn app_rules_without_running_processes_render_nothing() {
        let set = rules(r#"[{"id":1,"match":{"app":"curl"},"action":{"type":"block"}}]"#);
        assert!(!render_with(&set, &[], BTreeMap::new()).contains("drop"));
    }

    #[test]
    fn non_exhausted_quotas_and_disabled_rules_render_nothing() {
        let set = rules(
            r#"[{"id":1,"match":{"remote":["1.2.3.4/32"]},"action":{"type":"quota","limit":"1GB","period":"day"}},
                {"id":2,"enabled":false,"action":{"type":"block"}}]"#,
        );
        assert!(!render_with(&set, &[], BTreeMap::new()).contains("drop"));
    }
}
