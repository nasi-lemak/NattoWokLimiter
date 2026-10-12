//! `nwl`: command-line client for the NattoWokLimiter daemon.

use anyhow::{bail, Context};
use clap::{Parser, Subcommand, ValueEnum};
use nwl_core::rate::{format_bytes, ByteSize, Rate};
use nwl_core::rules::{Day, Rule, TimeOfDay};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "Control NattoWokLimiter: see who uses your network, block, limit and cap apps")]
struct Cli {
    /// Daemon address.
    #[arg(long, global = true, default_value = "http://127.0.0.1:7657", env = "NWL_SERVER")]
    server: String,
    /// Print raw JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Dir {
    In,
    Out,
    Both,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Dir::In => "in",
            Dir::Out => "out",
            Dir::Both => "both",
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Per {
    Day,
    Week,
    Month,
}

/// When a rule applies. Without any of these it always applies.
#[derive(clap::Args)]
struct When {
    /// Days the rule is active: `mon,tue,...`, `weekdays` or `weekends`.
    #[arg(long, value_delimiter = ',')]
    days: Vec<String>,
    /// Start of the daily window, `HH:MM` (needs --until).
    #[arg(long, requires = "until")]
    from: Option<TimeOfDay>,
    /// End of the daily window, `HH:MM`; before --from means overnight.
    #[arg(long, requires = "from")]
    until: Option<TimeOfDay>,
}

impl When {
    fn schedule(&self) -> anyhow::Result<Value> {
        let mut days = Vec::new();
        for d in &self.days {
            match d.to_ascii_lowercase().as_str() {
                "weekdays" => days.extend(&Day::ALL[..5]),
                "weekends" => days.extend(&Day::ALL[5..]),
                other => days.push(other.parse::<Day>().map_err(anyhow::Error::msg)?),
            }
        }
        if days.is_empty() && self.from.is_none() {
            return Ok(Value::Null);
        }
        days.sort();
        days.dedup();
        Ok(json!({"days": days, "from": self.from, "until": self.until}))
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Daemon and enforcement status.
    Status,
    /// Applications using the network, busiest first.
    Top {
        /// Refresh every second until interrupted.
        #[arg(short, long)]
        watch: bool,
        /// Show at most this many applications.
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// Open sockets with their owner, rates and applied policy.
    Conns {
        /// Only sockets of this application (full path, as shown by `top`).
        #[arg(long)]
        app: Option<String>,
        /// Include listening sockets.
        #[arg(short, long)]
        all: bool,
    },
    /// List rules in evaluation order.
    Rules,
    /// Block an application (name, path or glob).
    Block {
        app: String,
        #[arg(long, value_enum, default_value_t = Dir::Both)]
        direction: Dir,
        #[command(flatten)]
        when: When,
    },
    /// Limit an application's bandwidth, e.g. `nwl limit steam --down 5MB/s`.
    Limit {
        app: String,
        /// Download limit (e.g. 2MB/s, 500kB/s, 20Mbit).
        #[arg(long)]
        down: Option<Rate>,
        /// Upload limit.
        #[arg(long)]
        up: Option<Rate>,
        #[command(flatten)]
        when: When,
    },
    /// Cap an application's data per period, e.g. `nwl quota steam 50GB --per month`.
    Quota {
        app: String,
        limit: ByteSize,
        #[arg(long, value_enum, default_value_t = Per::Month)]
        per: Per,
        /// Which traffic counts against the quota.
        #[arg(long, value_enum, default_value_t = Dir::Both)]
        direction: Dir,
        #[command(flatten)]
        when: When,
    },
    /// Add a rule from JSON, e.g. `nwl add '{"match":{"remote":["10.0.0.0/8"]},"action":{"type":"block"}}'`.
    Add { json: String },
    /// Delete a rule.
    Rm { id: u64 },
    /// Enable a rule.
    Enable { id: u64 },
    /// Disable a rule without deleting it.
    Disable { id: u64 },
    /// Data used per application over recent days.
    Usage {
        #[arg(long, default_value_t = 7)]
        days: usize,
    },
    /// Recent events (new applications, quotas reached, rule changes).
    Events,
}

struct Client {
    base: String,
    agent: ureq::Agent,
}

impl Client {
    fn new(base: &str) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).build();
        Self { base: base.trim_end_matches('/').to_string(), agent }
    }

    fn call(&self, method: &str, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let req = self.agent.request(method, &format!("{}{path}", self.base)).set("x-nwl-client", "cli");
        let resp = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match resp {
            Ok(r) => Ok(r.into_json().unwrap_or(Value::Null)),
            Err(ureq::Error::Status(code, r)) => {
                let body: Value = r.into_json().unwrap_or(Value::Null);
                let msg = body["error"].as_str().unwrap_or("request failed");
                bail!("daemon returned {code}: {msg}")
            }
            Err(e) => Err(anyhow::Error::new(e))
                .with_context(|| format!("cannot reach nwld at {} (is it running?)", self.base)),
        }
    }

    fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.call("GET", path, None)
    }
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

fn rate(v: &Value) -> String {
    match u(v) {
        0 => "-".into(),
        n => format!("{}/s", format_bytes(n)),
    }
}

/// Prints rows as left-aligned columns; columns listed in `right` are right-aligned.
fn table(headers: &[&str], rows: &[Vec<String>], right: &[usize]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let parts: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if right.contains(&i) {
                    format!("{c:>w$}", w = widths[i])
                } else {
                    format!("{c:<w$}", w = widths[i])
                }
            })
            .collect();
        println!("{}", parts.join("  ").trim_end());
    };
    line(headers.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
}

fn describe_rule(r: &Value) -> String {
    match serde_json::from_value::<Rule>(r.clone()) {
        Ok(rule) => format!("{} · {}", rule.action_summary(), rule.scope_summary()),
        Err(_) => r.to_string(),
    }
}

/// Adds `schedule` to a rule when one was given.
fn with_schedule(mut rule: Value, when: &When) -> anyhow::Result<Value> {
    let schedule = when.schedule()?;
    if !schedule.is_null() {
        rule["schedule"] = schedule;
    }
    Ok(rule)
}

fn print_top(c: &Client, limit: usize) -> anyhow::Result<()> {
    let o = c.get("/api/overview")?;
    let sys = &o["system"];
    println!(
        "total  down {}  up {}  (session {} down, {} up)\n",
        rate(&sys["rate_down"]),
        rate(&sys["rate_up"]),
        format_bytes(u(&sys["total_down"])),
        format_bytes(u(&sys["total_up"]))
    );
    let rows: Vec<Vec<String>> = o["apps"]
        .as_array()
        .into_iter()
        .flatten()
        .take(limit)
        .map(|a| {
            let flag = if a["blocked"].as_bool() == Some(true) {
                "blocked"
            } else if !a["limit_rule"].is_null() {
                "limited"
            } else {
                ""
            };
            vec![
                a["name"].as_str().unwrap_or("?").to_string(),
                rate(&a["rate_down"]),
                rate(&a["rate_up"]),
                format_bytes(u(&a["total_down"]) + u(&a["total_up"])),
                a["connections"].to_string(),
                flag.to_string(),
                a["app"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    table(&["APP", "DOWN", "UP", "SESSION", "CONNS", "POLICY", "PATH"], &rows, &[1, 2, 3, 4]);
    Ok(())
}

fn add_rule(c: &Client, rule: Value) -> anyhow::Result<()> {
    let r = c.call("POST", "/api/rules", Some(rule))?;
    println!("added rule #{}: {}", r["id"], describe_rule(&r));
    Ok(())
}

fn set_enabled(c: &Client, id: u64, enabled: bool) -> anyhow::Result<()> {
    let rules = c.get("/api/rules")?;
    let mut rule = rules
        .as_array()
        .and_then(|rs| rs.iter().find(|r| r["id"].as_u64() == Some(id)).cloned())
        .with_context(|| format!("no rule #{id}"))?;
    rule["enabled"] = json!(enabled);
    c.call("PUT", &format!("/api/rules/{id}"), Some(rule))?;
    println!("rule #{id} {}", if enabled { "enabled" } else { "disabled" });
    Ok(())
}

fn main() -> std::process::ExitCode {
    // Behave like other CLI tools when piped into `head`: exit quietly on
    // a closed pipe instead of panicking.
    #[cfg(unix)]
    // SAFETY: restoring the default disposition of SIGPIPE before any I/O.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    match run(Cli::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let c = Client::new(&cli.server);
    let raw = |path: &str| -> anyhow::Result<()> {
        println!("{}", serde_json::to_string_pretty(&c.get(path)?)?);
        Ok(())
    };
    match cli.cmd {
        Cmd::Status if cli.json => raw("/api/status")?,
        Cmd::Status => {
            let s = c.get("/api/status")?;
            let e = &s["enforcement"];
            println!("nwld {}  up {}s", s["version"].as_str().unwrap_or("?"), s["uptime_secs"]);
            println!("monitor   {}", e["monitor"].as_str().unwrap_or("?"));
            println!("enforcer  {}", e["enforcer"].as_str().unwrap_or("?"));
            println!("enforcing {}", e["enforcing"]);
            if let Some(err) = e["error"].as_str() {
                println!("ERROR     {err}");
            }
            for w in e["warnings"].as_array().into_iter().flatten() {
                println!("warning   {}", w.as_str().unwrap_or(""));
            }
        }
        Cmd::Top { .. } if cli.json => raw("/api/apps")?,
        Cmd::Top { watch, limit } => loop {
            if watch {
                print!("\x1b[2J\x1b[H");
            }
            print_top(&c, limit)?;
            if !watch {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        },
        Cmd::Conns { app, all } => {
            let path = match &app {
                Some(a) => format!("/api/connections?app={}", encode(a)),
                None => "/api/connections".into(),
            };
            let conns = c.get(&path)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&conns)?);
                return Ok(());
            }
            let rows: Vec<Vec<String>> = conns
                .as_array()
                .into_iter()
                .flatten()
                .filter(|x| all || !x["key"]["remote"].is_null())
                .map(|x| {
                    let mut policy = Vec::new();
                    if x["blocked"].as_bool() == Some(true) {
                        policy.push(format!("blocked(#{})", x["access_rule"]));
                    }
                    for l in x["limits"].as_array().into_iter().flatten() {
                        policy.push(format!("limit(#{l})"));
                    }
                    vec![
                        x["name"].as_str().unwrap_or("?").to_string(),
                        x["pid"].as_u64().map_or("-".into(), |p| p.to_string()),
                        x["key"]["protocol"].as_str().unwrap_or("").to_string(),
                        x["key"]["local"].as_str().unwrap_or("").to_string(),
                        x["key"]["remote"].as_str().unwrap_or("*").to_string(),
                        x["remote_host"].as_str().unwrap_or("").to_string(),
                        x["state"].as_str().unwrap_or("").to_string(),
                        rate(&x["rate_down"]),
                        rate(&x["rate_up"]),
                        x["rtt_us"].as_u64().map_or("-".into(), |r| format!("{:.1}ms", r as f64 / 1000.0)),
                        policy.join(" "),
                    ]
                })
                .collect();
            table(
                &["APP", "PID", "PROTO", "LOCAL", "REMOTE", "HOST", "STATE", "DOWN", "UP", "RTT", "POLICY"],
                &rows,
                &[1, 7, 8, 9],
            );
        }
        Cmd::Rules if cli.json => raw("/api/rules")?,
        Cmd::Rules => {
            let rules = c.get("/api/rules")?;
            let rows: Vec<Vec<String>> = rules
                .as_array()
                .into_iter()
                .flatten()
                .map(|r| {
                    vec![
                        format!("#{}", r["id"]),
                        if r["enabled"].as_bool() == Some(false) { "off" } else { "on" }.into(),
                        r["name"].as_str().unwrap_or("").to_string(),
                        describe_rule(r),
                    ]
                })
                .collect();
            if rows.is_empty() {
                println!("no rules");
            } else {
                table(&["ID", "", "NAME", "RULE"], &rows, &[]);
            }
        }
        Cmd::Block { app, direction, when } => add_rule(
            &c,
            with_schedule(
                json!({"name": format!("Block {app}"), "match": {"app": app}, "action": {"type": "block", "direction": direction.as_str()}}),
                &when,
            )?,
        )?,
        Cmd::Limit { app, down, up, when } => {
            if down.is_none() && up.is_none() {
                bail!("give --down and/or --up");
            }
            add_rule(
                &c,
                with_schedule(
                    json!({"name": format!("Limit {app}"), "match": {"app": app}, "action": {"type": "limit", "download": down.map(|r| r.0), "upload": up.map(|r| r.0)}}),
                    &when,
                )?,
            )?
        }
        Cmd::Quota { app, limit, per, direction, when } => {
            let period = match per {
                Per::Day => "day",
                Per::Week => "week",
                Per::Month => "month",
            };
            add_rule(
                &c,
                with_schedule(
                    json!({"name": format!("{app} {limit} per {period}"), "match": {"app": app}, "action": {"type": "quota", "limit": limit.0, "period": period, "direction": direction.as_str()}}),
                    &when,
                )?,
            )?
        }
        Cmd::Add { json } => {
            let rule: Value = serde_json::from_str(&json).context("rule must be JSON")?;
            add_rule(&c, rule)?
        }
        Cmd::Rm { id } => {
            c.call("DELETE", &format!("/api/rules/{id}"), None)?;
            println!("removed rule #{id}");
        }
        Cmd::Enable { id } => set_enabled(&c, id, true)?,
        Cmd::Disable { id } => set_enabled(&c, id, false)?,
        Cmd::Usage { days } if cli.json => raw(&format!("/api/usage?days={days}"))?,
        Cmd::Usage { days } => {
            let usage = c.get(&format!("/api/usage?days={days}"))?;
            let mut totals: std::collections::BTreeMap<String, (String, u64, u64)> = Default::default();
            for day in usage.as_array().into_iter().flatten() {
                for a in day["apps"].as_array().into_iter().flatten() {
                    let e = totals.entry(a["app"].as_str().unwrap_or("").to_string()).or_insert((
                        a["name"].as_str().unwrap_or("").to_string(),
                        0,
                        0,
                    ));
                    e.1 += u(&a["down"]);
                    e.2 += u(&a["up"]);
                }
            }
            let mut rows: Vec<_> = totals.into_values().collect();
            rows.sort_by_key(|r| std::cmp::Reverse(r.1 + r.2));
            let rows: Vec<Vec<String>> = rows
                .into_iter()
                .map(|(name, d, up)| vec![name, format_bytes(d), format_bytes(up), format_bytes(d + up)])
                .collect();
            println!("last {days} days\n");
            table(&["APP", "DOWN", "UP", "TOTAL"], &rows, &[1, 2, 3]);
        }
        Cmd::Events => {
            let events = c.get("/api/events")?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&events)?);
                return Ok(());
            }
            for e in events.as_array().into_iter().flatten() {
                let mut fields = e.as_object().cloned().unwrap_or_default();
                let kind =
                    fields.remove("kind").and_then(|k| k.as_str().map(String::from)).unwrap_or_default();
                fields.remove("id");
                fields.remove("time");
                let detail: Vec<String> =
                    fields.iter().map(|(k, v)| format!("{k}={}", v.to_string().trim_matches('"'))).collect();
                println!("#{:<4} {kind:<22} {}", e["id"], detail.join(" "));
            }
        }
    }
    Ok(())
}

/// Percent-encodes a query parameter value.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
