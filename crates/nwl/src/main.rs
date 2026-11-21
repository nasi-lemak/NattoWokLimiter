//! `nwl`: command-line client for the NattoWokLimiter daemon.

use anyhow::{bail, Context};
use clap::{Parser, Subcommand, ValueEnum};
use nwl_core::rate::{format_bytes, ByteSize, Rate};
use nwl_core::rules::{Day, Rule, TimeOfDay};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(version, long_version = nwl_core::LONG_VERSION, about = "Control NattoWokLimiter: see who uses your network, block, limit and cap apps")]
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
    /// Only on metered networks (phone hotspots, mobile data, or networks
    /// marked metered with `nwl network metered`).
    #[arg(long, conflicts_with = "unmetered")]
    metered: bool,
    /// Only on unmetered networks.
    #[arg(long)]
    unmetered: bool,
    /// Only on the network with this name (Wi-Fi: its SSID); repeat for several.
    #[arg(long = "network", value_name = "NAME")]
    networks: Vec<String>,
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

    fn network(&self) -> Value {
        let metered = if self.metered {
            Some(true)
        } else if self.unmetered {
            Some(false)
        } else {
            None
        };
        if metered.is_none() && self.networks.is_empty() {
            return Value::Null;
        }
        json!({"metered": metered, "names": self.networks})
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum PresetAction {
    Add,
    Remove,
}

#[derive(Clone, Copy, ValueEnum)]
enum Treat {
    /// Treat the current network as metered.
    Metered,
    /// Treat it as not metered.
    Unmetered,
    /// Go by what the system detects.
    Auto,
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
    /// Pause all rules: nothing is blocked or limited until `resume` (or a
    /// daemon restart). Traffic is still counted.
    Pause,
    /// Resume all rules.
    Resume,
    /// Show the current network, or mark it metered or not (remembered per
    /// network). Rules made with `--metered` apply only on metered networks.
    Network {
        #[arg(value_enum)]
        set: Option<Treat>,
    },
    /// Data used per application over recent days.
    Usage {
        #[arg(long, default_value_t = 7)]
        days: usize,
    },
    /// Traffic over time: totals, a chart and top apps; or CSV.
    History {
        /// hour, day, week, month or quarter (also 1h, 24h, 7d, 30d, 90d).
        #[arg(long, default_value = "day")]
        range: String,
        /// Only this application (full path, as shown by `top`).
        #[arg(long)]
        app: Option<String>,
        /// Print CSV (one row per time point and app) instead.
        #[arg(long)]
        csv: bool,
    },
    /// Who apps talk to: remote hosts by traffic this session.
    Remotes {
        /// Only this application (full path, as shown by `top`).
        #[arg(long)]
        app: Option<String>,
        /// Show at most this many hosts.
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// Recent events (new applications, quotas reached, rule changes).
    Events,
    /// Ready-made rule sets: list them, or add or remove one, e.g.
    /// `nwl preset add hotspot-saver`.
    Preset {
        #[arg(value_enum)]
        action: Option<PresetAction>,
        /// The preset (id or name).
        name: Option<String>,
    },
    /// Print a backup of all rules and network choices (JSON), e.g.
    /// `nwl export > backup.json`.
    Export,
    /// Restore a backup made by `nwl export` or the app.
    Import {
        /// The backup file (`-` reads standard input).
        file: PathBuf,
        /// Add the backup's rules you don't have yet, instead of replacing all rules.
        #[arg(long)]
        merge: bool,
    },
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

    /// A non-JSON response body (CSV).
    fn get_text(&self, path: &str) -> anyhow::Result<String> {
        match self.agent.get(&format!("{}{path}", self.base)).call() {
            Ok(r) => Ok(r.into_string()?),
            Err(ureq::Error::Status(code, r)) => {
                let body: Value = r.into_json().unwrap_or(Value::Null);
                bail!("daemon returned {code}: {}", body["error"].as_str().unwrap_or("request failed"))
            }
            Err(e) => {
                Err(anyhow::Error::new(e)).with_context(|| format!("cannot reach nwld at {}", self.base))
            }
        }
    }
}

/// A one-line bar chart of `values` at most `width` characters wide.
fn bars(values: &[u64], width: usize) -> String {
    const BLOCKS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let per = values.len().div_ceil(width.max(1)).max(1);
    let merged: Vec<u64> = values.chunks(per).map(|c| c.iter().sum()).collect();
    let max = merged.iter().copied().max().unwrap_or(0).max(1);
    merged
        .iter()
        .map(|&v| if v == 0 { ' ' } else { BLOCKS[((v * 8).div_ceil(max)).clamp(1, 8) as usize] })
        .collect()
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

/// Adds `schedule` and `network` conditions to a rule when given.
fn with_schedule(mut rule: Value, when: &When) -> anyhow::Result<Value> {
    let schedule = when.schedule()?;
    if !schedule.is_null() {
        rule["schedule"] = schedule;
    }
    let network = when.network();
    if !network.is_null() {
        rule["network"] = network;
    }
    Ok(rule)
}

fn print_network(n: &Value) {
    let name = n["name"].as_str().unwrap_or("(unnamed)");
    let metered = if n["metered"] == true { "metered" } else { "not metered" };
    let how = match (n["overridden"].as_bool(), n["detected"].as_bool()) {
        (Some(_), _) => "set by you".to_string(),
        (None, Some(_)) => format!("detected by {}", n["source"].as_str().unwrap_or("the system")),
        (None, None) => "can't be detected; mark it with `nwl network metered`".to_string(),
    };
    println!("network   {name}: {metered} ({how})");
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
            print_network(&c.get("/api/network")?);
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
        Cmd::Pause | Cmd::Resume => {
            let paused = matches!(cli.cmd, Cmd::Pause);
            c.call("POST", "/api/pause", Some(json!({ "paused": paused })))?;
            println!(
                "{}",
                if paused { "all rules paused (resume with `nwl resume`)" } else { "rules resumed" }
            );
        }
        Cmd::Network { set } => {
            let view = match set {
                None => c.get("/api/network")?,
                Some(m) => {
                    let metered = match m {
                        Treat::Metered => json!(true),
                        Treat::Unmetered => json!(false),
                        Treat::Auto => Value::Null,
                    };
                    c.call("PUT", "/api/network", Some(json!({ "metered": metered })))?
                }
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                print_network(&view);
            }
        }
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
        Cmd::History { range, app, csv } => {
            let mut query = format!("range={}", encode(&range));
            if let Some(a) = &app {
                query += &format!("&app={}", encode(a));
            }
            if csv {
                print!("{}", c.get_text(&format!("/api/history.csv?{query}"))?);
                return Ok(());
            }
            let h = c.get(&format!("/api/history?{query}"))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&h)?);
                return Ok(());
            }
            let points = h["points"].as_array().cloned().unwrap_or_default();
            let ups: Vec<u64> = points.iter().map(|p| u(&p["up"])).collect();
            let downs: Vec<u64> = points.iter().map(|p| u(&p["down"])).collect();
            let (up, down) = (ups.iter().sum::<u64>(), downs.iter().sum::<u64>());
            let who = app.as_deref().map_or("all traffic".to_string(), |a| a.to_string());
            println!("{range}: {who}  down {}  up {}\n", format_bytes(down), format_bytes(up));
            println!("down |{}|", bars(&downs, 72));
            println!("up   |{}|\n", bars(&ups, 72));
            if app.is_none() {
                let rows: Vec<Vec<String>> = h["apps"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(15)
                    .map(|a| {
                        vec![
                            a["name"].as_str().unwrap_or("").to_string(),
                            format_bytes(u(&a["down"])),
                            format_bytes(u(&a["up"])),
                            format_bytes(u(&a["down"]) + u(&a["up"])),
                        ]
                    })
                    .collect();
                if !rows.is_empty() {
                    table(&["APP", "DOWN", "UP", "TOTAL"], &rows, &[1, 2, 3]);
                }
            }
        }
        Cmd::Remotes { app, limit } => {
            let mut path = format!("/api/remotes?limit={limit}");
            if let Some(a) = &app {
                path += &format!("&app={}", encode(a));
            }
            let remotes = c.get(&path)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&remotes)?);
                return Ok(());
            }
            let list = |v: &Value| -> String {
                v.as_array()
                    .into_iter()
                    .flatten()
                    .map(|x| x.to_string().trim_matches('"').to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let rows: Vec<Vec<String>> = remotes
                .as_array()
                .into_iter()
                .flatten()
                .map(|r| {
                    let apps: Vec<String> = r["apps"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(|a| a.rsplit(['/', '\\']).next().unwrap_or(a).to_string())
                        .collect();
                    let mut row = vec![
                        r["host"].as_str().unwrap_or("").to_string(),
                        r["ip"].as_str().unwrap_or("").to_string(),
                        format_bytes(u(&r["down"])),
                        format_bytes(u(&r["up"])),
                        list(&r["protocols"]),
                        list(&r["ports"]),
                        r["open_connections"].to_string(),
                    ];
                    if app.is_none() {
                        row.push(apps.join(","));
                    }
                    row
                })
                .collect();
            let mut headers = vec!["HOST", "IP", "DOWN", "UP", "PROTO", "PORTS", "OPEN"];
            if app.is_none() {
                headers.push("APPS");
            }
            if rows.is_empty() {
                println!("no traffic to remote hosts yet");
            } else {
                table(&headers, &rows, &[2, 3, 6]);
            }
        }
        Cmd::Preset { action, name } => {
            use nwl_core::presets::{Preset, PRESETS};
            let rules: Vec<Rule> = serde_json::from_value(c.get("/api/rules")?)?;
            let Some(action) = action else {
                for p in &PRESETS {
                    let added = rules.iter().filter(|r| p.owns(r)).count();
                    let status = if added == 0 { String::new() } else { format!("  [{added} rules added]") };
                    println!(
                        "{:<16} {}{status}\n  {}\n  covers {}\n",
                        p.id,
                        p.name,
                        p.description,
                        p.app_labels().join(", ")
                    );
                }
                return Ok(());
            };
            let name = name.ok_or_else(|| anyhow::anyhow!("which preset? see `nwl preset`"))?;
            let preset =
                Preset::find(&name).ok_or_else(|| anyhow::anyhow!("no preset {name:?}; see `nwl preset`"))?;
            match action {
                PresetAction::Add => {
                    let backup = json!({
                        "format": nwl_core::api::BACKUP_FORMAT,
                        "version": nwl_core::api::BACKUP_VERSION,
                        "rules": preset.rules(),
                    });
                    let r = c.call("POST", "/api/import?mode=merge", Some(backup))?;
                    println!("{}: added {} rules ({} already there)", preset.name, r["rules"], r["skipped"]);
                }
                PresetAction::Remove => {
                    let owned: Vec<&Rule> = rules.iter().filter(|r| preset.owns(r)).collect();
                    for r in &owned {
                        c.call("DELETE", &format!("/api/rules/{}", r.id), None)?;
                    }
                    println!("{}: removed {} rules", preset.name, owned.len());
                }
            }
        }
        Cmd::Export => raw("/api/export")?,
        Cmd::Import { file, merge } => {
            let text = if file.as_os_str() == "-" {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                s
            } else {
                std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?
            };
            let backup: Value = serde_json::from_str(&text).context("the file is not JSON")?;
            let mode = if merge { "merge" } else { "replace" };
            let r = c.call("POST", &format!("/api/import?mode={mode}"), Some(backup))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else if merge {
                println!("added {} rules ({} already present)", r["rules"], r["skipped"]);
            } else {
                println!("restored {} rules", r["rules"]);
            }
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
