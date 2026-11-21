//! The desktop UI.

use crate::client::Client;
use crate::data::{lock, Call, Request, Shared, HISTORY, SPARK};
use eframe::egui::{self, Color32, RichText, Stroke, Ui};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Bar, BarChart, Line, Plot};
use nwl_core::api::{AppView, ConnView, EventKind};
use nwl_core::history::Range;
use nwl_core::model::{AppId, Direction, Protocol};
use nwl_core::rate::{format_bytes, ByteSize, Rate};
use nwl_core::rules::{Action, Day, Period, Rule, TimeOfDay};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::time::Duration;
use web_time::Instant;

// Colors of the current theme (see `crate::theme`).
fn col_down() -> Color32 {
    crate::theme::current().down
}
fn col_up() -> Color32 {
    crate::theme::current().up
}
fn col_accent() -> Color32 {
    crate::theme::current().accent
}
fn col_bad() -> Color32 {
    crate::theme::current().bad
}
fn col_ok() -> Color32 {
    crate::theme::current().ok
}
fn col_on_accent() -> Color32 {
    crate::theme::current().on_accent
}

fn rate(n: u64) -> String {
    if n == 0 {
        "–".into()
    } else {
        format!("{}/s", format_bytes(n))
    }
}

fn avatar_color(seed: &str) -> Color32 {
    let h = seed.bytes().fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32));
    let hue = (h % 360) as f32 / 360.0;
    egui::ecolor::Hsva::new(hue, 0.55, 0.62, 1.0).into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Apps,
    Connections,
    Rules,
    History,
    Usage,
    Events,
}

struct LimitDialog {
    app: AppId,
    name: String,
    rule: Option<u64>,
    down: String,
    up: String,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormAction {
    Block,
    Allow,
    Limit,
    Quota,
}

struct RuleForm {
    open: bool,
    name: String,
    action: FormAction,
    direction: Direction,
    download: String,
    upload: String,
    quota: String,
    period: Period,
    quota_direction: Direction,
    app: String,
    remote: String,
    ports: String,
    protocol: Option<Protocol>,
    days: [bool; 7],
    from: String,
    until: String,
    /// Only on metered (`Some(true)`) or unmetered networks.
    metered: Option<bool>,
    /// Only on networks with these names (comma-separated).
    networks: String,
    /// The rule being edited; saving replaces it. Fields the form doesn't
    /// show (local ports, user) are kept from it.
    editing: Option<Rule>,
    error: Option<String>,
}

impl Default for RuleForm {
    fn default() -> Self {
        Self {
            open: false,
            name: String::new(),
            action: FormAction::Block,
            direction: Direction::Both,
            download: String::new(),
            upload: String::new(),
            quota: String::new(),
            period: Period::Month,
            quota_direction: Direction::Both,
            app: String::new(),
            remote: String::new(),
            ports: String::new(),
            protocol: None,
            days: [false; 7],
            from: String::new(),
            until: String::new(),
            metered: None,
            networks: String::new(),
            editing: None,
            error: None,
        }
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ']).map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect()
}

/// A size for a text field: readable when that is exact (`5.00 MB`),
/// otherwise the exact byte count, so editing never changes a value by itself.
fn exact_size(bytes: u64) -> String {
    let pretty = format_bytes(bytes);
    if pretty.parse::<ByteSize>().is_ok_and(|b| b.0 == bytes) {
        pretty
    } else {
        bytes.to_string()
    }
}

fn exact_rate(bytes: u64) -> String {
    let pretty = format!("{}/s", format_bytes(bytes));
    if pretty.parse::<Rate>().is_ok_and(|r| r.0 == bytes) {
        pretty
    } else {
        format!("{bytes}B/s")
    }
}

impl RuleForm {
    /// The form filled in from an existing rule, to edit it.
    fn from_rule(rule: &Rule) -> Self {
        let mut f =
            RuleForm { open: true, name: rule.name.clone(), editing: Some(rule.clone()), ..Self::default() };
        match &rule.action {
            Action::Allow => f.action = FormAction::Allow,
            Action::Block { direction } => {
                f.action = FormAction::Block;
                f.direction = *direction;
            }
            Action::Limit { download, upload } => {
                f.action = FormAction::Limit;
                f.download = download.map(|r| exact_rate(r.0)).unwrap_or_default();
                f.upload = upload.map(|r| exact_rate(r.0)).unwrap_or_default();
            }
            Action::Quota { limit, period, direction } => {
                f.action = FormAction::Quota;
                f.quota = exact_size(limit.0);
                f.period = *period;
                f.quota_direction = *direction;
            }
        }
        let m = &rule.matcher;
        f.app = m.app.as_ref().map(|a| a.0.clone()).unwrap_or_default();
        f.protocol = m.protocol;
        f.remote = m.remote.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
        f.ports = m.remote_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
        if let Some(s) = &rule.schedule {
            for (i, day) in Day::ALL.iter().enumerate() {
                f.days[i] = s.days.contains(day);
            }
            f.from = s.from.map(|t| t.to_string()).unwrap_or_default();
            f.until = s.until.map(|t| t.to_string()).unwrap_or_default();
        }
        if let Some(n) = &rule.network {
            f.metered = n.metered;
            f.networks = n.names.join(", ");
        }
        f
    }

    /// Builds the rule JSON, validating what can be checked locally.
    fn build(&self) -> Result<Value, String> {
        let mut m = serde_json::Map::new();
        if !self.app.trim().is_empty() {
            m.insert("app".into(), json!(self.app.trim()));
        }
        if let Some(p) = self.protocol {
            m.insert("protocol".into(), json!(p));
        }
        let nets: Vec<String> = split_list(&self.remote)
            .into_iter()
            .map(|n| {
                if n.contains('/') {
                    n
                } else if n.contains(':') {
                    n + "/128"
                } else {
                    n + "/32"
                }
            })
            .collect();
        if !nets.is_empty() {
            m.insert("remote".into(), json!(nets));
        }
        let ports = split_list(&self.ports);
        if !ports.is_empty() {
            m.insert("remote_ports".into(), json!(ports));
        }
        let opt_rate = |s: &str| -> Result<Option<u64>, String> {
            if s.trim().is_empty() {
                Ok(None)
            } else {
                s.parse::<Rate>().map(|r| Some(r.0)).map_err(|e| e.to_string())
            }
        };
        let action = match self.action {
            FormAction::Block => json!({"type": "block", "direction": self.direction}),
            FormAction::Allow => json!({"type": "allow"}),
            FormAction::Limit => {
                let (down, up) = (opt_rate(&self.download)?, opt_rate(&self.upload)?);
                if down.is_none() && up.is_none() {
                    return Err("Enter a download and/or upload limit.".into());
                }
                json!({"type": "limit", "download": down, "upload": up})
            }
            FormAction::Quota => {
                let limit = self.quota.parse::<ByteSize>().map_err(|e| e.to_string())?;
                json!({"type": "quota", "limit": limit.0, "period": self.period, "direction": self.quota_direction})
            }
        };
        // When editing, keep what the form doesn't show (id, enabled, local
        // ports, user).
        if let Some(orig) = &self.editing {
            if !orig.matcher.local_ports.is_empty() {
                m.insert("local_ports".into(), json!(orig.matcher.local_ports));
            }
            if let Some(uid) = orig.matcher.uid {
                m.insert("uid".into(), json!(uid));
            }
        }
        let mut rule = json!({"name": self.name.trim(), "match": m, "action": action});
        if let Some(orig) = &self.editing {
            rule["id"] = json!(orig.id);
            rule["enabled"] = json!(orig.enabled);
        }
        let days: Vec<Day> = (0..7).filter(|&i| self.days[i]).map(Day::from_index).collect();
        let (from, until) = (self.from.trim(), self.until.trim());
        if from.is_empty() != until.is_empty() {
            return Err("Set both From and Until, or neither.".into());
        }
        if !days.is_empty() || !from.is_empty() {
            let mut sched = json!({"days": days});
            if !from.is_empty() {
                sched["from"] = json!(from.parse::<TimeOfDay>()?);
                sched["until"] = json!(until.parse::<TimeOfDay>()?);
            }
            rule["schedule"] = sched;
        }
        // Network names may contain spaces, so only commas separate them.
        let names: Vec<&str> = self.networks.split(',').map(str::trim).filter(|n| !n.is_empty()).collect();
        if self.metered.is_some() || !names.is_empty() {
            rule["network"] = json!({"metered": self.metered, "names": names});
        }
        Ok(rule)
    }
}

pub struct NwlApp {
    client: Client,
    data: Shared,
    poller: Sender<Request>,
    tab: Tab,
    app_filter: String,
    conn_filter: String,
    show_listening: bool,
    expanded: Option<AppId>,
    limit: Option<LimitDialog>,
    form: RuleForm,
    usage_days: usize,
    show_notify_settings: bool,
    show_about: bool,
    /// The chosen theme (`"system"` or a theme id), and the palette applied.
    theme: String,
    applied_theme: &'static str,
    history_range: Range,
    /// App the History tab is filtered to; `None` for all traffic.
    history_app: Option<AppId>,
    /// The tray icon, where the desktop has a tray.
    tray: Option<crate::tray::Tray>,
    /// The window is hidden to the tray.
    hidden: bool,
    /// Quit was chosen: let the window close instead of hiding it.
    quitting: bool,
    /// Started hidden: when to check that a tray host shows the icon, or
    /// else show the window so the app is not unreachable.
    startup_check: Option<Instant>,
    /// Whether the app starts at login.
    autostart: bool,
    /// Row order of the apps table last frame, and whether the pointer was
    /// over it: rows keep their place while the user aims at a button.
    app_order: Vec<AppId>,
    freeze_order: bool,
}

impl NwlApp {
    /// `start_hidden`: started at login, so stay in the tray (if there is one).
    pub fn new(
        ctx: &egui::Context,
        client: Client,
        data: Shared,
        poller: Sender<Request>,
        start_hidden: bool,
    ) -> Self {
        let _ = poller.send(Request::Usage(30));
        Self {
            client,
            data,
            poller,
            tab: Tab::Apps,
            app_filter: String::new(),
            conn_filter: String::new(),
            show_listening: false,
            expanded: None,
            limit: None,
            form: RuleForm::default(),
            usage_days: 30,
            show_notify_settings: false,
            show_about: false,
            theme: crate::theme::load(),
            applied_theme: "",
            history_range: Range::Day,
            history_app: None,
            tray: {
                let ctx = ctx.clone();
                crate::tray::Tray::new(move || ctx.request_repaint())
            },
            hidden: start_hidden,
            startup_check: start_hidden.then(Instant::now),
            autostart: crate::autostart::enabled(),
            quitting: false,
            app_order: Vec::new(),
            freeze_order: false,
        }
    }

    /// Runs one API call in the background; the outcome shows as a toast and
    /// the views refresh.
    /// Deleting a rule can be undone: the toast offers to put it back, with
    /// its id, at its place in the list.
    fn act(&self, method: &'static str, path: &str, body: Option<Value>, done: &str) {
        let mut call = Call::new(method, path, body, done);
        if method == "DELETE" {
            call.undo = self.undo_delete(path).map(Box::new);
        }
        let _ = self.poller.send(Request::Call(call));
    }

    fn undo_delete(&self, path: &str) -> Option<Call> {
        let id: u64 = path.strip_prefix("/api/rules/")?.parse().ok()?;
        let d = lock(&self.data);
        let index = d.rules.iter().position(|r| r.id == id)?;
        let rule = serde_json::to_value(&d.rules[index]).ok()?;
        let name =
            if d.rules[index].name.is_empty() { format!("rule #{id}") } else { d.rules[index].name.clone() };
        Some(Call::new("POST", format!("/api/rules?index={index}"), Some(rule), format!("Restored {name}")))
    }

    /// Pauses or resumes all rules in the daemon.
    pub fn set_paused(&self, paused: bool) {
        let done = if paused { "All rules paused" } else { "Rules resumed" };
        self.act("POST", "/api/pause", Some(json!({ "paused": paused })), done);
    }

    fn header(&mut self, ui: &mut Ui) {
        let d = lock(&self.data);
        let mut toggle_pause: Option<bool> = None;
        let mut set_metered: Option<(Option<bool>, String)> = None;
        let mut new_theme: Option<String> = None;
        ui.horizontal(|ui| {
            let (logo, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
            ui.painter().circle_filled(logo.center(), 11.0, col_accent());
            let chevron = [
                logo.center() + egui::vec2(-5.0, 3.0),
                logo.center() + egui::vec2(0.0, -3.0),
                logo.center() + egui::vec2(5.0, 3.0),
            ];
            ui.painter().add(egui::Shape::line(chevron.to_vec(), Stroke::new(2.5, col_on_accent())));
            ui.label(RichText::new("NattoWok Limiter").strong().size(18.0));
            ui.add_space(10.0);
            let (text, color) = match (&d.status, d.connected) {
                (_, false) => ("Disconnected".to_string(), col_bad()),
                (Some(s), true) => {
                    let e = &s.enforcement;
                    let demo = if e.monitor.starts_with("simulated") { "Demo · " } else { "" };
                    if e.error.is_some() {
                        (format!("{demo}Enforcement error"), col_bad())
                    } else if e.paused {
                        (format!("{demo}Paused: nothing is blocked or limited"), col_accent())
                    } else if !e.enforcing {
                        (format!("{demo}Monitor only"), col_accent())
                    } else {
                        (format!("{demo}Enforcing"), col_ok())
                    }
                }
                (None, true) => ("Connecting…".to_string(), col_accent()),
            };
            crate::theme::pill(ui, text, color, true);
            if let Some(s) = d.status.as_ref().filter(|s| d.connected && s.enforcement.enforcing) {
                let paused = s.enforcement.paused;
                let (label, hint) = if paused {
                    ("Resume rules", "Apply all blocks, limits and quotas again")
                } else {
                    ("Pause rules", "Stop blocking and limiting until you resume (traffic is still counted)")
                };
                if ui.small_button(label).on_hover_text(hint).clicked() {
                    toggle_pause = Some(!paused);
                }
            }
            if let Some(net) = d.overview.as_ref().map(|o| &o.network).filter(|_| d.connected) {
                if let Some(choice) = network_menu(ui, net) {
                    set_metered = Some((choice, net.name.clone().unwrap_or_else(|| "this network".into())));
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Notifications and startup are the desktop app's; a browser tab has neither.
                let desktop = cfg!(not(target_arch = "wasm32"));
                if desktop && ui.button("⚙").on_hover_text("Settings: notifications and startup").clicked()
                {
                    self.show_notify_settings = !self.show_notify_settings;
                }
                if let Some(choice) = theme_menu(ui, &self.theme) {
                    new_theme = Some(choice);
                }
                ui.add_space(6.0);
                if let Some(o) = &d.overview {
                    let s = &o.system;
                    total(ui, "SESSION", format_bytes(s.total_up + s.total_down), ui.visuals().text_color());
                    total(ui, "↑ UPLOAD", rate(s.rate_up), col_up());
                    total(ui, "↓ DOWNLOAD", rate(s.rate_down), col_down());
                }
            });
        });
        drop(d);
        if let Some(paused) = toggle_pause {
            self.set_paused(paused);
        }
        if let Some(choice) = new_theme {
            if let Err(e) = crate::theme::save(&choice) {
                lock(&self.data).toast = Some((e, false, Instant::now()));
            }
            self.theme = choice;
        }
        if let Some((metered, name)) = set_metered {
            let done = match metered {
                Some(true) => format!("{name} is treated as metered"),
                Some(false) => format!("{name} is treated as not metered"),
                None => format!("{name}: metered as detected"),
            };
            self.act("PUT", "/api/network", Some(json!({ "metered": metered })), &done);
        }
    }

    fn graph(&self, ui: &mut Ui) {
        let d = lock(&self.data);
        let n = d.system.len();
        let points = |pick: fn(&(u64, u64)) -> u64| -> Vec<[f64; 2]> {
            d.system.iter().enumerate().map(|(i, s)| [i as f64 - n as f64 + 1.0, pick(s) as f64]).collect()
        };
        Plot::new("system")
            .height(150.0)
            .show_background(false)
            .show_grid([false, true])
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .include_x(-(HISTORY as f64))
            .include_x(0.0)
            .include_y(0.0)
            .show_x(false)
            .y_axis_formatter(|m, _| if m.value <= 0.0 { "0".into() } else { rate(m.value as u64) })
            .x_axis_formatter(|m, _| format!("{}s", -m.value as i64))
            .label_formatter(|h| match h {
                egui_plot::HoverPosition::NearDataPoint { plot_name, position, .. } => {
                    Some(format!("{plot_name}: {}\n{} s ago", rate(position.y as u64), -position.x as i64))
                }
                _ => None,
            })
            .show(ui, |p| {
                p.line(Line::new("Download", points(|s| s.1)).color(col_down()).fill(0.0).width(1.6));
                p.line(Line::new("Upload", points(|s| s.0)).color(col_up()).fill(0.0).width(1.6));
            });
    }

    /// The open tab's content, or help when the daemon isn't answering.
    fn tab_content(&mut self, ui: &mut Ui) {
        let (connected, error) = {
            let d = lock(&self.data);
            (d.connected, d.error.clone())
        };
        if !connected {
            if let Some(error) = error {
                self.disconnected(ui, &error);
                return;
            }
        }
        match self.tab {
            Tab::Apps => {
                egui::ScrollArea::vertical().id_salt("apps-scroll").show(ui, |ui| self.apps_tab(ui)).inner
            }
            Tab::Connections => self.connections_tab(ui),
            Tab::Rules => self.rules_tab(ui),
            Tab::History => {
                egui::ScrollArea::vertical()
                    .id_salt("history-scroll")
                    .show(ui, |ui| self.history_tab(ui))
                    .inner
            }
            Tab::Usage => {
                egui::ScrollArea::vertical().id_salt("usage-scroll").show(ui, |ui| self.usage_tab(ui)).inner
            }
            Tab::Events => self.events_tab(ui),
        }
    }

    /// Explains that the service isn't answering and how to start it.
    fn disconnected(&mut self, ui: &mut Ui, error: &str) {
        ui.add_space(36.0);
        ui.vertical_centered(|ui| {
            ui.set_max_width(560.0);
            ui.heading("Can't reach the NattoWok service");
            ui.add_space(6.0);
            ui.label(format!(
                "This app shows what the nwld service sees and asks it to apply your rules, but nothing \
                 answers at {}.",
                self.client.base()
            ));
            ui.add_space(10.0);
            if cfg!(target_arch = "wasm32") {
                ui.label("nwld stopped after serving this page. Start it again and this page reconnects by itself.");
            } else if cfg!(windows) {
                ui.label("Start nwld.exe as Administrator (right-click it, then \"Run as administrator\").");
            } else if cfg!(target_os = "macos") {
                ui.label("Start it in a terminal:");
                ui.code("sudo nwld");
            } else {
                ui.label("It normally runs in the background as a system service. Start it here, or in a terminal:");
                ui.code("sudo systemctl start nwld");
                ui.add_space(6.0);
                #[cfg(not(target_arch = "wasm32"))]
                if ui
                    .add(egui::Button::new(RichText::new("Start the service").color(col_on_accent())).fill(col_accent()))
                    .on_hover_text("Asks for your password, then starts nwld.service")
                    .clicked()
                {
                    start_service(self.data.clone());
                }
            }
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                ui.add_space((ui.available_width() - 220.0).max(0.0) / 2.0);
                ui.spinner();
                ui.weak("Trying again every second…");
            });
            ui.add_space(8.0);
            egui::CollapsingHeader::new("Details").id_salt("disconnected-details").show(ui, |ui| {
                ui.weak(error);
            });
        });
    }

    fn tabs(&mut self, ui: &mut Ui) {
        let d = lock(&self.data);
        let counts = [
            (Tab::Apps, "Applications", d.apps().len()),
            (
                Tab::Connections,
                "Connections",
                d.connections.iter().filter(|c| c.conn.key.remote.is_some()).count(),
            ),
            (Tab::Rules, "Rules", d.rules.len()),
            (Tab::History, "History", 0),
            (Tab::Usage, "Usage", 0),
            (Tab::Events, "Events", d.events.len()),
        ];
        drop(d);
        // A segmented control: the open tab is an accent-colored pill.
        let p = crate::theme::current();
        egui::Frame::new().fill(p.surface).corner_radius(10).inner_margin(egui::Margin::same(3)).show(
            ui,
            |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    for (tab, label, count) in counts {
                        let selected = self.tab == tab;
                        let fg = if selected { p.on_accent } else { p.text };
                        let mut job = egui::text::LayoutJob::default();
                        let format = |size: f32, color: Color32| egui::TextFormat {
                            font_id: egui::FontId::proportional(size),
                            color,
                            valign: egui::Align::Center,
                            ..Default::default()
                        };
                        job.append(label, 0.0, format(14.0, fg));
                        if count > 0 {
                            let weak = if selected { p.on_accent.gamma_multiply(0.75) } else { p.weak };
                            job.append(&count.to_string(), 7.0, format(12.0, weak));
                        }
                        let button = egui::Button::new(job)
                            .fill(if selected { p.accent } else { Color32::TRANSPARENT })
                            .stroke(Stroke::NONE)
                            .corner_radius(8)
                            .min_size(egui::vec2(0.0, 28.0));
                        if ui.add(button).clicked() {
                            self.tab = tab;
                        }
                    }
                });
            },
        );
    }

    fn apps_tab(&mut self, ui: &mut Ui) {
        ui.add(
            egui::TextEdit::singleline(&mut self.app_filter)
                .hint_text("Filter applications…")
                .desired_width(f32::INFINITY),
        );
        ui.add_space(4.0);
        let d = lock(&self.data);
        let filter = self.app_filter.to_lowercase();
        let mut apps: Vec<AppView> = d
            .apps()
            .iter()
            .filter(|a| {
                filter.is_empty()
                    || a.name.to_lowercase().contains(&filter)
                    || a.app.0.to_lowercase().contains(&filter)
            })
            .cloned()
            .collect();
        if self.freeze_order || self.limit.is_some() {
            let pos = |a: &AppView| self.app_order.iter().position(|id| *id == a.app).unwrap_or(usize::MAX);
            apps.sort_by_key(pos);
        }
        self.app_order = apps.iter().map(|a| a.app.clone()).collect();
        let histories: Vec<VecDeque<(u64, u64)>> =
            apps.iter().map(|a| d.app_history.get(&a.app).cloned().unwrap_or_default()).collect();
        let quotas = d.overview.as_ref().map(|o| o.quotas.clone()).unwrap_or_default();
        let limit_rules: Vec<Option<Rule>> = apps.iter().map(|a| d.rule(a.limit_rule).cloned()).collect();
        let detail: Vec<ConnView> = match &self.expanded {
            Some(app) => d
                .connections
                .iter()
                .filter(|c| c.app.as_ref() == Some(app) && c.conn.key.remote.is_some())
                .cloned()
                .collect(),
            None => vec![],
        };
        drop(d);

        if apps.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.weak("No application is using the network right now."));
            return;
        }
        let mut clicked: Option<(usize, &'static str)> = None;
        let table = TableBuilder::new(ui)
            .id_salt("apps")
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .sense(egui::Sense::click())
            .column(Column::remainder().at_least(220.0).clip(true))
            .column(Column::exact(110.0))
            .column(Column::exact(95.0))
            .column(Column::exact(95.0))
            .column(Column::exact(90.0))
            .column(Column::exact(50.0))
            .column(Column::exact(190.0))
            .header(22.0, |mut h| {
                for title in ["APPLICATION", "ACTIVITY", "DOWNLOAD", "UPLOAD", "SESSION", "CONNS", ""] {
                    h.col(|ui| {
                        ui.weak(RichText::new(title).small().strong());
                    });
                }
            })
            .body(|mut body| {
                for (i, a) in apps.iter().enumerate() {
                    body.row(46.0, |mut row| {
                        row.col(|ui| {
                            let tag = app_quota(&a.rules, &quotas).map(|q| {
                                (quota_text(q), quota_color(q), Some(q.used as f32 / q.limit.max(1) as f32))
                            });
                            app_cell(ui, &a.name, &a.app.0, a.blocked, tag);
                        });
                        row.col(|ui| sparkline(ui, &histories[i]));
                        row.col(|ui| {
                            ui.label(RichText::new(rate(a.rate_down)).color(col_down()).monospace());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(rate(a.rate_up)).color(col_up()).monospace());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(format_bytes(a.total_up + a.total_down)).monospace());
                        });
                        row.col(|ui| {
                            ui.label(a.connections.to_string());
                        });
                        row.col(|ui| {
                            let limit_text = match &limit_rules[i] {
                                Some(r) => r
                                    .action_summary()
                                    .replace("limit ", "")
                                    .replace("down ", "↓")
                                    .replace("up ", "↑"),
                                None => "Limit…".into(),
                            };
                            let limit_btn = egui::Button::new(if limit_rules[i].is_some() {
                                RichText::new(limit_text).color(col_accent())
                            } else {
                                RichText::new(limit_text)
                            });
                            if ui.add(limit_btn).clicked() {
                                clicked = Some((i, "limit"));
                            }
                            let block = if a.block_rule.is_some() {
                                egui::Button::new(
                                    RichText::new("Blocked").color(crate::theme::current().bg).strong(),
                                )
                                .fill(col_bad())
                            } else {
                                egui::Button::new("Block")
                            };
                            if ui
                                .add(block)
                                .on_hover_text(if a.block_rule.is_some() {
                                    "Click to unblock"
                                } else {
                                    "Block all traffic of this app"
                                })
                                .clicked()
                            {
                                clicked = Some((i, "block"));
                            }
                        });
                        if row.response().clicked() && clicked.is_none() {
                            clicked = Some((i, "expand"));
                        }
                    });
                }
            });
        self.freeze_order = ui.rect_contains_pointer(table.inner_rect);

        if let Some((i, what)) = clicked {
            let a = &apps[i];
            match what {
                "block" => {
                    use crate::actions::QuickAction;
                    let action =
                        if a.block_rule.is_some() { QuickAction::Unblock } else { QuickAction::Block };
                    self.quick_action(&a.into(), &action);
                }
                "limit" => {
                    let (down, up) = match &limit_rules[i] {
                        Some(Rule {
                            action: nwl_core::rules::Action::Limit { download, upload }, ..
                        }) => (
                            download.map(|r| r.to_string().replace(' ', "")).unwrap_or_default(),
                            upload.map(|r| r.to_string().replace(' ', "")).unwrap_or_default(),
                        ),
                        _ => Default::default(),
                    };
                    self.limit = Some(LimitDialog {
                        app: a.app.clone(),
                        name: a.name.clone(),
                        rule: a.limit_rule,
                        down,
                        up,
                        error: None,
                    });
                }
                _ => {
                    self.expanded =
                        if self.expanded.as_ref() == Some(&a.app) { None } else { Some(a.app.clone()) };
                }
            }
        }

        let (tracked, remotes) = {
            let d = lock(&self.data);
            (d.remotes_app.clone(), d.remotes.clone())
        };
        if tracked != self.expanded {
            let _ = self.poller.send(Request::Remotes(self.expanded.clone()));
        }
        if let Some(app) = self.expanded.clone() {
            ui.add_space(8.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong(format!("{} talks to", app.display_name()));
                if ui.small_button("×").on_hover_text("Close").clicked() {
                    self.expanded = None;
                }
            });
            remotes_table(ui, &remotes);
            ui.add_space(8.0);
            ui.strong("Open connections");
            conn_table(ui, "detail", &detail, false);
        }
    }

    fn notify_window(&mut self, ctx: &egui::Context) {
        if !self.show_notify_settings {
            return;
        }
        let mut open = true;
        let (mut settings, error) = {
            let d = lock(&self.data);
            (d.notify.clone(), d.notify_error.clone())
        };
        let before = settings.clone();
        let mut test = false;
        let mut autostart = self.autostart;
        egui::Window::new("Settings")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::RIGHT_TOP, [-12.0, 56.0])
            .show(ctx, |ui| {
                ui.heading("Notifications");
                ui.checkbox(&mut settings.enabled, RichText::new("Show desktop notifications").strong());
                ui.add_enabled_ui(settings.enabled, |ui| {
                    ui.indent("kinds", |ui| {
                        ui.checkbox(&mut settings.new_app, "An app uses the network for the first time");
                        ui.checkbox(&mut settings.traffic_spike, "An app moves far more data than usual");
                        ui.checkbox(&mut settings.quota_warning, "A quota passes 80%");
                        ui.checkbox(
                            &mut settings.quota_exhausted,
                            "A quota is used up and its traffic blocked",
                        );
                        ui.checkbox(&mut settings.enforcement, "Rules stop (or start again) being applied");
                        ui.checkbox(
                            &mut settings.network,
                            "You join a metered network, or network rules switch",
                        );
                    });
                });
                ui.add_space(4.0);
                ui.weak("Only events from now on; past events stay in the Events tab.");
                if let Some(e) = &error {
                    ui.colored_label(col_bad(), format!("Notification service: {e}"));
                }
                if ui.button("Send a test notification").clicked() {
                    test = true;
                }
                ui.separator();
                ui.heading("Startup");
                ui.checkbox(&mut autostart, RichText::new("Start NattoWok Limiter when I log in").strong());
                ui.weak("It starts in the tray. Without a tray, the window opens.");
            });
        if autostart != self.autostart {
            match crate::autostart::set(autostart) {
                Ok(()) => self.autostart = autostart,
                Err(e) => lock(&self.data).toast = Some((e, false, Instant::now())),
            }
        }
        if settings != before {
            let saved = settings.save();
            let mut d = lock(&self.data);
            d.notify = settings;
            if let Err(e) = saved {
                d.toast = Some((e, false, Instant::now()));
            }
        }
        if test {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let result = crate::notify::show("NattoWok Limiter", "Notifications are working.");
                lock(&self.data).notify_error = result.err();
            }
        }
        self.show_notify_settings = open;
    }

    /// Name, version, copyright, license and where the source is.
    fn about_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_about;
        egui::Window::new("About NattoWok Limiter")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.heading(format!("NattoWok Limiter {}", env!("CARGO_PKG_VERSION")));
                ui.label("See which apps use your network, then block, limit or cap them.");
                ui.add_space(6.0);
                for line in nwl_core::NOTICE.lines() {
                    ui.label(line);
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.hyperlink_to("Source code", nwl_core::SOURCE);
                    ui.label("·");
                    ui.hyperlink_to("License text", "https://www.gnu.org/licenses/gpl-3.0.html");
                });
            });
        self.show_about = open;
    }

    fn limit_window(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &mut self.limit else { return };
        let mut open = true;
        let mut action: Option<&str> = None;
        egui::Window::new(format!("Limit {}", dialog.name))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::Grid::new("limit").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Download");
                    ui.add(egui::TextEdit::singleline(&mut dialog.down).hint_text("unlimited"));
                    ui.end_row();
                    ui.label("Upload");
                    ui.add(egui::TextEdit::singleline(&mut dialog.up).hint_text("unlimited"));
                    ui.end_row();
                });
                ui.weak("e.g. 500kB/s, 2MB/s, 10Mbit. Empty means no limit.");
                if let Some(e) = &dialog.error {
                    ui.colored_label(col_bad(), e);
                }
                ui.horizontal(|ui| {
                    if ui.button("Apply").clicked() {
                        action = Some("apply");
                    }
                    if dialog.rule.is_some() && ui.button("Remove limit").clicked() {
                        action = Some("remove");
                    }
                    if ui.button("Cancel").clicked() {
                        action = Some("cancel");
                    }
                });
            });
        let Some(dialog) = self.limit.take() else { return };
        let keep = match action {
            Some("cancel") => false,
            Some("remove") => {
                let id = dialog.rule.expect("button only shown with a rule");
                self.act(
                    "DELETE",
                    &format!("/api/rules/{id}"),
                    None,
                    &format!("Removed limit of {}", dialog.name),
                );
                false
            }
            Some(_) => {
                let parse = |s: &str| -> Result<Option<u64>, String> {
                    if s.trim().is_empty() {
                        Ok(None)
                    } else {
                        s.parse::<Rate>().map(|r| Some(r.0)).map_err(|e| e.to_string())
                    }
                };
                match (parse(&dialog.down), parse(&dialog.up)) {
                    (Ok(None), Ok(None)) => match dialog.rule {
                        Some(id) => {
                            self.act("DELETE", &format!("/api/rules/{id}"), None, "Limit removed");
                            false
                        }
                        None => false,
                    },
                    (Ok(down), Ok(up)) => {
                        let body = json!({"name": format!("Limit {}", dialog.name), "match": {"app": dialog.app}, "action": {"type": "limit", "download": down, "upload": up}});
                        let (method, path) = match dialog.rule {
                            Some(id) => ("PUT", format!("/api/rules/{id}")),
                            None => ("POST", "/api/rules".to_string()),
                        };
                        self.act(method, &path, Some(body), &format!("Limited {}", dialog.name));
                        false
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        self.limit = Some(LimitDialog { error: Some(e), ..dialog });
                        return;
                    }
                }
            }
            None => open,
        };
        if keep {
            self.limit = Some(dialog);
        }
    }

    fn connections_tab(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.conn_filter)
                    .hint_text("Filter by app, host, address, port…")
                    .desired_width(ui.available_width() - 140.0),
            );
            ui.checkbox(&mut self.show_listening, "Show listening");
        });
        ui.add_space(4.0);
        let d = lock(&self.data);
        let f = self.conn_filter.to_lowercase();
        let conns: Vec<ConnView> = d
            .connections
            .iter()
            .filter(|c| self.show_listening || c.conn.key.remote.is_some())
            .filter(|c| {
                f.is_empty()
                    || [
                        c.name.clone().unwrap_or_default(),
                        c.app.as_ref().map(|a| a.0.clone()).unwrap_or_default(),
                        c.conn.key.local.to_string(),
                        c.conn.key.remote.map(|r| r.to_string()).unwrap_or_default(),
                        c.remote_host.clone().unwrap_or_default(),
                        c.conn.key.protocol.to_string(),
                    ]
                    .iter()
                    .any(|v| v.to_lowercase().contains(&f))
            })
            .take(1000)
            .cloned()
            .collect();
        drop(d);
        if conns.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.weak("No connections."));
        } else {
            conn_table(ui, "conns", &conns, true);
        }
    }

    fn rules_tab(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.weak("Access rules: first match wins. Limits and quotas always apply.");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if self.form.open { "Close form" } else { "New rule" };
                if ui
                    .add(egui::Button::new(RichText::new(label).color(col_on_accent())).fill(col_accent()))
                    .clicked()
                {
                    self.form = RuleForm { open: !self.form.open, ..RuleForm::default() };
                }
            });
        });
        if self.form.open {
            self.rule_form(ui);
        }
        ui.add_space(6.0);
        let d = lock(&self.data);
        let rules = d.rules.clone();
        let quotas = d.overview.as_ref().map(|o| o.quotas.clone()).unwrap_or_default();
        drop(d);
        if rules.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.weak("No rules yet. Block or limit an app from Applications, or create a rule.")
            });
            return;
        }
        let mut op: Option<(u64, &str, usize)> = None;
        egui::ScrollArea::vertical().id_salt("rules").show(ui, |ui| {
            for (i, r) in rules.iter().enumerate() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let mut enabled = r.enabled;
                        if ui.checkbox(&mut enabled, "").on_hover_text("Enabled").changed() {
                            op = Some((r.id, if enabled { "enable" } else { "disable" }, i));
                        }
                        ui.vertical(|ui| {
                            let title = if r.name.is_empty() { r.action_summary() } else { r.name.clone() };
                            let mut t = RichText::new(format!("{title}  #{}", r.id)).strong();
                            if !r.enabled {
                                t = t.weak();
                            }
                            ui.label(t);
                            ui.weak(format!("{} · {}", r.action_summary(), r.scope_summary()));
                            if let Some(q) = quotas.iter().find(|q| q.rule == r.id) {
                                ui.add_space(3.0);
                                ui.horizontal(|ui| {
                                    let frac = q.used as f32 / q.limit.max(1) as f32;
                                    let color = quota_color(q);
                                    quota_bar(ui, 220.0, frac, color);
                                    ui.label(RichText::new(quota_text(q)).small().color(color));
                                });
                            }
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("×").on_hover_text("Delete").clicked() {
                                op = Some((r.id, "delete", i));
                            }
                            if ui.small_button("Edit").clicked() {
                                op = Some((r.id, "edit", i));
                            }
                            if ui.add_enabled(i + 1 < rules.len(), egui::Button::new("↓").small()).clicked()
                            {
                                op = Some((r.id, "down", i));
                            }
                            if ui.add_enabled(i > 0, egui::Button::new("↑").small()).clicked() {
                                op = Some((r.id, "up", i));
                            }
                        });
                    });
                });
            }
        });
        if let Some((id, what, i)) = op {
            let path = format!("/api/rules/{id}");
            match what {
                "edit" => self.form = RuleForm::from_rule(&rules[i]),
                "delete" => self.act("DELETE", &path, None, &format!("Deleted rule #{id}")),
                "up" | "down" => {
                    let index = if what == "up" { i - 1 } else { i + 1 };
                    self.act("POST", &format!("{path}/move"), Some(json!({ "index": index })), "Rule moved")
                }
                _ => {
                    let mut rule = rules[i].clone();
                    rule.enabled = what == "enable";
                    self.act("PUT", &path, serde_json::to_value(rule).ok(), &format!("Rule #{id} {what}d"))
                }
            }
        }
    }

    fn rule_form(&mut self, ui: &mut Ui) {
        let app_names: Vec<(String, String)> =
            lock(&self.data).apps().iter().map(|a| (a.app.0.clone(), a.name.clone())).collect();
        let f = &mut self.form;
        let mut save = false;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            if let Some(orig) = &f.editing {
                ui.label(RichText::new(format!("Editing rule #{}", orig.id)).strong());
                ui.add_space(2.0);
            }
            egui::Grid::new("rule-form").num_columns(4).spacing([12.0, 8.0]).show(ui, |ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut f.name);
                ui.label("Action");
                egui::ComboBox::from_id_salt("action")
                    .selected_text(match f.action {
                        FormAction::Block => "Block",
                        FormAction::Allow => "Allow",
                        FormAction::Limit => "Limit bandwidth",
                        FormAction::Quota => "Data quota",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut f.action, FormAction::Block, "Block");
                        ui.selectable_value(&mut f.action, FormAction::Allow, "Allow");
                        ui.selectable_value(&mut f.action, FormAction::Limit, "Limit bandwidth");
                        ui.selectable_value(&mut f.action, FormAction::Quota, "Data quota");
                    });
                ui.end_row();

                match f.action {
                    FormAction::Block => {
                        ui.label("Direction");
                        direction_combo(ui, "dir", &mut f.direction);
                        ui.end_row();
                    }
                    FormAction::Limit => {
                        ui.label("Download");
                        ui.add(egui::TextEdit::singleline(&mut f.download).hint_text("e.g. 2MB/s"));
                        ui.label("Upload");
                        ui.add(egui::TextEdit::singleline(&mut f.upload).hint_text("e.g. 500kB/s"));
                        ui.end_row();
                    }
                    FormAction::Quota => {
                        ui.label("Quota");
                        ui.add(egui::TextEdit::singleline(&mut f.quota).hint_text("e.g. 20GB"));
                        ui.label("Per");
                        ui.horizontal(|ui| {
                            egui::ComboBox::from_id_salt("period")
                                .selected_text(format!("{:?}", f.period))
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut f.period, Period::Day, "Day");
                                    ui.selectable_value(&mut f.period, Period::Week, "Week");
                                    ui.selectable_value(&mut f.period, Period::Month, "Month");
                                });
                            direction_combo(ui, "qdir", &mut f.quota_direction);
                        });
                        ui.end_row();
                    }
                    FormAction::Allow => {}
                }

                ui.label("Application");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut f.app).hint_text("name, path or glob (any)"));
                    egui::ComboBox::from_id_salt("pick-app").selected_text("▼").width(30.0).show_ui(
                        ui,
                        |ui| {
                            for (path, name) in &app_names {
                                if ui.selectable_label(f.app == *path, name).on_hover_text(path).clicked() {
                                    f.app = path.clone();
                                }
                            }
                        },
                    );
                });
                ui.label("Protocol");
                egui::ComboBox::from_id_salt("proto")
                    .selected_text(f.protocol.map_or("Any".to_string(), |p| p.to_string().to_uppercase()))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut f.protocol, None, "Any");
                        ui.selectable_value(&mut f.protocol, Some(Protocol::Tcp), "TCP");
                        ui.selectable_value(&mut f.protocol, Some(Protocol::Udp), "UDP");
                    });
                ui.end_row();

                ui.label("Remote networks");
                ui.add(egui::TextEdit::singleline(&mut f.remote).hint_text("10.0.0.0/8, 2001:db8::/32"));
                ui.label("Remote ports");
                ui.add(egui::TextEdit::singleline(&mut f.ports).hint_text("443, 8000-8100"));
                ui.end_row();

                ui.label("Active on");
                ui.horizontal(|ui| {
                    for (i, name) in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].iter().enumerate() {
                        ui.toggle_value(&mut f.days[i], *name);
                    }
                });
                ui.label("Time");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut f.from).hint_text("09:00").desired_width(60.0));
                    ui.label("–");
                    ui.add(egui::TextEdit::singleline(&mut f.until).hint_text("17:00").desired_width(60.0));
                });
                ui.end_row();

                ui.label("Network");
                egui::ComboBox::from_id_salt("metered").selected_text(metered_label(f.metered)).show_ui(
                    ui,
                    |ui| {
                        for choice in [None, Some(true), Some(false)] {
                            ui.selectable_value(&mut f.metered, choice, metered_label(choice));
                        }
                    },
                );
                ui.label("Network names");
                ui.add(egui::TextEdit::singleline(&mut f.networks).hint_text("Home, Pixel 8 (any)"));
                ui.end_row();
            });
            ui.weak(
                "No days and no time means always active. Metered networks are phone hotspots and mobile \
                 data, or any network you mark as metered.",
            );
            if let Some(e) = &f.error {
                ui.colored_label(col_bad(), e);
            }
            save = ui
                .add(egui::Button::new(RichText::new("Save rule").color(col_on_accent())).fill(col_accent()))
                .clicked();
        });
        if save {
            match self.form.build() {
                Err(e) => self.form.error = Some(e),
                Ok(rule) => {
                    self.form.error = None;
                    let call = match &self.form.editing {
                        Some(orig) => Call::new(
                            "PUT",
                            format!("/api/rules/{}", orig.id),
                            Some(rule),
                            format!("Rule #{} saved", orig.id),
                        ),
                        None => Call::new("POST", "/api/rules", Some(rule), "Rule added"),
                    };
                    let _ = self.poller.send(Request::Call(Call { rule_form: true, ..call }));
                }
            }
        }
        // The daemon's answer to the last submission.
        match lock(&self.data).rule_form_result.take() {
            Some(Ok(())) => self.form = RuleForm::default(),
            Some(Err(e)) => self.form.error = Some(e),
            None => {}
        }
    }

    fn usage_tab(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.strong("Data usage");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let before = self.usage_days;
                egui::ComboBox::from_id_salt("usage-days")
                    .selected_text(format!("Last {} days", self.usage_days))
                    .show_ui(ui, |ui| {
                        for days in [7, 30, 90, 365] {
                            ui.selectable_value(&mut self.usage_days, days, format!("Last {days} days"));
                        }
                    });
                if before != self.usage_days {
                    let _ = self.poller.send(Request::Usage(self.usage_days));
                }
            });
        });
        let d = lock(&self.data);
        let usage = d.usage.clone();
        drop(d);
        if usage.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.weak("No usage recorded yet."));
            return;
        }
        // One slot per calendar day, oldest first, including days without traffic.
        let n = self.usage_days;
        let by_day: std::collections::HashMap<&str, &nwl_core::api::UsageDay> =
            usage.iter().map(|u| (u.day.as_str(), u)).collect();
        let today = chrono::Local::now().date_naive();
        let days: Vec<(String, u64, u64)> = (0..n)
            .rev()
            .map(|back| {
                let day = (today - chrono::Days::new(back as u64)).format("%Y-%m-%d").to_string();
                let (down, up) = by_day
                    .get(day.as_str())
                    .map_or((0, 0), |u| u.apps.iter().fold((0, 0), |(d, up), a| (d + a.down, up + a.up)));
                (day, down, up)
            })
            .collect();
        let labels: Vec<String> = days.iter().map(|d| d.0.clone()).collect();
        let down_bars: Vec<Bar> =
            days.iter().enumerate().map(|(i, d)| Bar::new(i as f64, d.1 as f64).width(0.7)).collect();
        let up_bars: Vec<Bar> =
            days.iter().enumerate().map(|(i, d)| Bar::new(i as f64, d.2 as f64).width(0.7)).collect();
        let down = BarChart::new("Download", down_bars).color(col_down());
        let up = BarChart::new("Upload", up_bars).color(col_up()).stack_on(&[&down]);
        Plot::new("usage")
            .show_background(false)
            .show_grid([false, true])
            .height(190.0)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .include_y(0.0)
            .y_axis_formatter(|m, _| if m.value <= 0.0 { "0".into() } else { format_bytes(m.value as u64) })
            .x_axis_formatter(move |m, _| labels.get(m.value.round() as usize).cloned().unwrap_or_default())
            .show(ui, |p| {
                p.bar_chart(down);
                p.bar_chart(up);
            });

        let mut totals: std::collections::HashMap<String, (String, u64, u64)> = Default::default();
        for day in &usage {
            for a in &day.apps {
                let e = totals.entry(a.app.0.clone()).or_insert((a.name.clone(), 0, 0));
                e.1 += a.down;
                e.2 += a.up;
            }
        }
        let mut rows: Vec<(String, String, u64, u64)> =
            totals.into_iter().map(|(app, (n, d, u))| (app, n, d, u)).collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.2 + r.3));
        let grand = rows.iter().map(|r| r.2 + r.3).sum::<u64>().max(1);
        TableBuilder::new(ui)
            .id_salt("usage-table")
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::remainder().at_least(220.0).clip(true))
            .columns(Column::exact(100.0), 3)
            .column(Column::exact(160.0))
            .header(22.0, |mut h| {
                for t in ["APPLICATION", "DOWNLOAD", "UPLOAD", "TOTAL", "SHARE"] {
                    h.col(|ui| {
                        ui.weak(RichText::new(t).small().strong());
                    });
                }
            })
            .body(|mut body| {
                for (app, name, down, up) in rows.iter().take(200) {
                    body.row(44.0, |mut row| {
                        row.col(|ui| app_cell(ui, name, app, false, None));
                        row.col(|ui| {
                            ui.monospace(format_bytes(*down));
                        });
                        row.col(|ui| {
                            ui.monospace(format_bytes(*up));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(format_bytes(down + up)).monospace().strong());
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::ProgressBar::new((down + up) as f32 / grand as f32)
                                    .desired_width(140.0)
                                    .fill(col_accent()),
                            );
                        });
                    });
                }
            });
    }

    /// Keeps the poller fetching exactly the history view on screen, and
    /// nothing while the History tab is closed.
    fn sync_history_query(&self) {
        let wanted = (self.tab == Tab::History).then(|| (self.history_range, self.history_app.clone()));
        if lock(&self.data).history_query != wanted {
            let _ = self.poller.send(Request::History(wanted));
        }
    }

    fn history_tab(&mut self, ui: &mut Ui) {
        let (view, apps): (Option<nwl_core::api::HistoryView>, Vec<(AppId, String)>) = {
            let d = lock(&self.data);
            let mut apps: Vec<(AppId, String)> =
                d.apps().iter().map(|a| (a.app.clone(), a.name.clone())).collect();
            for a in d.history.iter().flat_map(|h| &h.apps) {
                if !apps.iter().any(|(id, _)| *id == a.app) {
                    apps.push((a.app.clone(), a.name.clone()));
                }
            }
            apps.sort_by_key(|(_, n)| n.to_lowercase());
            (d.history.clone(), apps)
        };
        ui.horizontal(|ui| {
            for range in Range::ALL {
                let short = match range {
                    Range::Hour => "1 hour",
                    Range::Day => "24 hours",
                    Range::Week => "7 days",
                    Range::Month => "30 days",
                    Range::Quarter => "90 days",
                };
                if ui.selectable_label(self.history_range == range, short).clicked() {
                    self.history_range = range;
                }
            }
            ui.separator();
            let selected =
                self.history_app.as_ref().map_or("All traffic".to_string(), |a| a.display_name().to_string());
            egui::ComboBox::from_id_salt("history-app").selected_text(selected).width(180.0).show_ui(
                ui,
                |ui| {
                    ui.selectable_value(&mut self.history_app, None, "All traffic");
                    for (id, name) in &apps {
                        ui.selectable_value(&mut self.history_app, Some(id.clone()), name)
                            .on_hover_text(&id.0);
                    }
                },
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button("Export CSV")
                    .on_hover_text(if cfg!(target_arch = "wasm32") {
                        "Download this range as CSV"
                    } else {
                        "Save this range as CSV in your Downloads folder"
                    })
                    .clicked()
                {
                    self.export_history(ui.ctx());
                }
            });
        });
        self.sync_history_query();
        let Some(view) = view.filter(|v| v.range == self.history_range) else {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.spinner());
            return;
        };
        let (up, down) = view.points.iter().fold((0, 0), |(u, d), p| (u + p.up, d + p.down));
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.strong(format!("{}:", self.history_range.label()));
            ui.label(RichText::new(format!("↓ {}", format_bytes(down))).color(col_down()));
            ui.label(RichText::new(format!("↑ {}", format_bytes(up))).color(col_up()));
            ui.weak(format!("· one point per {}", step_label(view.step_secs)));
        });
        let step = view.step_secs;
        let to_points = |pick: fn(&nwl_core::history::Point) -> u64| -> Vec<[f64; 2]> {
            view.points.iter().map(|p| [p.t as f64, pick(p) as f64]).collect()
        };
        Plot::new("history")
            .show_background(false)
            .show_grid([false, true])
            .height(220.0)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .include_y(0.0)
            .y_axis_formatter(|m, _| if m.value <= 0.0 { "0".into() } else { format_bytes(m.value as u64) })
            .x_axis_formatter(move |m, _| local_time_label(m.value as i64, step))
            .label_formatter(move |h| match h {
                egui_plot::HoverPosition::NearDataPoint { plot_name, position, .. } => Some(format!(
                    "{}\n{plot_name}: {}",
                    local_time_label(position.x as i64, step.min(3600)),
                    format_bytes(position.y as u64)
                )),
                _ => None,
            })
            .show(ui, |p| {
                p.line(Line::new("Download", to_points(|p| p.down)).color(col_down()).fill(0.0).width(1.6));
                p.line(Line::new("Upload", to_points(|p| p.up)).color(col_up()).fill(0.0).width(1.6));
            });
        if self.history_app.is_some() || view.apps.is_empty() {
            return;
        }
        ui.add_space(6.0);
        ui.weak("Click an app to see its own history.");
        let grand = view.apps.iter().map(|a| a.up + a.down).sum::<u64>().max(1);
        let mut pick: Option<AppId> = None;
        // Plain text, so a click anywhere on a row selects that app.
        ui.style_mut().interaction.selectable_labels = false;
        TableBuilder::new(ui)
            .id_salt("history-apps")
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::remainder().at_least(220.0).clip(true))
            .columns(Column::exact(100.0), 3)
            .column(Column::exact(160.0))
            .header(22.0, |mut h| {
                for t in ["APPLICATION", "DOWNLOAD", "UPLOAD", "TOTAL", "SHARE"] {
                    h.col(|ui| {
                        ui.weak(RichText::new(t).small().strong());
                    });
                }
            })
            .body(|mut body| {
                for a in view.apps.iter().take(50) {
                    body.row(44.0, |mut row| {
                        row.col(|ui| app_cell(ui, &a.name, &a.app.0, false, None));
                        row.col(|ui| {
                            ui.monospace(format_bytes(a.down));
                        });
                        row.col(|ui| {
                            ui.monospace(format_bytes(a.up));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(format_bytes(a.down + a.up)).monospace().strong());
                        });
                        row.col(|ui| {
                            let share = (a.down + a.up) as f32 / grand as f32;
                            ui.add(egui::ProgressBar::new(share).desired_width(140.0).fill(col_accent()));
                        });
                        if row.response().clicked() {
                            pick = Some(a.app.clone());
                        }
                    });
                }
            });
        if let Some(app) = pick {
            self.history_app = Some(app);
        }
    }

    /// Saves the current history view as CSV in the Downloads folder (in the
    /// browser: downloads it).
    fn export_history(&self, ctx: &egui::Context) {
        let range = serde_json::to_value(self.history_range)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let mut path = format!("/api/history.csv?range={range}");
        let mut name = format!("nattowok-history-{range}");
        if let Some(app) = &self.history_app {
            path += &format!("&app={}", crate::client::encode(&app.0));
            name += &format!(
                "-{}",
                app.display_name().replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_")
            );
        }
        #[cfg(target_arch = "wasm32")]
        {
            // The daemon names the file and marks it as a download.
            let _ = name;
            ctx.open_url(egui::OpenUrl::same_tab(format!("{}{path}", self.client.base())));
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = ctx;
            let result = self.client.get_text(&path).and_then(|csv| {
                let dir = downloads_dir();
                let file = dir.join(format!("{name}.csv"));
                std::fs::write(&file, csv).map_err(|e| format!("saving {}: {e}", file.display()))?;
                Ok(file)
            });
            lock(&self.data).toast = Some(match result {
                Ok(file) => (format!("Saved {}", file.display()), true, Instant::now()),
                Err(e) => (e, false, Instant::now()),
            });
        }
    }

    fn events_tab(&self, ui: &mut Ui) {
        let events = lock(&self.data).events.clone();
        if events.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.weak("Nothing has happened yet."));
            return;
        }
        egui::ScrollArea::vertical().id_salt("events").show(ui, |ui| {
            for e in &events {
                ui.horizontal(|ui| {
                    ui.weak(local_time(e.time));
                    let (text, color) = match &e.kind {
                        EventKind::NewApp { app, name } => (format!("{name} used the network for the first time ({app})"), None),
                        EventKind::QuotaWarning { rule, name, percent } => (format!("Rule #{rule} {name} has used {percent}% of its quota"), Some(col_accent())),
                        EventKind::QuotaExhausted { rule, name } => (format!("Quota reached for rule #{rule} {name}: traffic blocked until the period resets"), Some(col_bad())),
                        EventKind::RuleAdded { rule, name } => (format!("Rule #{rule} added {name}"), None),
                        EventKind::RuleChanged { rule, name } => (format!("Rule #{rule} changed {name}"), None),
                        EventKind::RuleRemoved { rule, name } => (format!("Rule #{rule} removed {name}"), None),
                        EventKind::EnforcementError { message } => (format!("Enforcement error: {message}"), Some(col_bad())),
                        EventKind::EnforcementRecovered => ("Enforcement recovered".into(), Some(col_ok())),
                        EventKind::Paused => ("All rules paused".into(), Some(col_accent())),
                        EventKind::Resumed => ("All rules resumed".into(), Some(col_ok())),
                        EventKind::NetworkChanged { name, metered, rules } => {
                            let kind = if *metered { "metered" } else { "unmetered" };
                            let name = name.as_deref().map_or(String::new(), |n| format!(" {n}"));
                            (format!("Now on {kind} network{name}: {rules} network rule(s) apply"), metered.then_some(col_accent()))
                        }
                        EventKind::TrafficSpike { .. } => {
                            let (title, body) = crate::notify::text(&e.kind).unwrap_or_default();
                            (format!("{title}. {body}"), Some(col_accent()))
                        }
                    };
                    match color {
                        Some(c) => ui.colored_label(c, text),
                        None => ui.label(text),
                    };
                });
                ui.separator();
            }
        });
    }

    fn footer(&mut self, ui: &mut Ui) {
        let d = lock(&self.data);
        ui.horizontal(|ui| {
            match &d.status {
                Some(s) => ui.weak(format!(
                    "nwld v{} · {} · {} · {}",
                    s.version,
                    s.enforcement.monitor,
                    s.enforcement.enforcer,
                    self.client.base()
                )),
                None => ui.weak(self.client.base()),
            };
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.link("About").clicked() {
                    self.show_about = !self.show_about;
                }
            });
        });
        if let Some(s) = &d.status {
            if let Some(e) = &s.enforcement.error {
                ui.colored_label(col_bad(), format!("Enforcement failed: {e}"));
            }
            for w in &s.enforcement.warnings {
                ui.colored_label(col_accent(), w);
            }
        }
    }
}

/// "1 minute", "5 minutes", "1 hour", "6 hours", "1 day".
fn step_label(secs: i64) -> String {
    match secs {
        s if s % 86_400 == 0 => plural(s / 86_400, "day"),
        s if s % 3600 == 0 => plural(s / 3600, "hour"),
        s => plural(s / 60, "minute"),
    }
}

fn plural(n: i64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

/// A local-time axis label suited to the point size.
fn local_time_label(unix: i64, step: i64) -> String {
    let Some(t) = chrono::DateTime::from_timestamp(unix, 0).map(|t| t.with_timezone(&chrono::Local)) else {
        return String::new();
    };
    if step < 3600 {
        t.format("%H:%M").to_string()
    } else if step < 86_400 {
        t.format("%a %H:%M").to_string()
    } else {
        t.format("%b %d").to_string()
    }
}

/// The user's Downloads folder, or their home folder.
#[cfg(not(target_arch = "wasm32"))]
fn downloads_dir() -> std::path::PathBuf {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| ".".into());
    let downloads = home.join("Downloads");
    if downloads.is_dir() {
        downloads
    } else {
        home
    }
}

fn local_time(unix_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(unix_ms)
        .map(|t| t.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

/// A labelled figure in the header; laid out right to left.
fn total(ui: &mut Ui, label: &str, value: String, color: Color32) {
    ui.allocate_ui_with_layout(egui::vec2(124.0, 40.0), egui::Layout::top_down(egui::Align::Max), |ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(RichText::new(label).small().color(crate::theme::current().weak).strong());
        ui.label(RichText::new(value).size(18.0).strong().color(color));
    });
}

fn direction_combo(ui: &mut Ui, id: &str, dir: &mut Direction) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(match dir {
            Direction::Both => "Both directions",
            Direction::In => "Incoming",
            Direction::Out => "Outgoing",
        })
        .show_ui(ui, |ui| {
            ui.selectable_value(dir, Direction::Both, "Both directions");
            ui.selectable_value(dir, Direction::In, "Incoming");
            ui.selectable_value(dir, Direction::Out, "Outgoing");
        });
}

/// The app's quota closest to its cap, if it has any.
fn app_quota<'a>(
    rules: &[u64],
    quotas: &'a [nwl_core::quota::QuotaStatus],
) -> Option<&'a nwl_core::quota::QuotaStatus> {
    quotas.iter().filter(|q| rules.contains(&q.rule)).max_by(|a, b| {
        let frac = |q: &nwl_core::quota::QuotaStatus| q.used as f64 / q.limit.max(1) as f64;
        frac(a).total_cmp(&frac(b))
    })
}

/// Green, amber from 80%, red when used up.
fn quota_color(q: &nwl_core::quota::QuotaStatus) -> Color32 {
    if q.exhausted {
        col_bad()
    } else if q.used as f64 >= q.limit as f64 * 0.8 {
        col_accent()
    } else {
        col_ok()
    }
}

/// A thin rounded progress bar.
fn quota_bar(ui: &mut Ui, width: f32, frac: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 6.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 3.0, crate::theme::current().surface);
    let mut fill = rect;
    fill.set_width((rect.width() * frac.clamp(0.0, 1.0)).max(4.0));
    ui.painter().rect_filled(fill, 3.0, color);
}

/// "1.20 GB of 5.00 GB today".
fn quota_text(q: &nwl_core::quota::QuotaStatus) -> String {
    let when = match q.period {
        Period::Day => "today",
        Period::Week => "this week",
        Period::Month => "this month",
    };
    if q.exhausted {
        format!("{} used up {when}", format_bytes(q.limit))
    } else {
        format!("{} of {} {when}", format_bytes(q.used), format_bytes(q.limit))
    }
}

/// An app's icon, name and path; `tag` adds a colored note after the name,
/// with a small progress bar when it has a fraction (quotas).
fn app_cell(ui: &mut Ui, name: &str, path: &str, blocked: bool, tag: Option<(String, Color32, Option<f32>)>) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), egui::Sense::hover());
        let mut color = avatar_color(path);
        if blocked {
            color = color.gamma_multiply(0.4);
        }
        ui.painter().rect_filled(rect, 6.0, color);
        let letter = name.chars().next().unwrap_or('?').to_uppercase().to_string();
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            letter,
            egui::FontId::proportional(14.0),
            Color32::WHITE,
        );
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let mut n = RichText::new(name).strong();
            if blocked {
                n = n.strikethrough().weak();
            }
            ui.horizontal(|ui| {
                // Not selectable, so a click on the name opens the row.
                ui.add(egui::Label::new(n).selectable(false));
                if let Some((text, color, frac)) = tag {
                    if let Some(frac) = frac {
                        quota_bar(ui, 40.0, frac, color);
                    }
                    ui.label(RichText::new(text).small().color(color));
                }
            });
            ui.add(egui::Label::new(RichText::new(path).small().weak()).selectable(false))
                .on_hover_text(path);
        });
    });
}

fn sparkline(ui: &mut Ui, history: &VecDeque<(u64, u64)>) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(100.0, 24.0), egui::Sense::hover());
    let max = history.iter().map(|&(u, d)| u.max(d)).max().unwrap_or(0).max(1) as f32;
    let n = history.len();
    let point = |i: usize, v: u64| {
        let x = rect.right() - (n - 1 - i) as f32 * rect.width() / (SPARK - 1) as f32;
        egui::pos2(x, rect.bottom() - 1.0 - (rect.height() - 2.0) * v as f32 / max)
    };
    if n >= 2 {
        let down: Vec<_> = history.iter().enumerate().map(|(i, s)| point(i, s.1)).collect();
        let up: Vec<_> = history.iter().enumerate().map(|(i, s)| point(i, s.0)).collect();
        ui.painter().add(egui::Shape::line(down, Stroke::new(1.4, col_down())));
        ui.painter().add(egui::Shape::line(up, Stroke::new(1.2, col_up())));
    }
}

/// Remote hosts of one app this session, most traffic first.
fn remotes_table(ui: &mut Ui, remotes: &[nwl_core::api::RemoteView]) {
    if remotes.is_empty() {
        ui.weak("No traffic to remote hosts yet.");
        return;
    }
    let max = remotes.iter().map(|r| r.up + r.down).max().unwrap_or(1).max(1);
    TableBuilder::new(ui)
        .id_salt("remotes")
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::remainder().at_least(260.0).clip(true))
        .columns(Column::exact(95.0), 2)
        .column(Column::exact(120.0).clip(true))
        .column(Column::exact(50.0))
        .column(Column::exact(140.0))
        .header(22.0, |mut h| {
            for t in ["HOST", "col_down()", "col_up()", "PORTS", "OPEN", "SHARE"] {
                h.col(|ui| {
                    ui.weak(RichText::new(t).small().strong());
                });
            }
        })
        .body(|mut body| {
            for r in remotes {
                body.row(34.0, |mut row| {
                    row.col(|ui| {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            match &r.host {
                                Some(h) => {
                                    ui.label(RichText::new(h).strong()).on_hover_text(h);
                                    ui.label(RichText::new(r.ip.to_string()).monospace().small().weak());
                                }
                                None => {
                                    ui.monospace(r.ip.to_string());
                                }
                            }
                        });
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(format_bytes(r.down)).color(col_down()).monospace());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(format_bytes(r.up)).color(col_up()).monospace());
                    });
                    row.col(|ui| {
                        let protos: Vec<String> = r.protocols.iter().map(|p| p.to_string()).collect();
                        let ports: Vec<String> = r.ports.iter().map(u16::to_string).collect();
                        ui.label(format!("{} {}", protos.join("/"), ports.join(",")));
                    });
                    row.col(|ui| {
                        ui.label(r.open_connections.to_string());
                    });
                    row.col(|ui| {
                        let frac = (r.up + r.down) as f32 / max as f32;
                        ui.add(egui::ProgressBar::new(frac).desired_width(120.0).fill(col_accent()));
                    });
                });
            }
        });
}

fn conn_table(ui: &mut Ui, id: &str, conns: &[ConnView], with_app: bool) {
    let mut t = TableBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
    if with_app {
        t = t.column(Column::exact(150.0).clip(true));
    }
    t.column(Column::exact(45.0))
        .column(Column::exact(190.0).clip(true))
        .column(Column::remainder().at_least(220.0).clip(true))
        .column(Column::exact(90.0))
        .columns(Column::exact(90.0), 2)
        .column(Column::exact(65.0))
        .column(Column::exact(130.0).clip(true))
        .header(22.0, |mut h| {
            let titles: &[&str] =
                &["PROTO", "LOCAL", "REMOTE", "STATE", "col_down()", "col_up()", "RTT", "POLICY"];
            if with_app {
                h.col(|ui| {
                    ui.weak(RichText::new("APP").small().strong());
                });
            }
            for t in titles {
                h.col(|ui| {
                    ui.weak(RichText::new(*t).small().strong());
                });
            }
        })
        .body(|mut body| {
            for c in conns {
                body.row(34.0, |mut row| {
                    if with_app {
                        row.col(|ui| {
                            ui.label(c.name.as_deref().unwrap_or("unknown"));
                        });
                    }
                    row.col(|ui| {
                        ui.label(RichText::new(c.conn.key.protocol.to_string()).small());
                    });
                    row.col(|ui| {
                        ui.monospace(c.conn.key.local.to_string());
                    });
                    row.col(|ui| {
                        let remote = c.conn.key.remote.map_or("*".into(), |r| r.to_string());
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            match &c.remote_host {
                                Some(h) => {
                                    ui.label(RichText::new(h).strong()).on_hover_text(h);
                                    ui.label(RichText::new(remote).monospace().small().weak());
                                }
                                None => {
                                    ui.monospace(remote);
                                }
                            }
                        });
                    });
                    row.col(|ui| {
                        ui.label(c.conn.state.map(|s| format!("{s:?}").to_lowercase()).unwrap_or_default());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(rate(c.rate_down)).color(col_down()).monospace());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(rate(c.rate_up)).color(col_up()).monospace());
                    });
                    row.col(|ui| {
                        ui.label(
                            c.conn.rtt_us.map_or("–".into(), |r| format!("{:.1} ms", r as f64 / 1000.0)),
                        );
                    });
                    row.col(|ui| {
                        if c.blocked {
                            ui.colored_label(col_bad(), format!("blocked #{}", c.access_rule.unwrap_or(0)));
                        } else if !c.limits.is_empty() {
                            ui.colored_label(
                                col_accent(),
                                format!(
                                    "limited #{}",
                                    c.limits.iter().map(u64::to_string).collect::<Vec<_>>().join(",")
                                ),
                            );
                        } else if let Some(r) = c.access_rule {
                            ui.weak(format!("allowed #{r}"));
                        }
                    });
                });
            }
        });
}

/// The apps offered in the tray: every app with a one-click block or limit
/// (so it can be undone there), then the busiest by session traffic; sorted
/// by name so the menu does not reshuffle while it is open.
fn tray_apps(d: &crate::data::Data) -> Vec<crate::tray::TrayApp> {
    let mut apps: Vec<&AppView> = d.apps().iter().collect();
    let quotas = d.overview.as_ref().map(|o| o.quotas.as_slice()).unwrap_or_default();
    apps.sort_by_key(|a| {
        let ruled = a.block_rule.is_some() || a.limit_rule.is_some() || app_quota(&a.rules, quotas).is_some();
        (!ruled, std::cmp::Reverse(a.total_up + a.total_down))
    });
    let mut picked: Vec<crate::tray::TrayApp> = apps
        .into_iter()
        .take(crate::tray::MENU_APPS)
        .map(|a| {
            let limit = match d.rule(a.limit_rule).map(|r| &r.action) {
                Some(nwl_core::rules::Action::Limit { download, upload }) => {
                    download.or(*upload).map(|r| r.0)
                }
                _ => None,
            };
            let quota = app_quota(&a.rules, quotas).map(quota_text);
            crate::tray::TrayApp { target: a.into(), down: a.rate_down, up: a.rate_up, limit, quota }
        })
        .collect();
    picked.sort_by_key(|a| a.target.name.to_lowercase());
    picked
}

impl NwlApp {
    /// Runs a one-click action (block, limit, ...) on an app.
    fn quick_action(&self, target: &crate::actions::Target, action: &crate::actions::QuickAction) {
        if let Some(r) = crate::actions::request(target, action) {
            self.act(r.method, &r.path, r.body, &r.done);
        }
    }

    fn show_window(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn hide_window(&mut self, ctx: &egui::Context) {
        self.hidden = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
    }

    /// Handles tray commands and keeps the tray icon current. Runs every
    /// tick, also while the window is hidden.
    fn drive_tray(&mut self, ctx: &egui::Context) {
        let Some(tray) = &self.tray else { return };
        let commands = tray.commands();
        let tray_visible = tray.visible();
        for command in commands {
            match command {
                crate::tray::TrayCommand::ToggleWindow => {
                    if self.hidden {
                        self.show_window(ctx);
                    } else if tray_visible {
                        self.hide_window(ctx);
                    } else {
                        self.show_window(ctx);
                    }
                }
                crate::tray::TrayCommand::SetPaused(paused) => self.set_paused(paused),
                crate::tray::TrayCommand::SetNotifications(on) => {
                    let mut d = lock(&self.data);
                    d.notify.enabled = on;
                    if let Err(e) = d.notify.save() {
                        d.toast = Some((e, false, Instant::now()));
                    }
                }
                crate::tray::TrayCommand::App(target, action) => self.quick_action(&target, &action),
                crate::tray::TrayCommand::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        // Closing the window hides it to the tray, if a tray host shows the
        // icon; otherwise the app would become unreachable, so it closes.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting && tray_visible {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.hide_window(ctx);
        }
        let state = {
            let d = lock(&self.data);
            let enforcement = d.status.as_ref().map(|s| &s.enforcement);
            crate::tray::TrayState {
                connected: d.connected,
                paused: enforcement.filter(|e| e.enforcing).map(|e| e.paused),
                down: d.overview.as_ref().map_or(0, |o| o.system.rate_down),
                up: d.overview.as_ref().map_or(0, |o| o.system.rate_up),
                notifications: d.notify.enabled,
                apps: tray_apps(&d),
            }
        };
        if let Some(tray) = &mut self.tray {
            tray.update(state);
        }
    }
}

impl eframe::App for NwlApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Started hidden at login. eframe shows the window after its first
        // frame, so hide it again; then watch the tray for a few seconds and
        // open the window if no tray host shows the icon (the app would be
        // unreachable otherwise).
        if let Some(at) = self.startup_check {
            if self.hidden {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
            match self.tray.as_ref().map(|t| t.visible()) {
                None | Some(false) => {
                    self.startup_check = None;
                    if self.hidden {
                        self.show_window(ctx);
                    }
                }
                Some(true) if at.elapsed() > Duration::from_secs(3) => self.startup_check = None,
                Some(true) => ctx.request_repaint_after(Duration::from_millis(250)),
            }
        }
        self.drive_tray(ctx);
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // The chosen theme (or the system's light/dark one), applied on change.
        let system_dark = ctx.system_theme().map_or(true, |t| t == egui::Theme::Dark);
        let palette = crate::theme::resolve(&self.theme, system_dark);
        if palette.id != self.applied_theme {
            crate::theme::apply(&ctx, &palette);
            self.applied_theme = palette.id;
        }
        let bar = |margin: egui::Margin| {
            egui::Frame::new()
                .fill(palette.panel)
                .stroke(Stroke::new(1.0, palette.border))
                .inner_margin(margin)
        };
        egui::Panel::top("header").frame(bar(egui::Margin::symmetric(16, 10))).show(ui, |ui| {
            self.header(ui);
        });
        egui::Panel::bottom("footer").frame(bar(egui::Margin::symmetric(16, 6))).show(ui, |ui| {
            self.footer(ui);
        });
        let page = egui::Frame::new().fill(palette.bg).inner_margin(egui::Margin::same(14));
        egui::CentralPanel::default().frame(page).show(ui, |ui| {
            crate::theme::card()
                .inner_margin(egui::Margin { left: 6, right: 12, top: 10, bottom: 6 })
                .show(ui, |ui| self.graph(ui));
            ui.add_space(12.0);
            self.tabs(ui);
            ui.add_space(10.0);
            self.sync_history_query();
            crate::theme::card().show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                self.tab_content(ui);
            });
        });
        self.limit_window(&ctx);
        self.notify_window(&ctx);
        self.about_window(&ctx);

        let (toast, undo) = {
            let d = lock(&self.data);
            let undo = d.toast_undo.clone().filter(|(at, _)| Some(*at) == d.toast.as_ref().map(|t| t.2));
            (d.toast.clone(), undo.map(|(_, call)| call))
        };
        if let Some((text, ok, at)) = toast {
            // Undoable toasts stay a little longer.
            let shown = Duration::from_secs(if undo.is_some() { 7 } else { 4 });
            if at.elapsed() < shown {
                egui::Area::new(egui::Id::new("toast"))
                    .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -48.0])
                    .show(&ctx, |ui| {
                        egui::Frame::popup(ui.style()).corner_radius(10).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let color = if ok { col_ok() } else { col_bad() };
                                let (dot, _) =
                                    ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                                ui.painter().circle_filled(dot.center(), 4.0, color);
                                ui.label(text);
                                if let Some(call) = &undo {
                                    if ui.button(RichText::new("Undo").strong()).clicked() {
                                        let _ = self.poller.send(Request::Call(call.clone()));
                                        let mut d = lock(&self.data);
                                        d.toast = None;
                                        d.toast_undo = None;
                                    }
                                }
                            });
                        });
                    });
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }
    }
}

fn metered_label(metered: Option<bool>) -> &'static str {
    match metered {
        None => "Any network",
        Some(true) => "Metered only",
        Some(false) => "Unmetered only",
    }
}

/// The current network in the header, with the choice of treating it as
/// metered or not. Returns the choice made (`Some(None)`: as detected).
fn network_menu(ui: &mut Ui, net: &nwl_core::api::NetworkView) -> Option<Option<bool>> {
    let name = net.name.as_deref().unwrap_or("Network");
    let p = crate::theme::current();
    let (text, color) = if net.metered {
        (format!("📶 {name} · metered"), p.accent)
    } else {
        (format!("📶 {name}"), p.weak)
    };
    let button = egui::Button::new(RichText::new(text).color(if net.metered { p.accent } else { p.text }))
        .fill(crate::theme::mix(p.panel, color, if net.metered { 0.16 } else { 0.08 }))
        .stroke(Stroke::new(1.0, crate::theme::mix(p.panel, color, 0.4)))
        .corner_radius(12);
    let mut choice = None;
    egui::containers::menu::MenuButton::from_button(button)
        .ui(ui, |ui| {
            ui.label(RichText::new(name).strong());
            let detected = match net.detected {
                Some(true) => "metered",
                Some(false) => "not metered",
                None => "unknown",
            };
            let source = if net.source.is_empty() || net.source == "none" {
                String::new()
            } else {
                format!(" by {}", net.source)
            };
            ui.weak(format!("Detected{source}: {detected}"));
            ui.separator();
            ui.label("Treat this network as");
            for (value, text) in
                [(None, "As detected"), (Some(true), "Metered"), (Some(false), "Not metered")]
            {
                if ui.radio(net.overridden == value, text).clicked() {
                    choice = Some(value);
                    ui.close();
                }
            }
            ui.add_space(4.0);
            ui.weak("Rules can apply only on metered networks,\ne.g. a phone hotspot.");
        })
        .0
        .on_hover_text("The network rules see. Click to mark it metered or not.");
    choice
}

/// The theme picker in the header. Returns the choice made.
fn theme_menu(ui: &mut Ui, current: &str) -> Option<String> {
    let mut choice = None;
    egui::containers::menu::MenuButton::from_button(egui::Button::new("🎨"))
        .ui(ui, |ui| {
            ui.label(RichText::new("Theme").strong());
            ui.add_space(2.0);
            let system = crate::theme::SYSTEM;
            if ui.radio(current == system, "Match the system (light or dark)").clicked() {
                choice = Some(system.to_string());
                ui.close();
            }
            ui.separator();
            for palette in crate::theme::THEMES {
                let clicked = ui
                    .horizontal(|ui| {
                        let clicked = ui.radio(current == palette.id, palette.name).clicked();
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            crate::theme::swatch(ui, &palette);
                        });
                        clicked
                    })
                    .inner;
                if clicked {
                    choice = Some(palette.id.to_string());
                    ui.close();
                }
            }
        })
        .0
        .on_hover_text("Theme");
    choice
}

/// Starts the system service through polkit (a password prompt), reporting
/// the outcome as a toast. The poller notices when it answers.
#[cfg(not(target_arch = "wasm32"))]
fn start_service(data: Shared) {
    lock(&data).toast = Some(("Starting the service…".into(), true, Instant::now()));
    std::thread::spawn(move || {
        let result =
            std::process::Command::new("pkexec").args(["systemctl", "start", "nwld.service"]).output();
        let toast = match result {
            Ok(out) if out.status.success() => ("Service started".to_string(), true),
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr);
                if err.contains("not found") || err.contains("not loaded") {
                    ("nwld.service isn't installed. Start nwld with: sudo nwld".to_string(), false)
                } else if out.status.code() == Some(126) || out.status.code() == Some(127) {
                    ("Not started: the password prompt was cancelled".to_string(), false)
                } else {
                    (format!("Starting the service failed: {}", err.trim()), false)
                }
            }
            Err(_) => ("pkexec isn't available. Run: sudo systemctl start nwld".to_string(), false),
        };
        lock(&data).toast = Some((toast.0, toast.1, Instant::now()));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opening a rule in the form and saving it unchanged gives the same rule,
    /// including what the form doesn't show.
    #[test]
    fn editing_a_rule_round_trips() {
        let rules = [
            r#"{"id":4,"name":"Steam on the hotspot","enabled":false,
                "match":{"app":"steam","protocol":"tcp","remote":["10.0.0.0/8","2001:db8::/32"],
                         "remote_ports":[443,"27000-27100"],"local_ports":[5000],"uid":1000},
                "action":{"type":"limit","download":1234567,"upload":"1MB/s"},
                "schedule":{"days":["mon","fri"],"from":"22:00","until":"06:00"},
                "network":{"metered":true,"names":["Pixel 8","Office"]}}"#,
            r#"{"id":7,"name":"","enabled":true,"match":{"app":"/usr/bin/dropbox"},
                "action":{"type":"quota","limit":"500MB","period":"day","direction":"out"}}"#,
            r#"{"id":9,"name":"x","enabled":true,"match":{},"action":{"type":"block","direction":"in"},
                "schedule":{"days":["sat","sun"]}}"#,
            r#"{"id":2,"name":"ok","enabled":true,"match":{"remote":["192.168.1.0/24"]},"action":{"type":"allow"}}"#,
        ];
        for json in rules {
            let rule: Rule = serde_json::from_str(json).unwrap();
            let built = RuleForm::from_rule(&rule).build().unwrap();
            let back: Rule = serde_json::from_value(built).unwrap();
            assert_eq!(back, rule, "{json}");
        }
        assert_eq!(exact_size(5_000_000), "5.00 MB");
        assert_eq!(exact_size(1_234_567), "1234567");
        assert_eq!(exact_rate(1_234_567), "1234567B/s");
    }
}
