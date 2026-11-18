//! The desktop UI.

use crate::client::Client;
use crate::data::{lock, Request, Shared, HISTORY, SPARK};
use eframe::egui::{self, Color32, RichText, Stroke, Ui};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Bar, BarChart, Line, Plot};
use nwl_core::api::{AppView, ConnView, EventKind};
use nwl_core::model::{AppId, Direction, Protocol};
use nwl_core::rate::{format_bytes, ByteSize, Rate};
use nwl_core::rules::{Day, Period, Rule, TimeOfDay};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

const DOWN: Color32 = Color32::from_rgb(59, 130, 246);
const UP: Color32 = Color32::from_rgb(236, 72, 153);
const ACCENT: Color32 = Color32::from_rgb(217, 119, 6);
const BAD: Color32 = Color32::from_rgb(220, 38, 38);
const OK: Color32 = Color32::from_rgb(22, 163, 74);

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
            error: None,
        }
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ']).map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect()
}

impl RuleForm {
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
        let mut rule = json!({"name": self.name.trim(), "match": m, "action": action});
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
    dark: bool,
    show_notify_settings: bool,
    /// The tray icon, where the desktop has a tray.
    tray: Option<crate::tray::Tray>,
    /// The window is hidden to the tray.
    hidden: bool,
    /// Quit was chosen: let the window close instead of hiding it.
    quitting: bool,
    /// Row order of the apps table last frame, and whether the pointer was
    /// over it: rows keep their place while the user aims at a button.
    app_order: Vec<AppId>,
    freeze_order: bool,
}

impl NwlApp {
    pub fn new(ctx: &egui::Context, client: Client, data: Shared, poller: Sender<Request>) -> Self {
        let dark = ctx.global_style().visuals.dark_mode;
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
            dark,
            show_notify_settings: false,
            tray: {
                let ctx = ctx.clone();
                crate::tray::Tray::new(move || ctx.request_repaint())
            },
            hidden: false,
            quitting: false,
            app_order: Vec::new(),
            freeze_order: false,
        }
    }

    /// Runs one API call (fast: the daemon is local), reports the outcome as a
    /// toast and refreshes.
    fn act(&self, method: &str, path: &str, body: Option<Value>, done: &str) -> Result<Value, String> {
        let result = self.client.call(method, path, body);
        let toast = match &result {
            Ok(_) => (done.to_string(), true, Instant::now()),
            Err(e) => (e.clone(), false, Instant::now()),
        };
        lock(&self.data).toast = Some(toast);
        let _ = self.poller.send(Request::Refresh);
        result
    }

    /// Pauses or resumes all rules in the daemon.
    pub fn set_paused(&self, paused: bool) {
        let done = if paused { "All rules paused" } else { "Rules resumed" };
        let _ = self.act("POST", "/api/pause", Some(json!({ "paused": paused })), done);
    }

    fn header(&mut self, ui: &mut Ui) {
        let d = lock(&self.data);
        let mut toggle_pause: Option<bool> = None;
        ui.horizontal(|ui| {
            let (logo, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
            ui.painter().circle_filled(logo.center(), 11.0, ACCENT);
            let chevron = [
                logo.center() + egui::vec2(-5.0, 3.0),
                logo.center() + egui::vec2(0.0, -3.0),
                logo.center() + egui::vec2(5.0, 3.0),
            ];
            ui.painter().add(egui::Shape::line(chevron.to_vec(), Stroke::new(2.5, Color32::WHITE)));
            ui.label(RichText::new("NattoWok Limiter").strong().size(18.0));
            ui.add_space(8.0);
            let (text, color) = match (&d.status, d.connected) {
                (_, false) => ("Disconnected".to_string(), BAD),
                (Some(s), true) => {
                    let e = &s.enforcement;
                    let demo = if e.monitor.starts_with("simulated") { "Demo · " } else { "" };
                    if e.error.is_some() {
                        (format!("{demo}Enforcement error"), BAD)
                    } else if e.paused {
                        (format!("{demo}Paused: nothing is blocked or limited"), ACCENT)
                    } else if !e.enforcing {
                        (format!("{demo}Monitor only"), ACCENT)
                    } else {
                        (format!("{demo}Enforcing"), OK)
                    }
                }
                (None, true) => ("Connecting…".to_string(), ACCENT),
            };
            let (dot, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
            ui.painter().circle_filled(dot.center(), 4.0, color);
            ui.label(RichText::new(text).color(color).strong());
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
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🔔").on_hover_text("Notifications").clicked() {
                    self.show_notify_settings = !self.show_notify_settings;
                }
                let icon = if self.dark { "☀" } else { "🌙" };
                if ui.button(icon).on_hover_text("Toggle theme").clicked() {
                    self.dark = !self.dark;
                    ui.ctx().set_visuals(if self.dark {
                        egui::Visuals::dark()
                    } else {
                        egui::Visuals::light()
                    });
                }
                if let Some(o) = &d.overview {
                    let s = &o.system;
                    total(ui, "SESSION", format_bytes(s.total_up + s.total_down), ui.visuals().text_color());
                    total(ui, "UPLOAD", rate(s.rate_up), UP);
                    total(ui, "DOWNLOAD", rate(s.rate_down), DOWN);
                }
            });
        });
        drop(d);
        if let Some(paused) = toggle_pause {
            self.set_paused(paused);
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
                p.line(Line::new("Download", points(|s| s.1)).color(DOWN).fill(0.0).width(1.6));
                p.line(Line::new("Upload", points(|s| s.0)).color(UP).fill(0.0).width(1.6));
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
            (Tab::Usage, "Usage", 0),
            (Tab::Events, "Events", d.events.len()),
        ];
        drop(d);
        ui.horizontal(|ui| {
            for (tab, label, count) in counts {
                let text = if count > 0 { format!("{label} {count}") } else { label.to_string() };
                if ui.selectable_label(self.tab == tab, RichText::new(text).strong()).clicked() {
                    self.tab = tab;
                }
            }
        });
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
                    body.row(38.0, |mut row| {
                        row.col(|ui| {
                            let tag = quotas.iter().find(|q| a.rules.contains(&q.rule)).map(|q| {
                                let color = if q.exhausted { BAD } else { ACCENT };
                                (format!("{} / {}", format_bytes(q.used), format_bytes(q.limit)), color)
                            });
                            app_cell(ui, &a.name, &a.app.0, a.blocked, tag);
                        });
                        row.col(|ui| sparkline(ui, &histories[i]));
                        row.col(|ui| {
                            ui.label(RichText::new(rate(a.rate_down)).color(DOWN).monospace());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(rate(a.rate_up)).color(UP).monospace());
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
                                RichText::new(limit_text).color(ACCENT)
                            } else {
                                RichText::new(limit_text)
                            });
                            if ui.add(limit_btn).clicked() {
                                clicked = Some((i, "limit"));
                            }
                            let block = if a.block_rule.is_some() {
                                egui::Button::new(RichText::new("Blocked").color(Color32::WHITE)).fill(BAD)
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
                    let _ = match a.block_rule {
                        Some(id) => self.act("DELETE", &format!("/api/rules/{id}"), None, &format!("Unblocked {}", a.name)),
                        None => self.act(
                            "POST",
                            "/api/rules",
                            Some(json!({"name": format!("Block {}", a.name), "match": {"app": a.app}, "action": {"type": "block"}})),
                            &format!("Blocked {}", a.name),
                        ),
                    };
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
        egui::Window::new("Notifications")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::RIGHT_TOP, [-12.0, 56.0])
            .show(ctx, |ui| {
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
                    });
                });
                ui.add_space(4.0);
                ui.weak("Only events from now on; past events stay in the Events tab.");
                if let Some(e) = &error {
                    ui.colored_label(BAD, format!("Notification service: {e}"));
                }
                if ui.button("Send a test notification").clicked() {
                    test = true;
                }
            });
        if settings != before {
            let saved = settings.save();
            let mut d = lock(&self.data);
            d.notify = settings;
            if let Err(e) = saved {
                d.toast = Some((e, false, Instant::now()));
            }
        }
        if test {
            let result = crate::notify::show("NattoWok Limiter", "Notifications are working.");
            lock(&self.data).notify_error = result.err();
        }
        self.show_notify_settings = open;
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
                    ui.colored_label(BAD, e);
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
                )
                .is_err()
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
                            self.act("DELETE", &format!("/api/rules/{id}"), None, "Limit removed").is_err()
                        }
                        None => false,
                    },
                    (Ok(down), Ok(up)) => {
                        let body = json!({"name": format!("Limit {}", dialog.name), "match": {"app": dialog.app}, "action": {"type": "limit", "download": down, "upload": up}});
                        let (method, path) = match dialog.rule {
                            Some(id) => ("PUT", format!("/api/rules/{id}")),
                            None => ("POST", "/api/rules".to_string()),
                        };
                        self.act(method, &path, Some(body), &format!("Limited {}", dialog.name)).is_err()
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
                    .add(egui::Button::new(RichText::new(label).color(Color32::WHITE)).fill(ACCENT))
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
                                let frac = (q.used as f32 / q.limit.max(1) as f32).min(1.0);
                                let period = format!("{:?}", q.period).to_lowercase();
                                let text = format!(
                                    "{} of {} this {period}",
                                    format_bytes(q.used),
                                    format_bytes(q.limit)
                                );
                                ui.add(
                                    egui::ProgressBar::new(frac)
                                        .desired_width(320.0)
                                        .fill(if q.exhausted { BAD } else { ACCENT })
                                        .text(text),
                                );
                            }
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("×").on_hover_text("Delete").clicked() {
                                op = Some((r.id, "delete", i));
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
            let _ = match what {
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
            };
        }
    }

    fn rule_form(&mut self, ui: &mut Ui) {
        let app_names: Vec<(String, String)> =
            lock(&self.data).apps().iter().map(|a| (a.app.0.clone(), a.name.clone())).collect();
        let f = &mut self.form;
        let mut save = false;
        egui::Frame::group(ui.style()).show(ui, |ui| {
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
            });
            ui.weak("No days and no time means always active.");
            if let Some(e) = &f.error {
                ui.colored_label(BAD, e);
            }
            save = ui
                .add(egui::Button::new(RichText::new("Save rule").color(Color32::WHITE)).fill(ACCENT))
                .clicked();
        });
        if save {
            match self.form.build() {
                Err(e) => self.form.error = Some(e),
                Ok(rule) => {
                    let result = self.client.call("POST", "/api/rules", Some(rule));
                    let _ = self.poller.send(Request::Refresh);
                    match result {
                        Ok(_) => {
                            self.form = RuleForm::default();
                            lock(&self.data).toast = Some(("Rule added".into(), true, Instant::now()));
                        }
                        Err(e) => self.form.error = Some(e),
                    }
                }
            }
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
        let down = BarChart::new("Download", down_bars).color(DOWN);
        let up = BarChart::new("Upload", up_bars).color(UP).stack_on(&[&down]);
        Plot::new("usage")
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
                    body.row(36.0, |mut row| {
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
                                    .fill(ACCENT),
                            );
                        });
                    });
                }
            });
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
                        EventKind::QuotaWarning { rule, name, percent } => (format!("Rule #{rule} {name} has used {percent}% of its quota"), Some(ACCENT)),
                        EventKind::QuotaExhausted { rule, name } => (format!("Quota reached for rule #{rule} {name}: traffic blocked until the period resets"), Some(BAD)),
                        EventKind::RuleAdded { rule, name } => (format!("Rule #{rule} added {name}"), None),
                        EventKind::RuleChanged { rule, name } => (format!("Rule #{rule} changed {name}"), None),
                        EventKind::RuleRemoved { rule, name } => (format!("Rule #{rule} removed {name}"), None),
                        EventKind::EnforcementError { message } => (format!("Enforcement error: {message}"), Some(BAD)),
                        EventKind::EnforcementRecovered => ("Enforcement recovered".into(), Some(OK)),
                        EventKind::Paused => ("All rules paused".into(), Some(ACCENT)),
                        EventKind::Resumed => ("All rules resumed".into(), Some(OK)),
                        EventKind::TrafficSpike { .. } => {
                            let (title, body) = crate::notify::text(&e.kind).unwrap_or_default();
                            (format!("{title}. {body}"), Some(ACCENT))
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

    fn footer(&self, ui: &mut Ui) {
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
        });
        if let Some(s) = &d.status {
            if let Some(e) = &s.enforcement.error {
                ui.colored_label(BAD, format!("Enforcement failed: {e}"));
            }
            for w in &s.enforcement.warnings {
                ui.colored_label(ACCENT, w);
            }
        }
        if let Some(e) = &d.error {
            ui.colored_label(BAD, format!("{e}. Is nwld running? Retrying every second."));
        }
    }
}

fn local_time(unix_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(unix_ms)
        .map(|t| t.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

/// A labelled figure in the header; laid out right to left.
fn total(ui: &mut Ui, label: &str, value: String, color: Color32) {
    ui.allocate_ui_with_layout(egui::vec2(120.0, 40.0), egui::Layout::top_down(egui::Align::Max), |ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        ui.weak(RichText::new(label).small());
        ui.label(RichText::new(value).size(17.0).strong().color(color));
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

fn app_cell(ui: &mut Ui, name: &str, path: &str, blocked: bool, tag: Option<(String, Color32)>) {
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
                if let Some((text, color)) = tag {
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
        ui.painter().add(egui::Shape::line(down, Stroke::new(1.4, DOWN)));
        ui.painter().add(egui::Shape::line(up, Stroke::new(1.2, UP)));
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
            for t in ["HOST", "DOWN", "UP", "PORTS", "OPEN", "SHARE"] {
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
                        ui.label(RichText::new(format_bytes(r.down)).color(DOWN).monospace());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(format_bytes(r.up)).color(UP).monospace());
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
                        ui.add(egui::ProgressBar::new(frac).desired_width(120.0).fill(ACCENT));
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
            let titles: &[&str] = &["PROTO", "LOCAL", "REMOTE", "STATE", "DOWN", "UP", "RTT", "POLICY"];
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
                        ui.label(RichText::new(rate(c.rate_down)).color(DOWN).monospace());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(rate(c.rate_up)).color(UP).monospace());
                    });
                    row.col(|ui| {
                        ui.label(
                            c.conn.rtt_us.map_or("–".into(), |r| format!("{:.1} ms", r as f64 / 1000.0)),
                        );
                    });
                    row.col(|ui| {
                        if c.blocked {
                            ui.colored_label(BAD, format!("blocked #{}", c.access_rule.unwrap_or(0)));
                        } else if !c.limits.is_empty() {
                            ui.colored_label(
                                ACCENT,
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

impl NwlApp {
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
            }
        };
        if let Some(tray) = &mut self.tray {
            tray.update(state);
        }
    }
}

impl eframe::App for NwlApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drive_tray(ctx);
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(6.0);
            self.header(ui);
            ui.add_space(4.0);
        });
        egui::Panel::bottom("footer").show(ui, |ui| {
            ui.add_space(2.0);
            self.footer(ui);
            ui.add_space(2.0);
        });
        egui::CentralPanel::default().show(ui, |ui| {
            self.graph(ui);
            ui.add_space(6.0);
            self.tabs(ui);
            ui.separator();
            match self.tab {
                Tab::Apps => {
                    egui::ScrollArea::vertical().id_salt("apps-scroll").show(ui, |ui| self.apps_tab(ui)).inner
                }
                Tab::Connections => self.connections_tab(ui),
                Tab::Rules => self.rules_tab(ui),
                Tab::Usage => {
                    egui::ScrollArea::vertical()
                        .id_salt("usage-scroll")
                        .show(ui, |ui| self.usage_tab(ui))
                        .inner
                }
                Tab::Events => self.events_tab(ui),
            }
        });
        self.limit_window(&ctx);
        self.notify_window(&ctx);

        let toast = lock(&self.data).toast.clone();
        if let Some((text, ok, at)) = toast {
            if at.elapsed() < Duration::from_secs(4) {
                egui::Area::new(egui::Id::new("toast"))
                    .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -48.0])
                    .show(&ctx, |ui| {
                        egui::Frame::popup(ui.style()).show(ui, |ui| {
                            ui.colored_label(if ok { OK } else { BAD }, text);
                        });
                    });
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }
    }
}
