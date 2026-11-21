//! The desktop UI (also the web dashboard, compiled to WebAssembly): the
//! header, live graph, tabs and footer, and the frame loop that ties them to
//! the poller's data, the tray and the theme.
//!
//! Each tab and dialog lives in its own module; they add `impl NwlApp`
//! blocks, so they share the app's state directly:
//! * `apps`: Applications and the limit dialog;
//! * `connections`: connections, remote hosts and connection actions;
//! * `rules`: rules, the rule form, presets, backup and restore;
//! * `history`: History and Usage;
//! * `dialogs`: settings, About, the new-app question, events;
//! * `widgets`: small shared pieces (colors, app cells, quota bars, menus).

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

mod apps;
mod connections;
mod dialogs;
mod history;
mod rules;
mod widgets;

use apps::*;
use connections::*;
use rules::*;
use widgets::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Apps,
    Connections,
    Rules,
    History,
    Usage,
    Events,
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
    import: Option<ImportDialog>,
    show_presets: bool,
    /// Image URIs of app icons registered with egui.
    icon_uris: std::collections::HashMap<AppId, String>,
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
    /// The same for connections: rows hold still under the pointer and
    /// while a row's menu is open.
    conn_order: Vec<nwl_core::model::ConnKey>,
    freeze_conns: bool,
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
            icon_uris: Default::default(),
            import: None,
            show_presets: false,
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
            conn_order: Vec::new(),
            freeze_conns: false,
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
                // DB-IP's free databases ask for a credit where their data shows.
                if d.status.as_ref().is_some_and(|s| s.geoip.iter().any(|f| f.contains("dbip"))) {
                    ui.hyperlink_to(RichText::new("IP geolocation by DB-IP").small(), "https://db-ip.com");
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
        let system_dark = ctx.system_theme().is_none_or(|t| t == egui::Theme::Dark);
        let palette = crate::theme::resolve(&self.theme, system_dark);
        if palette.id != self.applied_theme {
            crate::theme::apply(&ctx, &palette);
            self.applied_theme = palette.id;
        }
        // Hand newly fetched app icons to egui's image loaders.
        {
            let d = lock(&self.data);
            for (app, icon) in &d.icons {
                if let (Some((uri, bytes)), false) = (icon, self.icon_uris.contains_key(app)) {
                    ctx.include_bytes(uri.clone(), bytes.clone());
                    self.icon_uris.insert(app.clone(), uri.clone());
                }
            }
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
        self.import_window(&ctx);
        self.presets_window(&ctx);
        self.prompt_window(&ctx);

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
