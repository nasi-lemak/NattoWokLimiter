//! Windows over the app: notification and startup settings, About, the
//! new-app question, and the event log tab.

use super::*;

impl NwlApp {
    pub(super) fn notify_window(&mut self, ctx: &egui::Context) {
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
                        ui.checkbox(
                            &mut settings.program_changed,
                            "An app's program changes (updated or replaced)",
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
    pub(super) fn about_window(&mut self, ctx: &egui::Context) {
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

    /// Asks about the oldest app waiting to use the network.
    pub(super) fn prompt_window(&mut self, ctx: &egui::Context) {
        let (prompt, more) = {
            let d = lock(&self.data);
            let prompts = d.overview.as_ref().map(|o| o.prompts.clone()).unwrap_or_default();
            (prompts.first().cloned(), prompts.len().saturating_sub(1))
        };
        let Some(p) = prompt else { return };
        let icons = self.icon_uris.clone();
        let mut answer = None;
        egui::Window::new("A new app wants to go online")
            .id(egui::Id::new("prompt"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_width(440.0);
                app_cell(ui, &p.name, &p.app.0, false, None, &icons);
                ui.add_space(6.0);
                ui.label(format!(
                    "{} is using the network for the first time. It's on hold until you decide.",
                    p.name
                ));
                if more > 0 {
                    ui.weak(format!("{more} more waiting after this one."));
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    use nwl_core::api::Answer;
                    let allow =
                        egui::Button::new(RichText::new("Allow").color(col_on_accent())).fill(col_accent());
                    if ui.add(allow).on_hover_text("Allow it from now on").clicked() {
                        answer = Some(Answer::Allow);
                    }
                    if ui.button("Allow this time").on_hover_text("Ask again after a restart").clicked() {
                        answer = Some(Answer::Once);
                    }
                    let block = egui::Button::new(RichText::new("Block").color(crate::theme::current().bg))
                        .fill(col_bad());
                    if ui.add(block).on_hover_text("Adds a block rule for it").clicked() {
                        answer = Some(Answer::Block);
                    }
                });
            });
        if let Some(answer) = answer {
            let target = crate::actions::Target {
                app: p.app.clone(),
                name: p.name.clone(),
                block_rule: None,
                limit_rule: None,
            };
            self.quick_action(&target, &crate::actions::QuickAction::Answer(answer));
        }
    }

    pub(super) fn events_tab(&self, ui: &mut Ui) {
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
                        EventKind::ProgramChanged { name, app } => {
                            (format!("{name}'s program changed ({app}): updated or replaced"), Some(col_accent()))
                        }
                        EventKind::AskNewApp { name, .. } => {
                            (format!("{name} wanted to use the network; held until answered"), Some(col_accent()))
                        }
                        EventKind::Imported { rules, replaced: true } => {
                            (format!("Rules restored from a backup ({rules} rules)"), None)
                        }
                        EventKind::Imported { rules, replaced: false } => {
                            (format!("{rules} rules added from a backup"), None)
                        }
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
}
