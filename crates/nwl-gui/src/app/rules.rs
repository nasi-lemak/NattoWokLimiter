//! The Rules tab: the rule list and form, presets, backup and restore.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FormAction {
    Block,
    Allow,
    Limit,
    Quota,
}

pub(super) struct RuleForm {
    pub(super) open: bool,
    pub(super) name: String,
    pub(super) action: FormAction,
    pub(super) direction: Direction,
    pub(super) download: String,
    pub(super) upload: String,
    pub(super) quota: String,
    pub(super) period: Period,
    pub(super) quota_direction: Direction,
    pub(super) app: String,
    pub(super) remote: String,
    pub(super) ports: String,
    /// Remote domains, comma-separated.
    pub(super) domains: String,
    pub(super) protocol: Option<Protocol>,
    pub(super) days: [bool; 7],
    pub(super) from: String,
    pub(super) until: String,
    /// Only on metered (`Some(true)`) or unmetered networks.
    pub(super) metered: Option<bool>,
    /// Only on networks with these names (comma-separated).
    pub(super) networks: String,
    /// The rule being edited; saving replaces it. Fields the form doesn't
    /// show (local ports, user) are kept from it.
    pub(super) editing: Option<Rule>,
    pub(super) error: Option<String>,
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
            domains: String::new(),
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

pub(super) fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ']).map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect()
}

/// A size for a text field: readable when that is exact (`5.00 MB`),
/// otherwise the exact byte count, so editing never changes a value by itself.
pub(super) fn exact_size(bytes: u64) -> String {
    let pretty = format_bytes(bytes);
    if pretty.parse::<ByteSize>().is_ok_and(|b| b.0 == bytes) {
        pretty
    } else {
        bytes.to_string()
    }
}

pub(super) fn exact_rate(bytes: u64) -> String {
    let pretty = format!("{}/s", format_bytes(bytes));
    if pretty.parse::<Rate>().is_ok_and(|r| r.0 == bytes) {
        pretty
    } else {
        format!("{bytes}B/s")
    }
}

impl RuleForm {
    /// The form filled in from an existing rule, to edit it.
    pub(super) fn from_rule(rule: &Rule) -> Self {
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
        f.domains = m.domains.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ");
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
    pub(super) fn build(&self) -> Result<Value, String> {
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
        let domains = split_list(&self.domains);
        if !domains.is_empty() {
            m.insert("domains".into(), json!(domains));
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

/// Restoring a backup: the file (dropped on the window or, on the desktop,
/// given by path) and how to apply it.
#[derive(Default)]
pub(super) struct ImportDialog {
    /// File name and contents.
    pub(super) file: Option<(String, String)>,
    pub(super) path: String,
    pub(super) merge: bool,
    pub(super) error: Option<String>,
}

impl ImportDialog {
    pub(super) fn load(&mut self, name: String, text: String) {
        self.error = match serde_json::from_str::<nwl_core::api::Backup>(&text) {
            Ok(b) if b.format == nwl_core::api::BACKUP_FORMAT => None,
            _ => Some(format!("{name} is not a NattoWok Limiter backup.")),
        };
        self.file = Some((name, text));
    }

    /// The backup, when a valid one is loaded.
    pub(super) fn backup(&self) -> Option<nwl_core::api::Backup> {
        let (_, text) = self.file.as_ref()?;
        serde_json::from_str::<nwl_core::api::Backup>(text)
            .ok()
            .filter(|b| b.format == nwl_core::api::BACKUP_FORMAT)
    }
}

impl NwlApp {
    pub(super) fn rules_tab(&mut self, ui: &mut Ui) {
        // Asking about new apps: a daemon setting.
        let settings = lock(&self.data).settings.clone();
        if let Some(mut s) = settings {
            let before = s.ask_new_apps;
            ui.checkbox(&mut s.ask_new_apps, RichText::new("Ask before new apps use the network").strong())
                .on_hover_text(
                    "An app using the network for the first time is blocked until you allow it. \
                     It is noticed within a second, so its very first packets may get through.",
                );
            if s.ask_new_apps != before {
                let done = if s.ask_new_apps {
                    "New apps will wait for your answer"
                } else {
                    "New apps are allowed"
                };
                self.act("PUT", "/api/settings", serde_json::to_value(&s).ok(), done);
            }
            ui.add_space(4.0);
        }
        let mut export = false;
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
                if ui.button("Presets…").on_hover_text("Ready-made rule sets").clicked() {
                    self.show_presets = !self.show_presets;
                }
                if ui.button("Import…").on_hover_text("Restore rules from a backup file").clicked() {
                    self.import = Some(ImportDialog::default());
                }
                if ui.button("Export").on_hover_text("Save all rules and network choices to a file").clicked()
                {
                    export = true;
                }
            });
        });
        if export {
            self.export_backup(ui.ctx());
        }
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

    pub(super) fn rule_form(&mut self, ui: &mut Ui) {
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

                ui.label("Domains");
                ui.add(egui::TextEdit::singleline(&mut f.domains).hint_text("example.com, *.ads.example"))
                    .on_hover_text(
                        "A domain includes its subdomains. Matched by the addresses DNS answers gave for it.",
                    );
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

    /// Ready-made rule sets: what each does, and Add or Remove.
    pub(super) fn presets_window(&mut self, ctx: &egui::Context) {
        if !self.show_presets {
            return;
        }
        let rules = lock(&self.data).rules.clone();
        let mut open = true;
        let mut choice: Option<(&'static nwl_core::presets::Preset, bool)> = None;
        egui::Window::new("Presets")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_width(460.0);
                ui.weak("Each preset adds ordinary rules you can edit or delete one by one.");
                for preset in &nwl_core::presets::PRESETS {
                    ui.separator();
                    let added = rules.iter().filter(|r| preset.owns(r)).count();
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(preset.name).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if added > 0 && ui.button("Remove").clicked() {
                                choice = Some((preset, false));
                            }
                            let label = if added > 0 { "Add missing" } else { "Add" };
                            let all = added >= preset.rules().len();
                            let add = egui::Button::new(RichText::new(label).color(col_on_accent()))
                                .fill(col_accent());
                            if !all && ui.add(add).clicked() {
                                choice = Some((preset, true));
                            }
                            if all {
                                ui.colored_label(col_ok(), "Added");
                            }
                        });
                    });
                    ui.label(preset.description);
                    ui.weak(format!("Covers {}.", preset.app_labels().join(", ")));
                }
            });
        self.show_presets = open;
        match choice {
            Some((preset, true)) => {
                // Merging skips rules already there, so adding twice is harmless.
                let backup = nwl_core::api::Backup {
                    format: nwl_core::api::BACKUP_FORMAT.into(),
                    version: nwl_core::api::BACKUP_VERSION,
                    exported: String::new(),
                    rules: preset.rules(),
                    network: Default::default(),
                };
                let done = format!("Added {}", preset.name);
                self.act("POST", "/api/import?mode=merge", serde_json::to_value(backup).ok(), &done);
            }
            Some((preset, false)) => {
                let done = format!("Removed {}", preset.name);
                for rule in rules.iter().filter(|r| preset.owns(r)) {
                    let call = Call::new("DELETE", format!("/api/rules/{}", rule.id), None, done.clone());
                    let _ = self.poller.send(Request::Call(call));
                }
            }
            None => {}
        }
    }

    /// Saves a backup of rules and network choices in the Downloads folder
    /// (in the browser: downloads it).
    pub(super) fn export_backup(&self, ctx: &egui::Context) {
        #[cfg(target_arch = "wasm32")]
        ctx.open_url(egui::OpenUrl::same_tab(format!("{}/api/export", self.client.base())));
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = ctx;
            let name = format!("nattowok-backup-{}.json", chrono::Local::now().format("%Y-%m-%d"));
            let result = self.client.get_text("/api/export").and_then(|json| {
                let file = downloads_dir().join(&name);
                std::fs::write(&file, json).map_err(|e| format!("saving {}: {e}", file.display()))?;
                Ok(file)
            });
            lock(&self.data).toast = Some(match result {
                Ok(file) => (format!("Backup saved to {}", file.display()), true, Instant::now()),
                Err(e) => (e, false, Instant::now()),
            });
        }
    }

    /// Restoring a backup: takes files dropped on the window (anywhere), and
    /// asks whether to replace or merge.
    pub(super) fn import_window(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(file) = dropped.into_iter().next() {
            let name = file
                .path()
                .file_name()
                .map_or_else(|| file.path().display().to_string(), |n| n.to_string_lossy().into_owned());
            let text =
                |bytes: Result<Vec<u8>, String>| bytes.map(|b| String::from_utf8_lossy(&b).into_owned());
            #[cfg(not(target_arch = "wasm32"))]
            {
                lock(&self.data).dropped_file = Some((name, text(file.bytes())));
            }
            #[cfg(target_arch = "wasm32")]
            {
                // Browsers read files asynchronously.
                let (data, ctx) = (self.data.clone(), ctx.clone());
                wasm_bindgen_futures::spawn_local(async move {
                    let read = text(file.bytes_async().await);
                    lock(&data).dropped_file = Some((name, read));
                    ctx.request_repaint();
                });
            }
        }
        if let Some((name, read)) = lock(&self.data).dropped_file.take() {
            let dialog = self.import.get_or_insert_with(ImportDialog::default);
            match read {
                Ok(text) => dialog.load(name, text),
                Err(e) => dialog.error = Some(format!("{name}: {e}")),
            }
            self.tab = Tab::Rules;
        }
        let Some(dialog) = &mut self.import else { return };
        let mut open = true;
        let mut restore = false;
        egui::Window::new("Restore a backup")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_width(420.0);
                match dialog.backup() {
                    Some(b) => {
                        let (name, _) = dialog.file.as_ref().expect("a backup is loaded");
                        ui.label(RichText::new(name).strong());
                        let when = b.exported.get(..10).unwrap_or("an unknown date");
                        ui.label(format!(
                            "{} rules and {} network choices, saved {when}.",
                            b.rules.len(),
                            b.network.metered.len()
                        ));
                    }
                    None => {
                        ui.label("Drop a NattoWok Limiter backup file (.json) onto this window.");
                    }
                }
                #[cfg(not(target_arch = "wasm32"))]
                ui.horizontal(|ui| {
                    ui.label("Or its path:");
                    let edit = ui.add(egui::TextEdit::singleline(&mut dialog.path).desired_width(220.0));
                    let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (ui.button("Open").clicked() || enter) && !dialog.path.trim().is_empty() {
                        let path = dialog.path.trim().to_string();
                        match std::fs::read_to_string(&path) {
                            Ok(text) => dialog.load(path, text),
                            Err(e) => dialog.error = Some(format!("{path}: {e}")),
                        }
                    }
                });
                if let Some(e) = &dialog.error {
                    ui.colored_label(col_bad(), e);
                }
                ui.separator();
                ui.radio_value(&mut dialog.merge, false, "Replace my rules with the backup's");
                ui.radio_value(&mut dialog.merge, true, "Add the backup's rules I don't have yet");
                ui.add_space(4.0);
                let ready = dialog.backup().is_some();
                let button =
                    egui::Button::new(RichText::new("Restore").color(col_on_accent())).fill(col_accent());
                restore = ui.add_enabled(ready, button).clicked();
            });
        if restore {
            if let Some(backup) = dialog.backup() {
                let mode = if dialog.merge { "merge" } else { "replace" };
                let done = if dialog.merge { "Backup merged" } else { "Rules restored from the backup" };
                self.act(
                    "POST",
                    &format!("/api/import?mode={mode}"),
                    serde_json::to_value(backup).ok(),
                    done,
                );
            }
            open = false;
        }
        if !open {
            self.import = None;
        }
    }
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
                         "remote_ports":[443,"27000-27100"],"local_ports":[5000],"uid":1000,
                         "domains":["steampowered.com","*.steamcontent.com"]},
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
