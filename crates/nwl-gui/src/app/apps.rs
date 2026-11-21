//! The Applications tab and the per-app limit dialog.

use super::*;

pub(super) struct LimitDialog {
    pub(super) app: AppId,
    pub(super) name: String,
    pub(super) rule: Option<u64>,
    pub(super) down: String,
    pub(super) up: String,
    pub(super) error: Option<String>,
}

impl NwlApp {
    pub(super) fn apps_tab(&mut self, ui: &mut Ui) {
        let icons = self.icon_uris.clone();
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
                            app_cell(ui, &a.name, &a.app.0, a.blocked, tag, &icons);
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
            let view = lock(&self.data).apps().iter().find(|a| a.app == app).cloned();
            let name = view.as_ref().map_or_else(|| app.display_name().to_string(), |v| v.name.clone());
            ui.add_space(8.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong(format!("{name} talks to"));
                if ui.small_button("×").on_hover_text("Close").clicked() {
                    self.expanded = None;
                }
            });
            // Its program's fingerprint: changes when it is updated or replaced.
            if let Some(sha) = view.as_ref().and_then(|v| v.sha256.clone()) {
                ui.horizontal(|ui| {
                    ui.weak("Program SHA-256");
                    ui.monospace(RichText::new(&sha[..16.min(sha.len())]).small()).on_hover_text(&sha);
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(sha.clone());
                    }
                    if let Some(since) = view.as_ref().and_then(|v| v.program_since) {
                        let when = chrono::DateTime::from_timestamp(since, 0)
                            .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string())
                            .unwrap_or_default();
                        ui.weak(format!("since {when}"));
                    }
                });
            }
            remotes_table(ui, &remotes);
            ui.add_space(8.0);
            ui.strong("Open connections");
            if let Some(action) = conn_table(ui, "detail", &detail, false) {
                self.conn_action(action);
            }
        }
    }

    pub(super) fn limit_window(&mut self, ctx: &egui::Context) {
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
}
