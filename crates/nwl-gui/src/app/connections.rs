//! Connection and remote-host tables, and actions on a connection.

use super::*;

/// Remote hosts of one app this session, most traffic first.
pub(super) fn remotes_table(ui: &mut Ui, remotes: &[nwl_core::api::RemoteView]) {
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
                            let detail = with_location(r.ip.to_string(), &r.location);
                            match r.domain.as_ref().or(r.host.as_ref()) {
                                Some(h) => {
                                    ui.label(RichText::new(h).strong()).on_hover_text(h);
                                    ui.label(RichText::new(detail).monospace().small().weak())
                                        .on_hover_text(location_text(&r.location));
                                }
                                None => {
                                    ui.monospace(r.ip.to_string());
                                    ui.label(RichText::new(location_text(&r.location)).small().weak());
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

/// What the user chose from a connection's menu.
pub(super) enum ConnAction {
    Close(ConnView),
    /// Block the remote address, for the connection's app or (`false`) all apps.
    BlockHost(ConnView, bool),
}

impl NwlApp {
    pub(super) fn conn_action(&self, action: ConnAction) {
        match action {
            ConnAction::Close(c) => {
                let what =
                    c.remote_host.clone().or(c.conn.key.remote.map(|r| r.to_string())).unwrap_or_default();
                let body = serde_json::to_value(&c.conn.key).ok();
                self.act("POST", "/api/connections/close", body, &format!("Closed the connection to {what}"));
            }
            ConnAction::BlockHost(c, just_app) => {
                let Some(remote) = c.conn.key.remote else { return };
                let ip = remote.ip();
                // By domain when the app looked one up: it keeps working as
                // the domain's addresses change. Else by address.
                let (host, mut matcher) = match &c.domain {
                    Some(d) => (d.clone(), json!({"domains": [d]})),
                    None => {
                        let net = if ip.is_ipv4() { format!("{ip}/32") } else { format!("{ip}/128") };
                        (c.remote_host.clone().unwrap_or_else(|| ip.to_string()), json!({"remote": [net]}))
                    }
                };
                let app_name = c.name.clone().unwrap_or_else(|| "this app".into());
                let name = match (&c.app, just_app) {
                    (Some(app), true) => {
                        matcher["app"] = json!(app.0);
                        format!("Block {host} for {app_name}")
                    }
                    _ => format!("Block {host}"),
                };
                let rule = json!({"name": name, "match": matcher, "action": {"type": "block"}});
                self.act("POST", "/api/rules", Some(rule), &name);
            }
        }
    }
}

/// The connections table; returns what was chosen from a row's menu.
pub(super) fn conn_table(ui: &mut Ui, id: &str, conns: &[ConnView], with_app: bool) -> Option<ConnAction> {
    let mut action = None;
    let mut t = TableBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
    if with_app {
        t = t.column(Column::exact(130.0).clip(true));
    }
    t.column(Column::exact(45.0))
        .column(Column::exact(175.0).clip(true))
        .column(Column::remainder().at_least(200.0).clip(true))
        .column(Column::exact(85.0))
        .columns(Column::exact(90.0), 2)
        .column(Column::exact(65.0))
        .column(Column::exact(110.0).clip(true))
        .column(Column::exact(36.0))
        .header(22.0, |mut h| {
            let titles: &[&str] = &["PROTO", "LOCAL", "REMOTE", "STATE", "DOWN", "UP", "RTT", "POLICY", ""];
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
                        let remote = with_location(remote, &c.location);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            // The domain the app looked up, else the reverse-DNS name.
                            match c.domain.as_ref().or(c.remote_host.as_ref()) {
                                Some(h) => {
                                    let hover = match (&c.domain, &c.remote_host) {
                                        (Some(d), Some(r)) if d != r => format!("{d}\nreverse DNS: {r}"),
                                        _ => h.clone(),
                                    };
                                    ui.label(RichText::new(h).strong()).on_hover_text(hover);
                                    ui.label(RichText::new(remote).monospace().small().weak())
                                        .on_hover_text(location_text(&c.location));
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
                    row.col(|ui| {
                        let Some(remote) = c.conn.key.remote else { return };
                        let host = c
                            .domain
                            .clone()
                            .or(c.remote_host.clone())
                            .unwrap_or_else(|| remote.ip().to_string());
                        // Keyed by the connection, not the row: rows re-sort
                        // every second, and an open menu must stay with its
                        // connection.
                        ui.push_id(&c.conn.key, |ui| {
                            ui.menu_button("⋯", |ui| {
                                ui.label(RichText::new(&host).strong());
                                ui.separator();
                                if ui.button("Close this connection").clicked() {
                                    action = Some(ConnAction::Close(c.clone()));
                                    ui.close();
                                }
                                if c.app.is_some() {
                                    let app = c.name.as_deref().unwrap_or("this app");
                                    if ui.button(format!("Block {host} for {app}")).clicked() {
                                        action = Some(ConnAction::BlockHost(c.clone(), true));
                                        ui.close();
                                    }
                                }
                                if ui.button(format!("Block {host} for all apps")).clicked() {
                                    action = Some(ConnAction::BlockHost(c.clone(), false));
                                    ui.close();
                                }
                                if ui.button("Copy the address").clicked() {
                                    ui.ctx().copy_text(remote.to_string());
                                    ui.close();
                                }
                            });
                        });
                    });
                });
            }
        });
    action
}

impl NwlApp {
    pub(super) fn connections_tab(&mut self, ui: &mut Ui) {
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
        let mut conns: Vec<ConnView> = d
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
                        c.domain.clone().unwrap_or_default(),
                        c.conn.key.protocol.to_string(),
                    ]
                    .iter()
                    .any(|v| v.to_lowercase().contains(&f))
            })
            .take(1000)
            .cloned()
            .collect();
        drop(d);
        if self.freeze_conns {
            let pos =
                |c: &ConnView| self.conn_order.iter().position(|k| *k == c.conn.key).unwrap_or(usize::MAX);
            conns.sort_by_key(pos);
        }
        self.conn_order = conns.iter().map(|c| c.conn.key.clone()).collect();
        if conns.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.weak("No connections."));
            return;
        }
        let table = ui.scope(|ui| conn_table(ui, "conns", &conns, true));
        self.freeze_conns = ui.rect_contains_pointer(table.response.rect) || ui.ctx().any_popup_open();
        if let Some(action) = table.inner {
            self.conn_action(action);
        }
    }
}
