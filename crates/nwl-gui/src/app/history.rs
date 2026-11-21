//! The History and Usage tabs, and CSV export.

use super::*;

impl NwlApp {
    pub(super) fn usage_tab(&mut self, ui: &mut Ui) {
        let icons = self.icon_uris.clone();
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
                        row.col(|ui| app_cell(ui, name, app, false, None, &icons));
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
    pub(super) fn sync_history_query(&self) {
        let wanted = (self.tab == Tab::History).then(|| (self.history_range, self.history_app.clone()));
        if lock(&self.data).history_query != wanted {
            let _ = self.poller.send(Request::History(wanted));
        }
    }

    pub(super) fn history_tab(&mut self, ui: &mut Ui) {
        let icons = self.icon_uris.clone();
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
                        row.col(|ui| app_cell(ui, &a.name, &a.app.0, false, None, &icons));
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
    pub(super) fn export_history(&self, ctx: &egui::Context) {
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
}
