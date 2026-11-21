//! Small shared pieces: theme colors, app cells, quota bars, sparklines,
//! the header's network and theme menus, number and time formatting.

use super::*;

// Colors of the current theme (see `crate::theme`).
pub(super) fn col_down() -> Color32 {
    crate::theme::current().down
}

pub(super) fn col_up() -> Color32 {
    crate::theme::current().up
}

pub(super) fn col_accent() -> Color32 {
    crate::theme::current().accent
}

pub(super) fn col_bad() -> Color32 {
    crate::theme::current().bad
}

pub(super) fn col_ok() -> Color32 {
    crate::theme::current().ok
}

pub(super) fn col_on_accent() -> Color32 {
    crate::theme::current().on_accent
}

pub(super) fn rate(n: u64) -> String {
    if n == 0 {
        "–".into()
    } else {
        format!("{}/s", format_bytes(n))
    }
}

pub(super) fn avatar_color(seed: &str) -> Color32 {
    let h = seed.bytes().fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32));
    let hue = (h % 360) as f32 / 360.0;
    egui::ecolor::Hsva::new(hue, 0.55, 0.62, 1.0).into()
}

/// "1 minute", "5 minutes", "1 hour", "6 hours", "1 day".
pub(super) fn step_label(secs: i64) -> String {
    match secs {
        s if s % 86_400 == 0 => plural(s / 86_400, "day"),
        s if s % 3600 == 0 => plural(s / 3600, "hour"),
        s => plural(s / 60, "minute"),
    }
}

pub(super) fn plural(n: i64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

/// A local-time axis label suited to the point size.
pub(super) fn local_time_label(unix: i64, step: i64) -> String {
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
pub(super) fn downloads_dir() -> std::path::PathBuf {
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

pub(super) fn local_time(unix_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(unix_ms)
        .map(|t| t.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

/// A labelled figure in the header; laid out right to left.
pub(super) fn total(ui: &mut Ui, label: &str, value: String, color: Color32) {
    ui.allocate_ui_with_layout(egui::vec2(124.0, 40.0), egui::Layout::top_down(egui::Align::Max), |ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(RichText::new(label).small().color(crate::theme::current().weak).strong());
        ui.label(RichText::new(value).size(18.0).strong().color(color));
    });
}

pub(super) fn direction_combo(ui: &mut Ui, id: &str, dir: &mut Direction) {
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
pub(super) fn app_quota<'a>(
    rules: &[u64],
    quotas: &'a [nwl_core::quota::QuotaStatus],
) -> Option<&'a nwl_core::quota::QuotaStatus> {
    quotas.iter().filter(|q| rules.contains(&q.rule)).max_by(|a, b| {
        let frac = |q: &nwl_core::quota::QuotaStatus| q.used as f64 / q.limit.max(1) as f64;
        frac(a).total_cmp(&frac(b))
    })
}

/// Green, amber from 80%, red when used up.
pub(super) fn quota_color(q: &nwl_core::quota::QuotaStatus) -> Color32 {
    if q.exhausted {
        col_bad()
    } else if q.used as f64 >= q.limit as f64 * 0.8 {
        col_accent()
    } else {
        col_ok()
    }
}

/// A thin rounded progress bar.
pub(super) fn quota_bar(ui: &mut Ui, width: f32, frac: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 6.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 3.0, crate::theme::current().surface);
    let mut fill = rect;
    fill.set_width((rect.width() * frac.clamp(0.0, 1.0)).max(4.0));
    ui.painter().rect_filled(fill, 3.0, color);
}

/// "1.20 GB of 5.00 GB today".
pub(super) fn quota_text(q: &nwl_core::quota::QuotaStatus) -> String {
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
pub(super) fn app_cell(
    ui: &mut Ui,
    name: &str,
    path: &str,
    blocked: bool,
    tag: Option<(String, Color32, Option<f32>)>,
    icons: &std::collections::HashMap<AppId, String>,
) {
    ui.horizontal(|ui| {
        // The app's own icon when the daemon has one, else a colored letter.
        match icons.get(&AppId(path.to_string())) {
            Some(uri) => {
                let tint = if blocked { Color32::from_white_alpha(90) } else { Color32::WHITE };
                ui.add(
                    egui::Image::from_uri(uri.clone()).fit_to_exact_size(egui::vec2(26.0, 26.0)).tint(tint),
                );
            }
            None => {
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
            }
        }
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

pub(super) fn sparkline(ui: &mut Ui, history: &VecDeque<(u64, u64)>) {
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

/// An address with its country and network owner: `1.2.3.4:443 · US · Google LLC`.
pub(super) fn with_location(address: String, loc: &nwl_core::api::Location) -> String {
    let mut out = address;
    if let Some(c) = &loc.country {
        out += &format!(" · {c}");
    }
    if let Some(o) = &loc.org {
        out += &format!(" · {o}");
    }
    out
}

/// The location in words, for hover text.
pub(super) fn location_text(loc: &nwl_core::api::Location) -> String {
    let mut parts = Vec::new();
    if let Some(name) = loc.country_name.as_ref().or(loc.country.as_ref()) {
        parts.push(name.clone());
    }
    match (&loc.org, loc.asn) {
        (Some(o), Some(n)) => parts.push(format!("{o} (AS{n})")),
        (Some(o), None) => parts.push(o.clone()),
        (None, Some(n)) => parts.push(format!("AS{n}")),
        (None, None) => {}
    }
    parts.join(", ")
}

pub(super) fn metered_label(metered: Option<bool>) -> &'static str {
    match metered {
        None => "Any network",
        Some(true) => "Metered only",
        Some(false) => "Unmetered only",
    }
}

/// The current network in the header, with the choice of treating it as
/// metered or not. Returns the choice made (`Some(None)`: as detected).
pub(super) fn network_menu(ui: &mut Ui, net: &nwl_core::api::NetworkView) -> Option<Option<bool>> {
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
pub(super) fn theme_menu(ui: &mut Ui, current: &str) -> Option<String> {
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
