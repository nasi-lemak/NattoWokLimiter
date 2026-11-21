//! Color themes and the app's look.
//!
//! A theme is a [`Palette`]; [`style`] turns it into a complete egui style
//! (widgets, windows, spacing, text sizes) so every theme gets the same
//! polish. "System" follows the desktop's or browser's light/dark setting.
//! The choice is remembered: in a file next to the notification settings on
//! the desktop, in local storage in the browser.

use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Margin, Shadow, Stroke, TextStyle};
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub id: &'static str,
    pub name: &'static str,
    pub dark: bool,
    /// Behind everything.
    pub bg: Color32,
    /// Header and footer bars, cards, windows.
    pub panel: Color32,
    /// Inputs, buttons, the tab strip.
    pub surface: Color32,
    pub border: Color32,
    pub text: Color32,
    pub weak: Color32,
    pub accent: Color32,
    /// Text on an accent-colored background.
    pub on_accent: Color32,
    pub down: Color32,
    pub up: Color32,
    pub ok: Color32,
    pub bad: Color32,
}

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

pub const NATTO: Palette = Palette {
    id: "natto",
    name: "Natto (dark)",
    dark: true,
    bg: rgb(0x141518),
    panel: rgb(0x1b1c20),
    surface: rgb(0x26272c),
    border: rgb(0x303137),
    text: rgb(0xe7e7ea),
    weak: rgb(0x8d8f98),
    accent: rgb(0xf59e0b),
    on_accent: rgb(0x1b1300),
    down: rgb(0x60a5fa),
    up: rgb(0xf472b6),
    ok: rgb(0x34d399),
    bad: rgb(0xf87171),
};

pub const DAYLIGHT: Palette = Palette {
    id: "daylight",
    name: "Daylight (light)",
    dark: false,
    bg: rgb(0xf3f4f7),
    panel: rgb(0xffffff),
    surface: rgb(0xeceef2),
    border: rgb(0xdcdfe5),
    text: rgb(0x1d2127),
    weak: rgb(0x6b7280),
    accent: rgb(0xd97706),
    on_accent: rgb(0xffffff),
    down: rgb(0x2563eb),
    up: rgb(0xdb2777),
    ok: rgb(0x15803d),
    bad: rgb(0xdc2626),
};

pub const MIDNIGHT: Palette = Palette {
    id: "midnight",
    name: "Midnight",
    dark: true,
    bg: rgb(0x0a0f1e),
    panel: rgb(0x10172b),
    surface: rgb(0x1a2340),
    border: rgb(0x26315a),
    text: rgb(0xdde5ff),
    weak: rgb(0x8290b8),
    accent: rgb(0x22d3ee),
    on_accent: rgb(0x04222a),
    down: rgb(0x38bdf8),
    up: rgb(0xa78bfa),
    ok: rgb(0x34d399),
    bad: rgb(0xfb7185),
};

pub const FOREST: Palette = Palette {
    id: "forest",
    name: "Forest",
    dark: true,
    bg: rgb(0x0e1411),
    panel: rgb(0x141c17),
    surface: rgb(0x1d2a22),
    border: rgb(0x2a3b31),
    text: rgb(0xe1ece5),
    weak: rgb(0x869a8d),
    accent: rgb(0xa3e635),
    on_accent: rgb(0x142000),
    down: rgb(0x38bdf8),
    up: rgb(0xfbbf24),
    ok: rgb(0x4ade80),
    bad: rgb(0xf87171),
};

pub const SAKURA: Palette = Palette {
    id: "sakura",
    name: "Sakura (light)",
    dark: false,
    bg: rgb(0xfbf3f6),
    panel: rgb(0xffffff),
    surface: rgb(0xf6e6ec),
    border: rgb(0xedd3dd),
    text: rgb(0x3a2730),
    weak: rgb(0x8e7280),
    accent: rgb(0xdb2777),
    on_accent: rgb(0xffffff),
    down: rgb(0x7c3aed),
    up: rgb(0xe11d48),
    ok: rgb(0x047857),
    bad: rgb(0xdc2626),
};

pub const PAPER: Palette = Palette {
    id: "paper",
    name: "Paper (light)",
    dark: false,
    bg: rgb(0xf2ede3),
    panel: rgb(0xfbf8f1),
    surface: rgb(0xebe3d4),
    border: rgb(0xddd1bd),
    text: rgb(0x382f26),
    weak: rgb(0x85786a),
    accent: rgb(0xb45309),
    on_accent: rgb(0xffffff),
    down: rgb(0x1d4ed8),
    up: rgb(0xbe185d),
    ok: rgb(0x15803d),
    bad: rgb(0xb91c1c),
};

pub const CONTRAST: Palette = Palette {
    id: "contrast",
    name: "High contrast",
    dark: true,
    bg: rgb(0x000000),
    panel: rgb(0x000000),
    surface: rgb(0x141414),
    border: rgb(0xbdbdbd),
    text: rgb(0xffffff),
    weak: rgb(0xd0d0d0),
    accent: rgb(0xffd400),
    on_accent: rgb(0x000000),
    down: rgb(0x00b7ff),
    up: rgb(0xff5cd6),
    ok: rgb(0x00e676),
    bad: rgb(0xff5252),
};

/// The named themes, in menu order.
pub const THEMES: [Palette; 7] = [NATTO, DAYLIGHT, MIDNIGHT, FOREST, SAKURA, PAPER, CONTRAST];

/// The menu entry and stored value that follows the system.
pub const SYSTEM: &str = "system";

/// The palette a choice stands for; "system" picks Natto or Daylight.
pub fn resolve(choice: &str, system_dark: bool) -> Palette {
    THEMES.iter().copied().find(|p| p.id == choice).unwrap_or(if system_dark { NATTO } else { DAYLIGHT })
}

static CURRENT: RwLock<Palette> = RwLock::new(NATTO);

/// The palette in use, for colors the style doesn't cover (graphs, badges).
pub fn current() -> Palette {
    *CURRENT.read().unwrap_or_else(|p| p.into_inner())
}

/// Makes `palette` the app's look.
pub fn apply(ctx: &egui::Context, palette: &Palette) {
    *CURRENT.write().unwrap_or_else(|p| p.into_inner()) = *palette;
    // The same style for egui's light and dark slots: the palette decides.
    let style = style(palette);
    ctx.set_style_of(egui::Theme::Dark, style.clone());
    ctx.set_style_of(egui::Theme::Light, style);
}

/// `a` moved towards `b` by `t` (0..=1).
pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}

pub fn style(p: &Palette) -> egui::Style {
    let mut style = egui::Style::default();
    let mut v = if p.dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    let radius = CornerRadius::same(6);

    v.panel_fill = p.bg;
    v.window_fill = p.panel;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(12);
    v.menu_corner_radius = CornerRadius::same(10);
    let shadow = Color32::from_black_alpha(if p.dark { 120 } else { 36 });
    v.window_shadow = Shadow { offset: [0, 8], blur: 28, spread: 0, color: shadow };
    v.popup_shadow = Shadow { offset: [0, 4], blur: 16, spread: 0, color: shadow };
    // Table stripes sit on cards (panel color).
    v.faint_bg_color = mix(p.panel, p.text, if p.dark { 0.025 } else { 0.022 });
    v.extreme_bg_color = p.surface;
    v.text_edit_bg_color = Some(p.surface);
    v.code_bg_color = p.surface;
    v.hyperlink_color = p.accent;
    v.warn_fg_color = p.accent;
    v.error_fg_color = p.bad;
    v.weak_text_color = Some(p.weak);
    v.selection.bg_fill = p.accent;
    v.selection.stroke = Stroke::new(1.0, p.on_accent);

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.panel;
    w.noninteractive.weak_bg_fill = p.panel;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.inactive.bg_fill = p.surface;
    w.inactive.weak_bg_fill = p.surface;
    w.inactive.bg_stroke = Stroke::NONE;
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    let hover = mix(p.surface, p.text, 0.08);
    w.hovered.bg_fill = hover;
    w.hovered.weak_bg_fill = hover;
    w.hovered.bg_stroke = Stroke::new(1.0, mix(p.border, p.accent, 0.5));
    w.hovered.fg_stroke = Stroke::new(1.5, p.text);
    w.hovered.expansion = 0.0;
    let press = mix(p.surface, p.accent, 0.25);
    w.active.bg_fill = press;
    w.active.weak_bg_fill = press;
    w.active.bg_stroke = Stroke::new(1.0, p.accent);
    w.active.fg_stroke = Stroke::new(1.5, p.text);
    w.active.expansion = 0.0;
    w.open = w.hovered;
    for wv in [&mut w.noninteractive, &mut w.inactive, &mut w.hovered, &mut w.active, &mut w.open] {
        wv.corner_radius = radius;
    }
    style.visuals = v;

    let s = &mut style.spacing;
    s.item_spacing = egui::vec2(8.0, 6.0);
    s.button_padding = egui::vec2(10.0, 4.0);
    s.window_margin = Margin::same(14);
    s.menu_margin = Margin::same(8);
    s.interact_size.y = 22.0;

    style.text_styles = [
        (TextStyle::Heading, FontId::new(20.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(11.0, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
    ]
    .into();
    style
}

/// A rounded card on the panel color, for grouping content.
pub fn card() -> egui::Frame {
    let p = current();
    egui::Frame::new()
        .fill(p.panel)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(12))
}

/// A small rounded label, tinted with `color`.
pub fn pill(ui: &mut egui::Ui, text: impl Into<String>, color: Color32, dot: bool) -> egui::Response {
    let p = current();
    egui::Frame::new()
        .fill(mix(p.panel, color, if p.dark { 0.16 } else { 0.12 }))
        .stroke(Stroke::new(1.0, mix(p.panel, color, 0.45)))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(10, 3))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            if dot {
                let (r, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 3.5, color);
            }
            ui.label(egui::RichText::new(text.into()).color(color).strong());
        })
        .response
}

/// Paints a theme's colors as a row of dots, for the theme menu.
pub fn swatch(ui: &mut egui::Ui, p: &Palette) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(58.0, 16.0), egui::Sense::hover());
    ui.painter().rect(rect, 8.0, p.bg, Stroke::new(1.0, p.border), egui::StrokeKind::Inside);
    for (i, c) in [p.accent, p.down, p.up].iter().enumerate() {
        ui.painter().circle_filled(
            egui::pos2(rect.left() + 12.0 + i as f32 * 17.0, rect.center().y),
            4.5,
            *c,
        );
    }
}

/// The saved theme choice (`"system"` if none).
pub fn load() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item("nattowok-theme").ok().flatten())
            .unwrap_or_else(|| SYSTEM.into())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        crate::notify::config_dir()
            .and_then(|d| std::fs::read_to_string(d.join("theme")).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| SYSTEM.into())
    }
}

/// Remembers the theme choice.
pub fn save(choice: &str) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let storage = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .ok_or("the browser has no local storage")?;
        storage.set_item("nattowok-theme", choice).map_err(|e| format!("saving the theme: {e:?}"))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let dir = crate::notify::config_dir().ok_or("no configuration directory")?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("theme"), choice).map_err(|e| format!("saving the theme: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WCAG relative luminance contrast between two colors.
    fn contrast(a: Color32, b: Color32) -> f32 {
        let lum = |c: Color32| {
            let ch = |v: u8| {
                let v = v as f32 / 255.0;
                if v <= 0.03928 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * ch(c.r()) + 0.7152 * ch(c.g()) + 0.0722 * ch(c.b())
        };
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn themes_are_readable() {
        for p in THEMES {
            assert!(contrast(p.text, p.bg) >= 7.0, "{}: body text", p.id);
            assert!(contrast(p.text, p.panel) >= 7.0, "{}: text on cards", p.id);
            assert!(contrast(p.weak, p.panel) >= 3.0, "{}: secondary text", p.id);
            assert!(contrast(p.on_accent, p.accent) >= 3.0, "{}: text on accent buttons", p.id);
            for (what, c) in [("download", p.down), ("upload", p.up), ("ok", p.ok), ("bad", p.bad)] {
                assert!(contrast(c, p.panel) >= 3.0, "{}: {what} color on cards", p.id);
            }
        }
        let ids: std::collections::HashSet<_> = THEMES.iter().map(|p| p.id).collect();
        assert_eq!(ids.len(), THEMES.len());
        assert!(!ids.contains(SYSTEM));
    }

    #[test]
    fn system_follows_light_and_dark() {
        assert_eq!(resolve(SYSTEM, true), NATTO);
        assert_eq!(resolve(SYSTEM, false), DAYLIGHT);
        assert_eq!(resolve("midnight", false), MIDNIGHT);
        assert_eq!(resolve("no-such-theme", true), NATTO);
        assert_eq!(mix(Color32::BLACK, Color32::WHITE, 0.5), Color32::from_rgb(128, 128, 128));
    }
}
