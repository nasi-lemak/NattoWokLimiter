//! System tray icon: a live speed meter with a small menu.
//!
//! The icon is drawn every second: a round badge with two bars, download on
//! the left and upload on the right, on a logarithmic scale (1 kB/s to
//! 100 MB/s). Paused rules show as a grey badge with a pause sign. Hovering
//! shows the exact rates; the menu opens the window, blocks or limits the
//! busiest apps, pauses or resumes all rules, switches notifications and
//! quits. The menu is described once ([`TrayState::menu`]) and each backend
//! renders that description.
//!
//! Linux uses the StatusNotifierItem D-Bus protocol (KDE, GNOME with the
//! AppIndicator extension, XFCE, Cinnamon, ...) through `ksni`, pure Rust
//! with no GTK. Windows and macOS use their native trays through `tray-icon`.

use crate::actions::{QuickAction, Target, LIMIT_PRESETS};
use nwl_core::rate::format_bytes;
use std::sync::mpsc::{self, Receiver, Sender};

/// Apps offered in the tray menu.
pub const MENU_APPS: usize = 6;

/// An application in the tray menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayApp {
    pub target: Target,
    pub down: u64,
    pub up: u64,
    /// The current one-click limit (download and upload), bytes/s.
    pub limit: Option<u64>,
    /// Its quota, e.g. "1.20 GB of 5.00 GB today".
    pub quota: Option<String>,
}

/// What the tray shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrayState {
    pub connected: bool,
    /// `Some(paused)` when rules can be paused (the daemon enforces).
    pub paused: Option<bool>,
    pub down: u64,
    pub up: u64,
    pub notifications: bool,
    /// The busiest apps, at most [`MENU_APPS`].
    pub apps: Vec<TrayApp>,
}

/// What the user asked for from the tray.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayCommand {
    /// Show the window (or hide it, if it is showing).
    ToggleWindow,
    SetPaused(bool),
    SetNotifications(bool),
    App(Target, QuickAction),
    Quit,
}

/// A platform-neutral menu entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// Text that changes every second (rates); not clickable.
    Info(String),
    Separator,
    Action {
        label: String,
        enabled: bool,
        command: TrayCommand,
    },
    Check {
        label: String,
        checked: bool,
        command: TrayCommand,
    },
    Sub {
        label: String,
        children: Vec<Entry>,
    },
}

impl Entry {
    fn action(label: impl Into<String>, command: TrayCommand) -> Self {
        Entry::Action { label: label.into(), enabled: true, command }
    }
}

fn rate(n: u64) -> String {
    if n == 0 {
        "0 B/s".into()
    } else {
        format!("{}/s", format_bytes(n))
    }
}

impl TrayState {
    pub fn summary(&self) -> String {
        if !self.connected {
            return "Not connected to nwld".into();
        }
        let mut s = format!("↓ {}   ↑ {}", rate(self.down), rate(self.up));
        if self.paused == Some(true) {
            s += "   (rules paused)";
        }
        s
    }

    /// The whole menu.
    pub fn menu(&self) -> Vec<Entry> {
        let mut menu = vec![Entry::Info(self.summary()), Entry::Separator];
        menu.push(Entry::action("Open NattoWok Limiter", TrayCommand::ToggleWindow));
        if !self.apps.is_empty() {
            menu.push(Entry::Sub {
                label: "Apps".into(),
                children: self.apps.iter().map(app_menu).collect(),
            });
        }
        menu.push(Entry::Action {
            label: self.pause_label().into(),
            enabled: self.paused.is_some(),
            command: TrayCommand::SetPaused(self.paused != Some(true)),
        });
        menu.push(Entry::Check {
            label: "Notifications".into(),
            checked: self.notifications,
            command: TrayCommand::SetNotifications(!self.notifications),
        });
        menu.push(Entry::Separator);
        menu.push(Entry::action("Quit", TrayCommand::Quit));
        menu
    }

    fn pause_label(&self) -> &'static str {
        if self.paused == Some(true) {
            "Resume all rules"
        } else {
            "Pause all rules"
        }
    }
}

/// The submenu of one app: its rates, block/unblock and limit presets.
fn app_menu(a: &TrayApp) -> Entry {
    let t = &a.target;
    let cmd = |action| TrayCommand::App(t.clone(), action);
    let mut label = t.name.clone();
    if t.block_rule.is_some() {
        label += " (blocked)";
    } else if let Some(l) = a.limit {
        label += &format!(" (limited to {})", rate(l));
    }
    let mut children = vec![Entry::Info(format!("↓ {}   ↑ {}", rate(a.down), rate(a.up)))];
    if let Some(quota) = &a.quota {
        children.push(Entry::Info(format!("Quota: {quota}")));
    }
    children.push(Entry::Separator);
    children.push(match t.block_rule {
        Some(_) => Entry::action("Unblock", cmd(QuickAction::Unblock)),
        None => Entry::action("Block", cmd(QuickAction::Block)),
    });
    children.push(Entry::Separator);
    for preset in LIMIT_PRESETS {
        children.push(Entry::Check {
            label: format!("Limit to {}", rate(preset)),
            checked: a.limit == Some(preset),
            command: cmd(QuickAction::Limit(preset)),
        });
    }
    children.push(Entry::Action {
        label: "Remove limit".into(),
        enabled: t.limit_rule.is_some(),
        command: cmd(QuickAction::RemoveLimit),
    });
    Entry::Sub { label, children }
}

/// Bar height (0..=1) for a rate, logarithmic from 1 kB/s to 100 MB/s.
fn level(rate: u64) -> f32 {
    if rate == 0 {
        return 0.0;
    }
    (((rate as f32).log10() - 3.0) / 5.0).clamp(0.08, 1.0)
}

/// Renders the icon as RGBA pixels, `size` x `size`.
pub fn render_icon(size: u32, state: &TrayState) -> Vec<u8> {
    let s = size as f32;
    let (badge, bar_down, bar_up): ([u8; 3], [u8; 3], [u8; 3]) =
        if !state.connected || state.paused == Some(true) {
            ([120, 116, 110], [235, 235, 235], [235, 235, 235])
        } else {
            ([217, 119, 6], [255, 255, 255], [255, 228, 196])
        };
    let mut px = vec![0u8; (size * size * 4) as usize];
    let (cx, cy, r) = (s / 2.0, s / 2.0, s / 2.0 - 0.5);
    let bar_w = (s * 0.18).max(2.0);
    let gap = (s * 0.1).max(1.0);
    let (bottom, top) = (s * 0.78, s * 0.22);
    let paused = state.paused == Some(true) && state.connected;
    let heights = if paused {
        (1.0, 1.0)
    } else if state.connected {
        (level(state.down), level(state.up))
    } else {
        (0.0, 0.0)
    };
    for y in 0..size {
        for x in 0..size {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            // Badge with a one-pixel soft edge.
            let d = ((fx - cx).powi(2) + (fy - cy).powi(2)).sqrt();
            let alpha = (r - d + 0.5).clamp(0.0, 1.0);
            if alpha <= 0.0 {
                continue;
            }
            let mut color = badge;
            for (i, (h, c)) in [(heights.0, bar_down), (heights.1, bar_up)].into_iter().enumerate() {
                let left = if i == 0 { cx - gap / 2.0 - bar_w } else { cx + gap / 2.0 };
                // Any traffic gets at least two pixels, visible at 22 px.
                let bar_h = if h > 0.0 { ((bottom - top) * h).max(2.0) } else { 0.0 };
                let bar_top = bottom - bar_h;
                if h > 0.0 && fx >= left && fx < left + bar_w && fy >= bar_top && fy < bottom {
                    color = c;
                }
            }
            let i = ((y * size + x) * 4) as usize;
            px[i..i + 3].copy_from_slice(&color);
            px[i + 3] = (alpha * 255.0) as u8;
        }
    }
    px
}

/// A running tray icon, or nothing where none could be created.
pub struct Tray {
    backend: backend::Backend,
    commands: Receiver<TrayCommand>,
    last: Option<TrayState>,
}

impl Tray {
    /// Creates the tray icon. `wake` is called whenever the user acts on it,
    /// so the app can handle the command even while its window is hidden.
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Option<Tray> {
        let (tx, rx) = mpsc::channel();
        let backend = backend::Backend::new(tx, Box::new(wake))?;
        Some(Tray { backend, commands: rx, last: None })
    }

    /// Whether a tray host is showing the icon right now, i.e. whether the
    /// window can be hidden to the tray without the app becoming unreachable.
    pub fn visible(&self) -> bool {
        self.backend.visible()
    }

    pub fn update(&mut self, state: TrayState) {
        if self.last.as_ref() != Some(&state) {
            self.backend.update(&state);
            self.last = Some(state);
        }
    }

    pub fn commands(&self) -> Vec<TrayCommand> {
        self.commands.try_iter().collect()
    }
}

#[cfg(target_os = "linux")]
mod backend {
    use super::*;
    use ksni::blocking::TrayMethods;
    use ksni::menu::{CheckmarkItem, MenuItem, StandardItem, SubMenu};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    type Wake = Box<dyn Fn() + Send + Sync>;

    pub struct Item {
        state: TrayState,
        commands: Sender<TrayCommand>,
        wake: Arc<Wake>,
        online: Arc<AtomicBool>,
    }

    impl Item {
        fn send(&self, command: TrayCommand) {
            let _ = self.commands.send(command);
            (self.wake)();
        }
    }

    fn to_ksni(entry: Entry) -> MenuItem<Item> {
        match entry {
            Entry::Info(label) => StandardItem { label, enabled: false, ..Default::default() }.into(),
            Entry::Separator => MenuItem::Separator,
            Entry::Action { label, enabled, command } => StandardItem {
                label,
                enabled,
                activate: Box::new(move |t: &mut Item| t.send(command.clone())),
                ..Default::default()
            }
            .into(),
            Entry::Check { label, checked, command } => CheckmarkItem {
                label,
                checked,
                activate: Box::new(move |t: &mut Item| t.send(command.clone())),
                ..Default::default()
            }
            .into(),
            Entry::Sub { label, children } => {
                SubMenu { label, submenu: children.into_iter().map(to_ksni).collect(), ..Default::default() }
                    .into()
            }
        }
    }

    /// ksni wants ARGB32 in network byte order.
    fn argb(size: u32, state: &TrayState) -> ksni::Icon {
        let mut data = render_icon(size, state);
        for px in data.chunks_exact_mut(4) {
            px.rotate_right(1); // RGBA -> ARGB
        }
        ksni::Icon { width: size as i32, height: size as i32, data }
    }

    impl ksni::Tray for Item {
        fn id(&self) -> String {
            "nattowok".into()
        }
        fn title(&self) -> String {
            "NattoWok Limiter".into()
        }
        fn category(&self) -> ksni::Category {
            ksni::Category::ApplicationStatus
        }
        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            [22, 32, 48].into_iter().map(|s| argb(s, &self.state)).collect()
        }
        fn tool_tip(&self) -> ksni::ToolTip {
            ksni::ToolTip {
                title: "NattoWok Limiter".into(),
                description: self.state.summary(),
                ..Default::default()
            }
        }
        fn activate(&mut self, _x: i32, _y: i32) {
            self.send(TrayCommand::ToggleWindow);
        }
        fn menu(&self) -> Vec<MenuItem<Self>> {
            self.state.menu().into_iter().map(to_ksni).collect()
        }
        fn watcher_online(&self) {
            self.online.store(true, Ordering::Relaxed);
        }
        fn watcher_offline(&self, _reason: ksni::OfflineReason) -> bool {
            // No tray host (e.g. GNOME without the AppIndicator extension):
            // keep the item on the bus so it appears if a host starts later.
            self.online.store(false, Ordering::Relaxed);
            true
        }
    }

    pub struct Backend {
        handle: ksni::blocking::Handle<Item>,
        online: Arc<AtomicBool>,
    }

    impl Backend {
        pub fn new(commands: Sender<TrayCommand>, wake: Wake) -> Option<Self> {
            let online = Arc::new(AtomicBool::new(true));
            let item =
                Item { state: TrayState::default(), commands, wake: Arc::new(wake), online: online.clone() };
            match item.spawn() {
                Ok(handle) => Some(Self { handle, online }),
                Err(e) => {
                    eprintln!("tray icon unavailable: {e}");
                    None
                }
            }
        }

        pub fn visible(&self) -> bool {
            self.online.load(Ordering::Relaxed) && !self.handle.is_closed()
        }

        pub fn update(&self, state: &TrayState) {
            let state = state.clone();
            self.handle.update(move |item| item.state = state);
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod backend {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tray_icon::menu::{
        CheckMenuItem, IsMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu,
    };
    use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

    type Wake = Box<dyn Fn() + Send + Sync>;
    type Commands = Arc<Mutex<HashMap<MenuId, TrayCommand>>>;

    pub struct Backend {
        icon: TrayIcon,
        /// Which command each clickable item sends.
        commands: Commands,
        /// The menu as last built, with info texts blanked: rebuilt only when
        /// this changes, so an open menu is not replaced every second.
        structure: Option<Vec<Entry>>,
        /// Info items, in menu order, updated in place.
        info: Vec<MenuItem>,
    }

    fn icon(state: &TrayState) -> Option<tray_icon::Icon> {
        tray_icon::Icon::from_rgba(render_icon(32, state), 32, 32).ok()
    }

    /// The menu without its changing texts.
    fn structure(entries: &[Entry]) -> Vec<Entry> {
        entries
            .iter()
            .map(|e| match e {
                Entry::Info(_) => Entry::Info(String::new()),
                Entry::Sub { label, children } => {
                    Entry::Sub { label: label.clone(), children: structure(children) }
                }
                other => other.clone(),
            })
            .collect()
    }

    fn infos(entries: &[Entry], out: &mut Vec<String>) {
        for e in entries {
            match e {
                Entry::Info(text) => out.push(text.clone()),
                Entry::Sub { children, .. } => infos(children, out),
                _ => {}
            }
        }
    }

    /// Builds native items, recording commands and info items.
    fn build(
        entries: &[Entry],
        commands: &mut HashMap<MenuId, TrayCommand>,
        info: &mut Vec<MenuItem>,
    ) -> Vec<Box<dyn IsMenuItem>> {
        entries
            .iter()
            .map(|e| -> Box<dyn IsMenuItem> {
                match e {
                    Entry::Info(text) => {
                        let item = MenuItem::new(text, false, None);
                        info.push(item.clone());
                        Box::new(item)
                    }
                    Entry::Separator => Box::new(PredefinedMenuItem::separator()),
                    Entry::Action { label, enabled, command } => {
                        let item = MenuItem::new(label, *enabled, None);
                        commands.insert(item.id().clone(), command.clone());
                        Box::new(item)
                    }
                    Entry::Check { label, checked, command } => {
                        let item = CheckMenuItem::new(label, true, *checked, None);
                        commands.insert(item.id().clone(), command.clone());
                        Box::new(item)
                    }
                    Entry::Sub { label, children } => {
                        let sub = Submenu::new(label, true);
                        for child in build(children, commands, info) {
                            let _ = sub.append(child.as_ref());
                        }
                        Box::new(sub)
                    }
                }
            })
            .collect()
    }

    impl Backend {
        /// Must run on the main thread, inside the running event loop.
        pub fn new(sender: Sender<TrayCommand>, wake: Wake) -> Option<Self> {
            let icon = TrayIconBuilder::new()
                .with_menu_on_left_click(false)
                .with_tooltip("NattoWok Limiter")
                .with_icon(icon(&TrayState::default())?)
                .build()
                .map_err(|e| eprintln!("tray icon unavailable: {e}"))
                .ok()?;
            let commands: Commands = Arc::default();
            let wake = Arc::new(wake);
            let (map, tx, w) = (commands.clone(), sender.clone(), wake.clone());
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                let command = map.lock().unwrap_or_else(|p| p.into_inner()).get(&event.id).cloned();
                if let Some(c) = command {
                    let _ = tx.send(c);
                    w();
                }
            }));
            TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    let _ = sender.send(TrayCommand::ToggleWindow);
                    wake();
                }
            }));
            let mut backend = Self { icon, commands, structure: None, info: Vec::new() };
            backend.update(&TrayState::default());
            Some(backend)
        }

        pub fn visible(&self) -> bool {
            true
        }

        pub fn update(&mut self, state: &TrayState) {
            let _ = self.icon.set_icon(icon(state));
            let _ = self.icon.set_tooltip(Some(format!("NattoWok Limiter\n{}", state.summary())));
            let entries = state.menu();
            let shape = structure(&entries);
            if self.structure.as_ref() != Some(&shape) {
                let mut commands = HashMap::new();
                let mut info = Vec::new();
                let menu = Menu::new();
                for item in build(&entries, &mut commands, &mut info) {
                    let _ = menu.append(item.as_ref());
                }
                *self.commands.lock().unwrap_or_else(|p| p.into_inner()) = commands;
                self.info = info;
                self.icon.set_menu(Some(Box::new(menu)));
                self.structure = Some(shape);
            } else {
                let mut texts = Vec::new();
                infos(&entries, &mut texts);
                for (item, text) in self.info.iter().zip(texts) {
                    item.set_text(text);
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
mod backend {
    use super::*;

    pub struct Backend;

    impl Backend {
        pub fn new(_: Sender<TrayCommand>, _: Box<dyn Fn() + Send + Sync>) -> Option<Self> {
            None
        }
        pub fn visible(&self) -> bool {
            false
        }
        pub fn update(&self, _: &TrayState) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(px: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * size + x) * 4) as usize;
        px[i..i + 4].try_into().unwrap()
    }

    #[test]
    fn meter_bars_follow_rates() {
        let size = 32;
        let busy = TrayState {
            connected: true,
            paused: Some(false),
            down: 50_000_000,
            up: 2_000,
            ..Default::default()
        };
        let px = render_icon(size, &busy);
        assert_eq!(pixel(&px, size, 0, 0)[3], 0, "corners are transparent");
        // Upper part of the download bar is lit (fast), the upload bar there is not (slow).
        let (down_x, up_x, y) = (13, 18, 10);
        assert_eq!(&pixel(&px, size, down_x, y)[..3], &[255, 255, 255]);
        assert_eq!(&pixel(&px, size, up_x, y)[..3], &[217, 119, 6]);
        // Near the bottom both bars are lit.
        assert_eq!(&pixel(&px, size, up_x, 23)[..3], &[255, 228, 196]);

        let paused = TrayState { paused: Some(true), ..busy.clone() };
        assert_eq!(
            &pixel(&render_icon(size, &paused), size, 16, 4)[..3],
            &[120, 116, 110],
            "grey when paused"
        );
    }

    #[test]
    fn levels_and_text() {
        assert_eq!(level(0), 0.0);
        assert!(level(1_000) > 0.0 && level(1_000) < 0.1);
        assert_eq!(level(1_000_000_000), 1.0);
        assert!(level(1_000_000) > level(100_000));
        let s = TrayState {
            connected: true,
            paused: Some(true),
            down: 2_300_000,
            up: 140_000,
            notifications: true,
            apps: vec![],
        };
        assert_eq!(s.summary(), "↓ 2.30 MB/s   ↑ 140.00 kB/s   (rules paused)");
        assert_eq!(s.pause_label(), "Resume all rules");
        assert_eq!(TrayState::default().summary(), "Not connected to nwld");
    }

    #[test]
    fn menu_offers_actions_per_app() {
        use nwl_core::model::AppId;
        let app = |name: &str, block: Option<u64>, limit: Option<u64>| TrayApp {
            target: Target {
                app: AppId(format!("/usr/bin/{name}")),
                name: name.into(),
                block_rule: block,
                limit_rule: limit,
            },
            down: 1_000_000,
            up: 0,
            limit: limit.map(|_| 1_000_000),
            quota: None,
        };
        let state = TrayState {
            connected: true,
            paused: Some(false),
            apps: vec![app("curl", None, None), app("steam", Some(3), None), app("rclone", None, Some(4))],
            ..Default::default()
        };
        let menu = state.menu();
        let Some(Entry::Sub { children: apps, .. }) =
            menu.iter().find(|e| matches!(e, Entry::Sub { label, .. } if label == "Apps"))
        else {
            panic!("no Apps submenu: {menu:?}")
        };
        let labels: Vec<&str> = apps
            .iter()
            .map(|e| match e {
                Entry::Sub { label, .. } => label.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(labels, ["curl", "steam (blocked)", "rclone (limited to 1.00 MB/s)"]);
        let Entry::Sub { children, .. } = &apps[1] else { unreachable!() };
        assert!(children.iter().any(|e| matches!(e, Entry::Action { label, command: TrayCommand::App(_, QuickAction::Unblock), .. } if label == "Unblock")));
        let Entry::Sub { children, .. } = &apps[2] else { unreachable!() };
        let checked: Vec<&str> = children
            .iter()
            .filter_map(|e| match e {
                Entry::Check { label, checked: true, .. } => Some(label.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(checked, ["Limit to 1.00 MB/s"], "the current limit is ticked");
        assert!(children
            .iter()
            .any(|e| matches!(e, Entry::Action { label, enabled: true, .. } if label == "Remove limit")));
        assert!(matches!(
            menu.iter().find(|e| matches!(e, Entry::Action { label, .. } if label == "Pause all rules")),
            Some(Entry::Action { command: TrayCommand::SetPaused(true), .. })
        ));
    }
}
