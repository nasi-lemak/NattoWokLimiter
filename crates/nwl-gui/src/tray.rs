//! System tray icon: a live speed meter with a small menu.
//!
//! The icon is drawn every second: a round badge with two bars, download on
//! the left and upload on the right, on a logarithmic scale (1 kB/s to
//! 100 MB/s). Paused rules show as a grey badge with a pause sign. Hovering
//! shows the exact rates; the menu opens the window, pauses or resumes all
//! rules, switches notifications and quits.
//!
//! Linux uses the StatusNotifierItem D-Bus protocol (KDE, GNOME with the
//! AppIndicator extension, XFCE, Cinnamon, ...) through `ksni`, pure Rust
//! with no GTK. Windows and macOS use their native trays through `tray-icon`.

use nwl_core::rate::format_bytes;
use std::sync::mpsc::{self, Receiver, Sender};

/// What the tray shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrayState {
    pub connected: bool,
    /// `Some(paused)` when rules can be paused (the daemon enforces).
    pub paused: Option<bool>,
    pub down: u64,
    pub up: u64,
    pub notifications: bool,
}

/// What the user asked for from the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    /// Show the window (or hide it, if it is showing).
    ToggleWindow,
    SetPaused(bool),
    SetNotifications(bool),
    Quit,
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

    fn pause_label(&self) -> &'static str {
        if self.paused == Some(true) {
            "Resume all rules"
        } else {
            "Pause all rules"
        }
    }
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
    use ksni::menu::{CheckmarkItem, MenuItem, StandardItem};
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
            let paused = self.state.paused;
            vec![
                StandardItem { label: self.state.summary(), enabled: false, ..Default::default() }.into(),
                MenuItem::Separator,
                StandardItem {
                    label: "Open NattoWok Limiter".into(),
                    activate: Box::new(|t: &mut Self| t.send(TrayCommand::ToggleWindow)),
                    ..Default::default()
                }
                .into(),
                StandardItem {
                    label: self.state.pause_label().into(),
                    enabled: paused.is_some(),
                    activate: Box::new(move |t: &mut Self| {
                        if let Some(p) = paused {
                            t.send(TrayCommand::SetPaused(!p));
                        }
                    }),
                    ..Default::default()
                }
                .into(),
                CheckmarkItem {
                    label: "Notifications".into(),
                    checked: self.state.notifications,
                    activate: Box::new(|t: &mut Self| {
                        let on = !t.state.notifications;
                        t.send(TrayCommand::SetNotifications(on));
                    }),
                    ..Default::default()
                }
                .into(),
                MenuItem::Separator,
                StandardItem {
                    label: "Quit".into(),
                    activate: Box::new(|t: &mut Self| t.send(TrayCommand::Quit)),
                    ..Default::default()
                }
                .into(),
            ]
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
    use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

    type Wake = Box<dyn Fn() + Send + Sync>;

    pub struct Backend {
        icon: TrayIcon,
        summary: MenuItem,
        pause: MenuItem,
        notifications: CheckMenuItem,
        state: std::sync::Arc<std::sync::Mutex<TrayState>>,
    }

    fn icon(state: &TrayState) -> Option<tray_icon::Icon> {
        tray_icon::Icon::from_rgba(render_icon(32, state), 32, 32).ok()
    }

    impl Backend {
        /// Must run on the main thread, inside the running event loop.
        pub fn new(commands: Sender<TrayCommand>, wake: Wake) -> Option<Self> {
            let state = std::sync::Arc::new(std::sync::Mutex::new(TrayState::default()));
            let summary = MenuItem::new("NattoWok Limiter", false, None);
            let open = MenuItem::new("Open NattoWok Limiter", true, None);
            let pause = MenuItem::new("Pause all rules", false, None);
            let notifications = CheckMenuItem::new("Notifications", true, true, None);
            let quit = MenuItem::new("Quit", true, None);
            let menu = Menu::new();
            let sep1 = PredefinedMenuItem::separator();
            let sep2 = PredefinedMenuItem::separator();
            for item in [
                &summary as &dyn tray_icon::menu::IsMenuItem,
                &sep1,
                &open,
                &pause,
                &notifications,
                &sep2,
                &quit,
            ] {
                menu.append(item).ok()?;
            }
            let icon = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_menu_on_left_click(false)
                .with_tooltip("NattoWok Limiter")
                .with_icon(icon(&TrayState::default())?)
                .build()
                .map_err(|e| eprintln!("tray icon unavailable: {e}"))
                .ok()?;

            let wake = std::sync::Arc::new(wake);
            let (ids, tx, w, st) = (
                (open.id().clone(), pause.id().clone(), notifications.id().clone(), quit.id().clone()),
                commands.clone(),
                wake.clone(),
                state.clone(),
            );
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                let s = st.lock().unwrap_or_else(|p| p.into_inner()).clone();
                let command = if event.id == ids.0 {
                    Some(TrayCommand::ToggleWindow)
                } else if event.id == ids.1 {
                    s.paused.map(|p| TrayCommand::SetPaused(!p))
                } else if event.id == ids.2 {
                    Some(TrayCommand::SetNotifications(!s.notifications))
                } else if event.id == ids.3 {
                    Some(TrayCommand::Quit)
                } else {
                    None
                };
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
                    let _ = commands.send(TrayCommand::ToggleWindow);
                    wake();
                }
            }));
            Some(Self { icon, summary, pause, notifications, state })
        }

        pub fn visible(&self) -> bool {
            true
        }

        pub fn update(&self, state: &TrayState) {
            *self.state.lock().unwrap_or_else(|p| p.into_inner()) = state.clone();
            let _ = self.icon.set_icon(icon(state));
            let _ = self.icon.set_tooltip(Some(format!("NattoWok Limiter\n{}", state.summary())));
            self.summary.set_text(state.summary());
            self.pause.set_text(state.pause_label());
            self.pause.set_enabled(state.paused.is_some());
            self.notifications.set_checked(state.notifications);
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
        };
        assert_eq!(s.summary(), "↓ 2.30 MB/s   ↑ 140.00 kB/s   (rules paused)");
        assert_eq!(s.pause_label(), "Resume all rules");
        assert_eq!(TrayState::default().summary(), "Not connected to nwld");
    }
}
