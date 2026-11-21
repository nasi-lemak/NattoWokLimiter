//! Background polling of the daemon, so the UI never waits on the network.
//! The UI reads [`Data`] and sends [`Request`]s. On the desktop the poller is
//! a thread; in the browser it is a task on the page's event loop.

use crate::client::Client;
use nwl_core::api::{AppView, ConnView, Event, HistoryView, Overview, RemoteView, Status, UsageDay};
use nwl_core::history::Range;
use nwl_core::model::AppId;
use nwl_core::rules::Rule;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use web_time::Instant;

pub const HISTORY: usize = 120;
pub const SPARK: usize = 60;

#[derive(Default)]
pub struct Data {
    /// Which events become desktop notifications.
    pub notify: crate::notify::Settings,
    /// Only events after this id are notified: the history that existed when
    /// the app connected is not replayed. `None` until the first poll.
    notify_after: Option<u64>,
    /// The last error from the notification service, if any.
    pub notify_error: Option<String>,
    pub connected: bool,
    pub error: Option<String>,
    pub status: Option<Status>,
    pub overview: Option<Overview>,
    /// System-wide `(up, down)` samples, oldest first.
    pub system: VecDeque<(u64, u64)>,
    pub app_history: HashMap<AppId, VecDeque<(u64, u64)>>,
    pub rules: Vec<Rule>,
    pub connections: Vec<ConnView>,
    /// Newest first.
    pub events: Vec<Event>,
    pub usage: Vec<UsageDay>,
    pub usage_days: usize,
    /// Remote hosts of the app whose details are open.
    pub remotes: Vec<RemoteView>,
    pub remotes_app: Option<AppId>,
    /// The history view the History tab shows, and what it asked for.
    pub history: Option<HistoryView>,
    pub history_query: Option<(Range, Option<AppId>)>,
    /// Result of the last action, shown as a toast.
    pub toast: Option<(String, bool, Instant)>,
    /// Outcome of the last rule-form submission, for the form to pick up.
    pub rule_form_result: Option<Result<(), String>>,
    /// The "Undo" for the toast shown at that instant.
    pub toast_undo: Option<(Instant, Call)>,
    /// App icons fetched from the daemon: `(uri, bytes)` for egui's image
    /// loaders; `None` if fetching failed (not retried).
    pub icons: HashMap<AppId, Option<Icon>>,
    /// A file dropped on the window: its name and text (read asynchronously
    /// in the browser).
    pub dropped_file: Option<(String, Result<String, String>)>,
    last_mono: u64,
    last_event: u64,
    primed: bool,
}

impl Data {
    /// Empty state with the user's saved notification settings.
    pub fn new() -> Self {
        Self { notify: crate::notify::Settings::load(), ..Self::default() }
    }

    pub fn apps(&self) -> &[AppView] {
        self.overview.as_ref().map_or(&[], |o| &o.apps)
    }

    pub fn rule(&self, id: Option<u64>) -> Option<&Rule> {
        id.and_then(|id| self.rules.iter().find(|r| r.id == id))
    }

    fn push(history: &mut VecDeque<(u64, u64)>, sample: (u64, u64), cap: usize) {
        history.push_back(sample);
        while history.len() > cap {
            history.pop_front();
        }
    }
}

/// What the UI wants refreshed besides the overview.
pub enum Request {
    Usage(usize),
    /// Track the remote hosts of this app (or stop).
    Remotes(Option<AppId>),
    /// Fetch (and keep refreshing) this history view, or stop.
    History(Option<(Range, Option<AppId>)>),
    /// Run an API call, then refresh.
    Call(Call),
}

/// An API call made for the user, with what to say when it worked.
#[derive(Clone)]
pub struct Call {
    pub method: &'static str,
    pub path: String,
    pub body: Option<Value>,
    pub done: String,
    /// The rule form waits for this call's outcome (errors show in the form).
    pub rule_form: bool,
    /// What reverses this call, offered as "Undo" once it worked.
    pub undo: Option<Box<Call>>,
}

impl Call {
    pub fn new(
        method: &'static str,
        path: impl Into<String>,
        body: Option<Value>,
        done: impl Into<String>,
    ) -> Self {
        Self { method, path: path.into(), body, done: done.into(), rule_form: false, undo: None }
    }
}

pub type Shared = Arc<Mutex<Data>>;

/// An app icon: an image URI for egui's loaders, and the file's bytes.
pub type Icon = (String, Arc<[u8]>);

pub fn lock(data: &Shared) -> std::sync::MutexGuard<'_, Data> {
    data.lock().unwrap_or_else(|p| p.into_inner())
}

/// Carries out a notification button: the app's rules as they are now
/// decide the request, so a second click never stacks a duplicate rule.
#[cfg(not(target_arch = "wasm32"))]
fn run_action(client: &Client, data: &Shared, app: AppId, name: String, action: crate::actions::QuickAction) {
    let target = lock(data)
        .apps()
        .iter()
        .find(|a| a.app == app)
        .map(crate::actions::Target::from)
        .unwrap_or(crate::actions::Target { app, name, block_rule: None, limit_rule: None });
    let Some(r) = crate::actions::request(&target, &action) else { return };
    pollster::block_on(run_call(client, data, Call::new(r.method, r.path, r.body, r.done)));
}

async fn run_call(client: &Client, data: &Shared, call: Call) {
    let result = client.call(call.method, &call.path, call.body).await;
    let mut d = lock(data);
    let now = Instant::now();
    match &result {
        Ok(_) => {
            d.toast = Some((call.done, true, now));
            d.toast_undo = call.undo.map(|undo| (now, *undo));
        }
        Err(e) if !call.rule_form => d.toast = Some((e.clone(), false, now)),
        Err(_) => {}
    }
    if call.rule_form {
        d.rule_form_result = Some(result.map(|_| ()));
    }
}

/// Applies a request; whether to poll right away is up to the caller.
async fn handle(client: &Client, data: &Shared, request: Request, timers: &mut Timers) {
    match request {
        Request::Usage(days) => {
            lock(data).usage_days = days;
            timers.usage_due = Instant::now();
        }
        Request::Remotes(app) => {
            let mut d = lock(data);
            d.remotes.clear();
            d.remotes_app = app;
        }
        Request::History(query) => {
            let mut d = lock(data);
            d.history = None;
            d.history_query = query;
            timers.history_due = Instant::now();
        }
        Request::Call(call) => run_call(client, data, call).await,
    }
}

/// When the slower views are next refreshed.
struct Timers {
    usage_due: Instant,
    history_due: Instant,
}

impl Timers {
    fn new() -> Self {
        Self { usage_due: Instant::now(), history_due: Instant::now() }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_poller(
    client: Client,
    data: Shared,
    repaint: impl Fn() + Send + 'static,
) -> mpsc::Sender<Request> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("poller".into())
        .spawn(move || {
            let mut timers = Timers::new();
            loop {
                // The native client blocks, so these futures complete in one poll.
                pollster::block_on(poll(&client, &data, &mut timers));
                repaint();
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(request) => pollster::block_on(handle(&client, &data, request, &mut timers)),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
        })
        .expect("spawn poller thread");
    tx
}

#[cfg(target_arch = "wasm32")]
pub fn spawn_poller(client: Client, data: Shared, repaint: impl Fn() + 'static) -> mpsc::Sender<Request> {
    let (tx, rx) = mpsc::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let mut timers = Timers::new();
        loop {
            poll(&client, &data, &mut timers).await;
            repaint();
            // Wait for the next second, or less if the UI asks for something.
            let next = Instant::now() + Duration::from_secs(1);
            while Instant::now() < next {
                match rx.try_recv() {
                    Ok(request) => {
                        handle(&client, &data, request, &mut timers).await;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => crate::client::sleep(50).await,
                    Err(mpsc::TryRecvError::Disconnected) => return,
                }
            }
        }
    });
    tx
}

async fn poll(client: &Client, data: &Shared, timers: &mut Timers) {
    let overview: Overview = match client.get("/api/overview").await {
        Ok(o) => o,
        Err(e) => {
            let mut d = lock(data);
            d.connected = false;
            d.error = Some(e);
            return;
        }
    };
    let primed = lock(data).primed;
    // History endpoints are only needed once, to fill the graphs on start.
    let initial = if primed {
        None
    } else {
        let system: Vec<(u64, u64)> = client.get("/api/system/history").await.unwrap_or_default();
        let apps: Vec<AppView> = client.get("/api/apps").await.unwrap_or_default();
        Some((system, apps))
    };
    let status: Option<Status> = client.get("/api/status").await.ok();
    let rules: Option<Vec<Rule>> = client.get("/api/rules").await.ok();
    let connections: Option<Vec<ConnView>> = client.get("/api/connections").await.ok();
    let last_event = lock(data).last_event;
    let events: Vec<Event> = if overview.last_event > last_event {
        client.get(&format!("/api/events?after={last_event}")).await.unwrap_or_default()
    } else {
        vec![]
    };
    let remotes_app = lock(data).remotes_app.clone();
    let remotes: Option<Vec<RemoteView>> = match &remotes_app {
        Some(app) => {
            client.get(&format!("/api/remotes?limit=20&app={}", crate::client::encode(&app.0))).await.ok()
        }
        None => None,
    };
    // History changes slowly (minute buckets): refresh every 10 s.
    let history_query = lock(data).history_query.clone();
    let history: Option<HistoryView> = match &history_query {
        Some((range, app)) if Instant::now() >= timers.history_due => {
            timers.history_due = Instant::now() + Duration::from_secs(10);
            let range = serde_json::to_value(range)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();
            let mut path = format!("/api/history?range={range}");
            if let Some(a) = app {
                path += &format!("&app={}", crate::client::encode(&a.0));
            }
            client.get(&path).await.ok()
        }
        _ => None,
    };
    let usage_days = lock(data).usage_days.max(7);
    let usage: Option<Vec<UsageDay>> = if Instant::now() >= timers.usage_due {
        timers.usage_due = Instant::now() + Duration::from_secs(10);
        client.get(&format!("/api/usage?days={usage_days}")).await.ok()
    } else {
        None
    };

    let (notifications, missing) = {
        let mut d = lock(data);
        d.connected = true;
        d.error = None;
        if let Some((system, apps)) = initial {
            d.system = system.into_iter().rev().take(HISTORY).rev().collect();
            for a in apps {
                let h: VecDeque<_> = a.history.iter().copied().rev().take(SPARK).rev().collect();
                d.app_history.insert(a.app, h);
            }
            d.primed = true;
        } else if overview.mono_ms != d.last_mono {
            let sample = (overview.system.rate_up, overview.system.rate_down);
            Data::push(&mut d.system, sample, HISTORY);
            for a in &overview.apps {
                let h = d.app_history.entry(a.app.clone()).or_default();
                Data::push(h, (a.rate_up, a.rate_down), SPARK);
            }
        }
        d.last_mono = overview.mono_ms;
        let live: std::collections::HashSet<&AppId> = overview.apps.iter().map(|a| &a.app).collect();
        d.app_history.retain(|k, _| live.contains(k));
        let notify_after = *d.notify_after.get_or_insert(overview.last_event);
        let mut notifications = Vec::new();
        for e in events {
            if e.id > notify_after && d.notify.wants(&e.kind) {
                if let Some((title, body)) = crate::notify::text(&e.kind) {
                    notifications.push((title, body, crate::notify::buttons(&e.kind)));
                }
            }
            d.last_event = d.last_event.max(e.id);
            d.events.insert(0, e);
        }
        d.events.truncate(500);
        if let Some(s) = status {
            d.status = Some(s);
        }
        if let Some(r) = rules {
            d.rules = r;
        }
        if let Some(c) = connections {
            d.connections = c;
        }
        if let Some(u) = usage {
            d.usage = u;
        }
        // Ignore a response for an app that is no longer selected.
        if let Some(r) = remotes.filter(|_| d.remotes_app == remotes_app) {
            d.remotes = r;
        }
        if let Some(h) = history.filter(|_| d.history_query == history_query) {
            d.history = Some(h);
        }
        // Apps whose icon to fetch, a few per tick.
        let missing: Vec<AppId> = overview
            .apps
            .iter()
            .filter(|a| a.icon && !d.icons.contains_key(&a.app))
            .map(|a| a.app.clone())
            .take(4)
            .collect();
        d.overview = Some(overview);
        (notifications, missing)
    };
    // Shown outside the lock: talking to the notification service can take
    // a moment and the UI must not wait for it.
    #[cfg(not(target_arch = "wasm32"))]
    for (title, body, buttons) in notifications {
        let result = match buttons {
            Some((app, name, buttons)) => {
                let (client, data) = (client.clone(), data.clone());
                crate::notify::show_with_buttons(&title, &body, buttons, move |action| {
                    run_action(&client, &data, app, name, action)
                })
            }
            None => crate::notify::show(&title, &body),
        };
        lock(data).notify_error = result.err();
    }
    // The browser shows no notifications (the setting is off there).
    #[cfg(target_arch = "wasm32")]
    drop(notifications);
    // Icons of apps that have one, a few per tick.
    for app in missing {
        let icon =
            client.get_bytes(&format!("/api/icon?app={}", crate::client::encode(&app.0))).await.ok().map(
                |(bytes, kind)| {
                    let ext = if kind.contains("svg") { "svg" } else { "png" };
                    let uri = format!("bytes://nwl-icon/{}.{ext}", crate::client::encode(&app.0));
                    (uri, Arc::from(bytes))
                },
            );
        lock(data).icons.insert(app, icon);
    }
}
