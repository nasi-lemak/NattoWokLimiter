//! HTTP API and the embedded web dashboard.
//!
//! The API controls a firewall, so it only listens on loopback and defends
//! against browsers being used against it:
//! * the `Host` header must name a loopback host (defeats DNS rebinding);
//! * state-changing requests must carry an `X-NWL-Client` header, which a
//!   cross-origin page cannot add without a CORS preflight we never approve
//!   (defeats CSRF).

use crate::engine::Engine;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use nwl_core::rules::{Rule, RuleError};
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

const INDEX: &str = include_str!("../assets/index.html");
pub const CLIENT_HEADER: &str = "x-nwl-client";

/// Messages from the API to the engine thread.
#[derive(Debug, PartialEq, Eq)]
pub enum Wake {
    /// Rules changed: re-apply enforcement now instead of at the next tick.
    Reapply,
    Shutdown,
}

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Mutex<Engine>>,
    pub updates: broadcast::Sender<Arc<str>>,
    pub wake: mpsc::Sender<Wake>,
    pub started: Instant,
    /// Flips to `true` on shutdown so long-lived streams end and graceful
    /// shutdown can complete.
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { Html(INDEX) }))
        .route("/api/status", get(status))
        .route("/api/overview", get(overview))
        .route("/api/apps", get(apps))
        .route("/api/connections", get(connections))
        .route("/api/system/history", get(system_history))
        .route("/api/rules", get(list_rules).post(add_rule))
        .route("/api/rules/:id", put(replace_rule).delete(remove_rule))
        .route("/api/rules/:id/move", post(move_rule))
        .route("/api/quotas", get(quotas))
        .route("/api/events", get(events))
        .route("/api/usage", get(usage))
        .route("/api/stream", get(stream))
        .layer(middleware::from_fn(guard))
        .with_state(state)
}

fn is_loopback_host(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
}

async fn guard(req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    if !is_loopback_host(host) {
        return error(StatusCode::FORBIDDEN, "requests must address localhost");
    }
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe && !req.headers().contains_key(CLIENT_HEADER) {
        return error(StatusCode::FORBIDDEN, "missing X-NWL-Client header");
    }
    next.run(req).await
}

fn error(code: StatusCode, message: &str) -> Response {
    (code, Json(json!({ "error": message }))).into_response()
}

fn rule_error(e: RuleError) -> Response {
    let code = match e {
        RuleError::NotFound(_) => StatusCode::NOT_FOUND,
        RuleError::Invalid { .. } => StatusCode::UNPROCESSABLE_ENTITY,
    };
    error(code, &e.to_string())
}

impl AppState {
    fn engine(&self) -> std::sync::MutexGuard<'_, Engine> {
        self.engine.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn reapply(&self) {
        let _ = self.wake.send(Wake::Reapply);
    }
}

async fn status(State(s): State<AppState>) -> impl IntoResponse {
    let e = s.engine();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": s.started.elapsed().as_secs(),
        "enforcement": e.status,
    }))
}

async fn overview(State(s): State<AppState>) -> impl IntoResponse {
    Json(s.engine().overview())
}

async fn apps(State(s): State<AppState>) -> impl IntoResponse {
    Json(s.engine().apps())
}

#[derive(Deserialize)]
struct ConnQuery {
    app: Option<String>,
}

async fn connections(State(s): State<AppState>, Query(q): Query<ConnQuery>) -> impl IntoResponse {
    Json(s.engine().connections(q.app.as_deref()))
}

async fn system_history(State(s): State<AppState>) -> impl IntoResponse {
    Json(s.engine().system_history())
}

async fn list_rules(State(s): State<AppState>) -> impl IntoResponse {
    Json(s.engine().rules.rules.clone())
}

async fn add_rule(State(s): State<AppState>, Json(rule): Json<Rule>) -> Response {
    let result = s.engine().add_rule(rule);
    match result {
        Ok(id) => {
            s.reapply();
            let rule = s.engine().rules.get(id).cloned();
            (StatusCode::CREATED, Json(rule)).into_response()
        }
        Err(e) => rule_error(e),
    }
}

async fn replace_rule(State(s): State<AppState>, Path(id): Path<u64>, Json(rule): Json<Rule>) -> Response {
    let result = s.engine().replace_rule(id, rule);
    match result {
        Ok(()) => {
            s.reapply();
            Json(s.engine().rules.get(id).cloned()).into_response()
        }
        Err(e) => rule_error(e),
    }
}

async fn remove_rule(State(s): State<AppState>, Path(id): Path<u64>) -> Response {
    let result = s.engine().remove_rule(id);
    match result {
        Ok(rule) => {
            s.reapply();
            Json(rule).into_response()
        }
        Err(e) => rule_error(e),
    }
}

#[derive(Deserialize)]
struct MoveBody {
    index: usize,
}

async fn move_rule(State(s): State<AppState>, Path(id): Path<u64>, Json(body): Json<MoveBody>) -> Response {
    let result = s.engine().move_rule(id, body.index);
    match result {
        Ok(()) => {
            s.reapply();
            Json(s.engine().rules.rules.clone()).into_response()
        }
        Err(e) => rule_error(e),
    }
}

async fn quotas(State(s): State<AppState>) -> impl IntoResponse {
    Json(s.engine().quota_status())
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    after: u64,
}

async fn events(State(s): State<AppState>, Query(q): Query<EventsQuery>) -> impl IntoResponse {
    Json(s.engine().events_since(q.after))
}

#[derive(Deserialize)]
struct UsageQuery {
    days: Option<usize>,
}

async fn usage(State(s): State<AppState>, Query(q): Query<UsageQuery>) -> impl IntoResponse {
    Json(s.engine().usage(q.days.unwrap_or(30).clamp(1, 400)))
}

/// Server-sent events: one `overview` event per tick.
async fn stream(State(s): State<AppState>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = s.updates.subscribe();
    let mut shutdown = s.shutdown.clone();
    let events = BroadcastStream::new(rx)
        .filter_map(|msg| msg.ok().map(|json| Ok(Event::default().event("overview").data(&*json))));
    let events = futures_util::StreamExt::take_until(events, async move {
        let _ = shutdown.wait_for(|stop| *stop).await;
    });
    Sse::new(events).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> (Router, mpsc::Receiver<Wake>) {
        let dir = std::env::temp_dir().join(format!(
            "nwld-api-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let engine = Engine::new(Store::open(dir).unwrap(), 10).unwrap();
        let (wake, rx) = mpsc::channel();
        let state = AppState {
            engine: Arc::new(Mutex::new(engine)),
            updates: broadcast::channel(4).0,
            wake,
            started: Instant::now(),
            shutdown: tokio::sync::watch::channel(false).1,
        };
        (router(state), rx)
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        host: &str,
        client: bool,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", host)
            .header("content-type", "application/json");
        if client {
            req = req.header(CLIENT_HEADER, "test");
        }
        let resp = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    #[test]
    fn loopback_hosts() {
        for ok in ["localhost", "localhost:7657", "127.0.0.1:1", "[::1]:7657", "[::1]"] {
            assert!(is_loopback_host(ok), "{ok}");
        }
        for bad in ["evil.com", "127.0.0.1.evil.com:80", "", "[::2]:1", "localhost.evil:1"] {
            assert!(!is_loopback_host(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn guards_and_rule_crud() {
        let (app, wake) = app();
        let (code, _) = call(&app, "GET", "/api/rules", "attacker.example", false, "").await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        let rule = r#"{"name":"block curl","match":{"app":"curl"},"action":{"type":"block"}}"#;
        let (code, _) = call(&app, "POST", "/api/rules", "localhost:7657", false, rule).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "CSRF header required");

        let (code, body) = call(&app, "POST", "/api/rules", "localhost:7657", true, rule).await;
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(body["id"], 1);
        assert_eq!(wake.try_recv(), Ok(Wake::Reapply));

        let bad = r#"{"action":{"type":"limit"}}"#;
        let (code, body) = call(&app, "POST", "/api/rules", "localhost", true, bad).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].as_str().unwrap().contains("limit"));

        let replaced =
            r#"{"name":"slow curl","match":{"app":"curl"},"action":{"type":"limit","upload":"1MB/s"}}"#;
        let (code, body) = call(&app, "PUT", "/api/rules/1", "localhost", true, replaced).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["action"]["upload"], 1_000_000);

        let (_, list) = call(&app, "GET", "/api/rules", "127.0.0.1", false, "").await;
        assert_eq!(list.as_array().unwrap().len(), 1);
        let (code, _) = call(&app, "DELETE", "/api/rules/1", "localhost", true, "").await;
        assert_eq!(code, StatusCode::OK);
        let (code, _) = call(&app, "DELETE", "/api/rules/1", "localhost", true, "").await;
        assert_eq!(code, StatusCode::NOT_FOUND);

        let (_, events) = call(&app, "GET", "/api/events", "localhost", false, "").await;
        assert_eq!(events.as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn serves_dashboard() {
        let (app, _) = app();
        let resp = app
            .oneshot(Request::builder().uri("/").header("host", "localhost").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
