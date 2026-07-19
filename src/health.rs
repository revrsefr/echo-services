//! A tiny liveness + metrics endpoint (plain HTTP), for a monitor to watch a
//! live node. Deliberately minimal and safe:
//!   - read-only: only gauges/counters, no way to mutate any state;
//!   - unauthenticated by design (the data isn't secret) — so bind it to
//!     localhost and let a monitor/scraper reach it there;
//!   - two GET routes only: `/health` (JSON liveness) and `/metrics`
//!     (Prometheus text exposition).
//!
//! The gauges come straight from the engine: the stat counters, the live
//! account/channel/bot/oper totals, and the event-log position (seq / lamport /
//! entries) so a stalled or non-advancing log is visible to alerting.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::config::Health as HealthCfg;
use crate::engine::Engine;

type Shared = Arc<Mutex<Engine>>;

#[derive(Clone)]
struct AppState {
    engine: Shared,
    started: Instant,
}

// Start the endpoint, if configured. Absent [health] in config.toml = no-op.
pub async fn run(engine: Shared, cfg: HealthCfg) {
    let addr: SocketAddr = match cfg.bind.parse() {
        Ok(a) => a,
        Err(e) => return tracing::error!(%e, bind = %cfg.bind, "bad health bind address"),
    };
    let state = AppState { engine, started: Instant::now() };
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => return tracing::error!(%e, %addr, "health bind failed"),
    };
    tracing::info!(%addr, "health/metrics endpoint listening");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(%e, "health server exited");
    }
}

// Liveness probe: 200 + a compact JSON body. Reaching it at all means the tokio
// runtime is up and the engine lock is obtainable (not deadlocked).
async fn health(State(state): State<AppState>) -> Json<Value> {
    let gauges = state.engine.lock().await.health_metrics();
    Json(json!({
        "status": "ok",
        "uptime_s": state.started.elapsed().as_secs(),
        "gauges": gauges,
    }))
}

// Prometheus text exposition. Each gauge becomes `echo_<name> <value>`, with the
// dotted keys mapped to Prometheus-legal underscores (accounts.total ->
// echo_accounts_total). Plus a synthetic uptime gauge.
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let gauges = state.engine.lock().await.health_metrics();
    let mut body = String::with_capacity(64 * (gauges.len() + 1));
    body.push_str("# HELP echo_uptime_seconds Seconds since this node started.\n");
    body.push_str("# TYPE echo_uptime_seconds gauge\n");
    body.push_str(&format!("echo_uptime_seconds {}\n", state.started.elapsed().as_secs()));
    for (key, value) in &gauges {
        let metric = sanitize(key);
        body.push_str(&format!("# TYPE echo_{metric} gauge\n"));
        body.push_str(&format!("echo_{metric} {value}\n"));
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

// Map a gauge key to a Prometheus-legal metric name: anything not [a-z0-9_]
// becomes '_' (dots, dashes). Keys are ASCII service/stat names, so this is
// enough — no leading-digit case to worry about (all keys start with a letter).
fn sanitize(key: &str) -> String {
    key.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::db::Db;
    use axum::http::StatusCode;

    fn state(tag: &str) -> AppState {
        let path = std::env::temp_dir().join(format!("echo-health-{tag}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let mut e = Engine::new(vec![], Db::open(&path, "42S"));
        e.bump("botserv.messages");
        AppState { engine: Arc::new(Mutex::new(e)), started: Instant::now() }
    }

    #[tokio::test]
    async fn health_reports_ok_and_gauges() {
        let Json(body) = health(State(state("live"))).await;
        assert_eq!(body["status"], "ok");
        assert!(body["gauges"]["accounts.total"].is_number());
        assert!(body["gauges"]["event.lamport"].is_number(), "log position present: {body}");
    }

    #[tokio::test]
    async fn metrics_is_prometheus_text_with_sanitized_names() {
        let resp = metrics(State(state("metrics"))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        // Dotted keys are sanitized to underscores, counters are present, and the
        // synthetic uptime gauge is emitted.
        assert!(text.contains("echo_botserv_messages 1"), "counter: {text}");
        assert!(text.contains("echo_accounts_total "), "gauge: {text}");
        assert!(text.contains("echo_uptime_seconds "), "uptime: {text}");
        // No dotted metric NAME leaks through (HELP prose may contain periods, so
        // check only the sample lines, not the comments).
        let sample_lines: Vec<&str> = text.lines().filter(|l| l.starts_with("echo_")).collect();
        assert!(!sample_lines.is_empty());
        assert!(sample_lines.iter().all(|l| !l.split(' ').next().unwrap().contains('.')), "no dotted names: {text}");
    }
}
