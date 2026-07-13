//! A small JSON-RPC 2.0 endpoint (plain HTTP + JSON) that exposes read-only
//! statistics for a website. Deliberately minimal and safe:
//!   - bearer-token authenticated (constant-time compare), token required;
//!   - read-only — only `stats.*` methods, no way to mutate any state;
//!   - method-allowlisted (unknown methods get a JSON-RPC error, not a panic);
//!   - a tight request-body limit;
//!   - meant to bind to localhost, alongside the website backend.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use crate::config::JsonRpc as JsonRpcCfg;
use crate::engine::Engine;

type Shared = Arc<Mutex<Engine>>;

#[derive(Clone)]
struct AppState {
    engine: Shared,
    token: String,
}

// Start the endpoint, if configured. Absent [jsonrpc] in config.toml = no-op.
pub async fn run(engine: Shared, cfg: JsonRpcCfg) {
    let addr: SocketAddr = match cfg.bind.parse() {
        Ok(a) => a,
        Err(e) => return tracing::error!(%e, bind = %cfg.bind, "bad jsonrpc bind address"),
    };
    if cfg.token.is_empty() {
        return tracing::error!("jsonrpc token is empty; refusing to start an unauthenticated stats endpoint");
    }
    let state = AppState { engine, token: cfg.token };
    let app = Router::new()
        .route("/", post(handle))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => return tracing::error!(%e, %addr, "jsonrpc bind failed"),
    };
    tracing::info!(%addr, "jsonrpc stats API listening");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(%e, "jsonrpc server exited");
    }
}

async fn handle(State(state): State<AppState>, headers: HeaderMap, body: Json<Value>) -> (StatusCode, Json<Value>) {
    if !authorized(&headers, &state.token) {
        return (StatusCode::UNAUTHORIZED, Json(error(&Value::Null, -32001, "unauthorized")));
    }
    let req = body.0;
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return (StatusCode::OK, Json(error(&id, -32600, "invalid request: no method")));
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let result = match method {
        // stats.get -> { "<key>": <count>, … } (counters + live gauges).
        "stats.get" => Ok(json!(state.engine.lock().await.stats_snapshot())),
        // stats.channel { channel } -> { channel, lines, top: [{nick, lines}] }.
        "stats.channel" => match params.get("channel").and_then(Value::as_str) {
            Some(chan) => {
                let (lines, top) = state.engine.lock().await.channel_activity(chan).unwrap_or((0, Vec::new()));
                let top: Vec<Value> = top.into_iter().map(|(nick, n)| json!({ "nick": nick, "lines": n })).collect();
                Ok(json!({ "channel": chan, "lines": lines, "top": top }))
            }
            None => Err((-32602, "params.channel is required")),
        },
        _ => Err((-32601, "method not found")),
    };

    match result {
        Ok(value) => (StatusCode::OK, Json(json!({ "jsonrpc": "2.0", "result": value, "id": id }))),
        Err((code, message)) => (StatusCode::OK, Json(error(&id, code, message))),
    }
}

// Constant-time bearer check (length compared first — token length isn't secret).
fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let Some(header) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    let (a, b) = (presented.as_bytes(), token.as_bytes());
    a.len() == b.len() && a.ct_eq(b).into()
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "error": { "code": code, "message": message }, "id": id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::db::Db;

    fn engine_with_stat(tag: &str) -> Shared {
        let path = std::env::temp_dir().join(format!("fedserv-jsonrpc-{tag}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let mut e = Engine::new(vec![], Db::open(&path, "42S"));
        e.bump("botserv.messages");
        Arc::new(Mutex::new(e))
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {token}").parse().unwrap());
        h
    }

    #[tokio::test]
    async fn requires_token_then_returns_counters() {
        let state = AppState { engine: engine_with_stat("auth"), token: "secret".into() };
        // No/wrong token -> 401, no data.
        let (status, _) = handle(State(state.clone()), HeaderMap::new(), Json(json!({"method": "stats.get", "id": 1}))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = handle(State(state.clone()), bearer("wrong"), Json(json!({"method": "stats.get", "id": 1}))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Correct token -> the counters and gauges.
        let (status, Json(resp)) = handle(State(state), bearer("secret"), Json(json!({"jsonrpc": "2.0", "method": "stats.get", "id": 7}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["result"]["botserv.messages"], 1);
        assert!(resp["result"]["accounts.total"].is_number(), "gauge present: {resp}");
        assert_eq!(resp["id"], 7);
    }

    #[tokio::test]
    async fn unknown_method_is_a_jsonrpc_error() {
        let state = AppState { engine: engine_with_stat("badmethod"), token: "secret".into() };
        let (status, Json(resp)) = handle(State(state), bearer("secret"), Json(json!({"method": "drop.everything", "id": 2}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["error"]["code"], -32601);
    }
}
