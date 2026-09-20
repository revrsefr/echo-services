//! A small JSON-RPC 2.0 endpoint (plain HTTP + JSON) that exposes read-only
//! statistics for a website. Deliberately minimal and safe:
//!   - bearer-token authenticated (constant-time compare), token required;
//!   - read-only — only `stats.*` methods, no way to mutate any state;
//!   - method-allowlisted (unknown methods get a JSON-RPC error, not a panic);
//!   - a tight request-body limit;
//!   - meant to bind to localhost, alongside the website backend.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
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
    origins: Arc<Vec<String>>,
}

// A well-formed SCRAM-256 verifier used only to keep the `auth.login` response
// time constant when the account doesn't exist, so timing can't reveal whether
// an account is registered. Built once, off any real credential.
fn dummy_verifier() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        crate::engine::scram::make_verifier(
            crate::engine::scram::Hash::Sha256,
            "\0unused\0",
            1_200_000,
        )
    })
}

// Start the endpoint, if configured. Absent [jsonrpc] in config.toml = no-op.
pub async fn run(engine: Shared, cfg: JsonRpcCfg) {
    let addr: SocketAddr = match cfg.bind.parse() {
        Ok(a) => a,
        Err(e) => return tracing::error!(%e, bind = %cfg.bind, "bad jsonrpc bind address"),
    };
    if cfg.token.is_empty() {
        return tracing::error!(
            "jsonrpc token is empty; refusing to start an unauthenticated stats endpoint"
        );
    }
    let tls = cfg.tls.clone();
    let state = AppState {
        engine,
        token: cfg.token,
        origins: Arc::new(cfg.origins),
    };
    let app = Router::new()
        .route("/", post(handle).options(preflight))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);

    match tls {
        // TLS terminated here → HTTP/2 (ALPN) plus HTTP/1.1, encrypted to echo.
        Some(t) => {
            // The dependency tree carries more than one rustls crypto provider, so
            // pin one before building any TLS config (ignored if already set).
            let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
            let config =
                match axum_server::tls_rustls::RustlsConfig::from_pem_file(&t.cert, &t.key).await {
                    Ok(c) => c,
                    Err(e) => return tracing::error!(%e, "jsonrpc TLS cert/key unreadable"),
                };
            tracing::info!(%addr, "jsonrpc stats API listening (TLS, HTTP/2)");
            if let Err(e) = axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service())
                .await
            {
                tracing::error!(%e, "jsonrpc server exited");
            }
        }
        // Plain HTTP, for when a reverse proxy terminates TLS/HTTP-2/HTTP-3.
        None => {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => return tracing::error!(%e, %addr, "jsonrpc bind failed"),
            };
            tracing::info!(%addr, "jsonrpc stats API listening");
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(%e, "jsonrpc server exited");
            }
        }
    }
}

// Preflight (OPTIONS): tell the browser this origin may POST with an
// Authorization header. Only origins on the allowlist are answered.
async fn preflight(State(state): State<AppState>, headers: HeaderMap) -> (StatusCode, HeaderMap) {
    let mut out = cors_headers(&headers, &state.origins);
    out.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("POST, OPTIONS"),
    );
    out.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("authorization, content-type"),
    );
    out.insert("access-control-max-age", HeaderValue::from_static("86400"));
    (StatusCode::NO_CONTENT, out)
}

async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Json<Value>,
) -> (StatusCode, HeaderMap, Json<Value>) {
    let cors = cors_headers(&headers, &state.origins);
    if !authorized(&headers, &state.token) {
        return (
            StatusCode::UNAUTHORIZED,
            cors,
            Json(error(&Value::Null, -32001, "unauthorized")),
        );
    }
    let req = body.0;
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return (
            StatusCode::OK,
            cors,
            Json(error(&id, -32600, "invalid request: no method")),
        );
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let result = match method {
        // stats.get -> { "<key>": <count>, … } (counters + live gauges).
        "stats.get" => Ok(json!(state.engine.lock().await.stats_snapshot())),
        // stats.channel { channel } -> { channel, lines, top: [{nick, lines}] }.
        "stats.channel" => match params.get("channel").and_then(Value::as_str) {
            Some(chan) => {
                let (lines, top) = state
                    .engine
                    .lock()
                    .await
                    .channel_activity(chan)
                    .unwrap_or((0, Vec::new()));
                let top: Vec<Value> = top
                    .into_iter()
                    .map(|(nick, n)| json!({ "nick": nick, "lines": n }))
                    .collect();
                Ok(json!({ "channel": chan, "lines": lines, "top": top }))
            }
            None => Err((-32602, "params.channel is required")),
        },
        // auth.login { account, password } -> { ok, account, staff }. Verifies the
        // plaintext password against the account's SCRAM-256 verifier (the PBKDF2
        // runs off the engine lock). `staff` = the account holds an oper privilege.
        // Bearer-token gated; the website backend is the only caller. Never logs
        // the password; unknown accounts run a dummy verify (constant timing).
        "auth.login" => {
            let account = params
                .get("account")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            let password = params
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if account.is_empty() || password.is_empty() {
                Err((-32602, "params.account and params.password are required"))
            } else {
                let looked = state.engine.lock().await.web_auth_lookup(&account);
                let (canon, verifier, staff) = match looked {
                    Some(t) => t,
                    None => (String::new(), dummy_verifier().to_string(), false),
                };
                let known = !canon.is_empty();
                let ok = tokio::task::spawn_blocking(move || {
                    crate::engine::scram::verify_plain(
                        crate::engine::scram::Hash::Sha256,
                        &verifier,
                        &password,
                    )
                })
                .await
                .unwrap_or(false)
                    && known;
                Ok(json!({
                    "ok": ok,
                    "account": if ok { canon.as_str() } else { "" },
                    "staff": ok && staff,
                }))
            }
        }
        _ => Err((-32601, "method not found")),
    };

    match result {
        Ok(value) => (
            StatusCode::OK,
            cors,
            Json(json!({ "jsonrpc": "2.0", "result": value, "id": id })),
        ),
        Err((code, message)) => (StatusCode::OK, cors, Json(error(&id, code, message))),
    }
}

// CORS headers for a request: echo the Origin only if it's on the allowlist
// (never `*`), and always Vary on Origin so caches don't cross origins.
fn cors_headers(headers: &HeaderMap, origins: &[String]) -> HeaderMap {
    let mut out = HeaderMap::new();
    out.insert("vary", HeaderValue::from_static("Origin"));
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    if let Some(o) = origin {
        if origins.iter().any(|a| a == o) {
            if let Ok(v) = HeaderValue::from_str(o) {
                out.insert("access-control-allow-origin", v);
            }
        }
    }
    out
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
        let path = std::env::temp_dir().join(format!("echo-jsonrpc-{tag}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let mut e = Engine::new(vec![], Db::open(&path, "42S"));
        e.bump("botserv.messages");
        Arc::new(Mutex::new(e))
    }

    fn state(tag: &str, origins: Vec<String>) -> AppState {
        AppState {
            engine: engine_with_stat(tag),
            token: "secret".into(),
            origins: Arc::new(origins),
        }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {token}").parse().unwrap());
        h
    }

    #[tokio::test]
    async fn requires_token_then_returns_counters() {
        let st = state("auth", vec![]);
        // No/wrong token -> 401, no data.
        let (status, _, _) = handle(
            State(st.clone()),
            HeaderMap::new(),
            Json(json!({"method": "stats.get", "id": 1})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = handle(
            State(st.clone()),
            bearer("wrong"),
            Json(json!({"method": "stats.get", "id": 1})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Correct token -> the counters and gauges.
        let (status, _, Json(resp)) = handle(
            State(st),
            bearer("secret"),
            Json(json!({"jsonrpc": "2.0", "method": "stats.get", "id": 7})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["result"]["botserv.messages"], 1);
        assert!(
            resp["result"]["accounts.total"].is_number(),
            "gauge present: {resp}"
        );
        assert_eq!(resp["id"], 7);
    }

    #[tokio::test]
    async fn unknown_method_is_a_jsonrpc_error() {
        let (status, _, Json(resp)) = handle(
            State(state("badmethod", vec![])),
            bearer("secret"),
            Json(json!({"method": "drop.everything", "id": 2})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn cors_echoes_only_allowlisted_origins() {
        let st = state("cors", vec!["https://tchatou.fr".into()]);
        let mut allowed = bearer("secret");
        allowed.insert("origin", "https://tchatou.fr".parse().unwrap());
        let (_, headers, _) = handle(
            State(st.clone()),
            allowed,
            Json(json!({"method": "stats.get", "id": 1})),
        )
        .await;
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://tchatou.fr"
        );
        // A site not on the list gets no allow-origin header (browser blocks it).
        let mut evil = bearer("secret");
        evil.insert("origin", "https://evil.example".parse().unwrap());
        let (_, headers, _) = handle(
            State(st),
            evil,
            Json(json!({"method": "stats.get", "id": 1})),
        )
        .await;
        assert!(
            headers.get("access-control-allow-origin").is_none(),
            "unlisted origin not echoed"
        );
    }

    #[tokio::test]
    async fn auth_login_verifies_password() {
        let path = std::env::temp_dir().join("echo-jsonrpc-authlogin.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register("Bob", "hunter2", None).expect("register");
        let st = AppState {
            engine: Arc::new(Mutex::new(Engine::new(vec![], db))),
            token: "secret".into(),
            origins: Arc::new(vec![]),
        };
        // correct password -> ok, canonical casing, not staff
        let (_, _, Json(r)) = handle(State(st.clone()), bearer("secret"),
            Json(json!({"method":"auth.login","params":{"account":"bob","password":"hunter2"},"id":1}))).await;
        assert_eq!(r["result"]["ok"], true, "{r}");
        assert_eq!(r["result"]["account"], "Bob");
        assert_eq!(r["result"]["staff"], false);
        // wrong password -> not ok, no account leaked
        let (_, _, Json(r)) = handle(
            State(st.clone()),
            bearer("secret"),
            Json(
                json!({"method":"auth.login","params":{"account":"bob","password":"nope"},"id":2}),
            ),
        )
        .await;
        assert_eq!(r["result"]["ok"], false, "{r}");
        assert_eq!(r["result"]["account"], "");
        // unknown account -> not ok
        let (_, _, Json(r)) = handle(
            State(st),
            bearer("secret"),
            Json(json!({"method":"auth.login","params":{"account":"ghost","password":"x"},"id":3})),
        )
        .await;
        assert_eq!(r["result"]["ok"], false, "{r}");
    }
}
