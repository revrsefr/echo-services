//! Web admin panel — a self-contained HTTP admin site served by echo itself, so
//! any operator running echo gets it with no external stack (no database, no app
//! server). Enabled by `[panel] bind = "..."` in config.toml; put it behind a TLS
//! reverse proxy.
//!
//! Staff log in with their echo account and password (verified against the same
//! SCRAM store as IRC), and only services operators may enter. Every page and
//! action is gated by the account's live oper tier, re-checked on each request so
//! a revoked oper loses access immediately. Reads and writes go straight to the
//! engine under the shared lock, exactly like the gRPC and IRC paths.

mod tmpl;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use crate::config::Panel as PanelCfg;
use crate::engine::{scram, Engine};
use echo_api::Privs;

mod render;
use render::{esc, shell};

type Shared = Arc<Mutex<Engine>>;
type HmacSha256 = Hmac<Sha256>;

// How long a login stays valid.
const SESSION_TTL: u64 = 8 * 3600;

#[derive(Clone)]
struct AppState {
    engine: Shared,
    // Random per-process key that signs session cookies (sessions drop on restart).
    key: Arc<[u8; 32]>,
    brand: String,
}

// Start the panel, if configured. Absent [panel] in config.toml = no-op.
pub async fn run(engine: Shared, cfg: PanelCfg) {
    let addr: SocketAddr = match cfg.bind.parse() {
        Ok(a) => a,
        Err(e) => return tracing::error!(%e, bind = %cfg.bind, "bad panel bind address"),
    };
    let mut key = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut key);
    let brand = cfg.brand.clone().unwrap_or_else(|| "echo services".to_string());
    let state = AppState { engine, key: Arc::new(key), brand };

    let app = Router::new()
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", post(logout))
        .route("/static/*path", get(static_asset))
        .route("/", get(dashboard))
        .route("/users", get(page_users))
        .route("/users/:nick", get(page_user_detail))
        .route("/channels", get(page_channels))
        .route("/channels/:slug", get(page_channel_detail))
        .route("/servers", get(page_servers))
        .route("/servers/:name", get(page_server_detail))
        .route("/trends", get(page_trends))
        .route("/bans", get(page_bans))
        .route("/name-bans", get(page_name_bans))
        .route("/exceptions", get(page_exceptions))
        .route("/spamfilter", get(page_spamfilter))
        .route("/security-groups", get(page_security_groups))
        .route("/ip-whois", get(page_ip_whois))
        .route("/whowas", get(page_whowas))
        .route("/logs", get(page_logs))
        .route("/opers", get(page_opers))
        .route("/registrations", get(page_registrations))
        .route("/modules", get(page_modules))
        .route("/audit", get(page_audit))
        .route("/access", get(page_access))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => return tracing::error!(%e, %addr, "panel bind failed"),
    };
    tracing::info!(%addr, "web admin panel listening");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(%e, "panel server exited");
    }
}

// ---- sessions ------------------------------------------------------------

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// A signed token: base64(account|expiry) . base64(HMAC-SHA256).
fn sign_session(key: &[u8], account: &str) -> String {
    let payload = format!("{account}|{}", now() + SESSION_TTL);
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(payload.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("{}.{}", B64.encode(payload.as_bytes()), B64.encode(tag))
}

// Verify a session token: check the HMAC (constant time) and expiry, return the
// account. Any tampering, truncation, or expiry yields None.
fn verify_session(key: &[u8], token: &str) -> Option<String> {
    let (p_b64, t_b64) = token.split_once('.')?;
    let payload = B64.decode(p_b64).ok()?;
    let tag = B64.decode(t_b64).ok()?;
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(&payload);
    let expected = mac.finalize().into_bytes();
    if expected.as_slice().ct_eq(&tag).unwrap_u8() != 1 {
        return None;
    }
    let s = String::from_utf8(payload).ok()?;
    // Account names may contain '|', the expiry never does — split from the right.
    let (account, exp) = s.rsplit_once('|')?;
    if exp.parse::<u64>().ok()? < now() {
        return None;
    }
    Some(account.to_string())
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').map(str::trim).find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then_some(v)
    })
}

fn set_cookie(token: &str) -> String {
    format!("panel={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")
}

// The authenticated operator, extracted (and re-authorised) on every gated page.
struct Oper {
    account: String,
    privs: Privs,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for Oper {
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let deny = || Redirect::to("/login");
        let raw = parts.headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");
        let token = cookie_value(raw, "panel").ok_or_else(deny)?;
        let account = verify_session(state.key.as_slice(), token).ok_or_else(deny)?;
        // Re-read the live privileges so a de-opered account is locked out at once.
        let privs = state.engine.lock().await.account_privs(&account);
        if privs.any() {
            Ok(Oper { account, privs })
        } else {
            Err(deny())
        }
    }
}

// ---- auth pages ----------------------------------------------------------

#[derive(Deserialize)]
struct LoginForm {
    account: String,
    password: String,
}

fn login_page(st: &AppState, error: Option<&str>) -> Html<String> {
    let err = error
        .map(|e| format!("<div class=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        r#"<div class="login">
  <h1>{brand}</h1>
  <p class="sub">Services administration</p>
  {err}
  <form method="post" action="/login">
    <label>Account<input name="account" autocomplete="username" autofocus></label>
    <label>Password<input name="password" type="password" autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
  </form>
  <p class="hint">Sign in with your services account. Operators only.</p>
</div>"#,
        brand = esc(&st.brand),
        err = err,
    );
    Html(shell(&st.brand, None, "", &format!("<div class=\"login-wrap\">{body}</div>")))
}

async fn login_form(State(st): State<AppState>) -> Html<String> {
    login_page(&st, None)
}

async fn login_submit(State(st): State<AppState>, Form(f): Form<LoginForm>) -> Response {
    let bad = "Invalid account or password.";
    // Fetch the verifier under the lock, then run the ~1s PBKDF2 off-thread —
    // never hold the engine lock across it (it would freeze the whole daemon).
    let Some((account, verifier)) = st.engine.lock().await.authority_auth_begin(&f.account) else {
        return login_page(&st, Some(bad)).into_response();
    };
    let password = f.password.clone();
    let ok = tokio::task::spawn_blocking(move || {
        scram::verify_plain(scram::Hash::Sha256, &verifier, &password)
    })
    .await
    .unwrap_or(false);
    // Feed the same brute-force backoff as IDENTIFY.
    st.engine.lock().await.authority_note_auth(&f.account, ok);
    if !ok {
        return login_page(&st, Some(bad)).into_response();
    }
    if !st.engine.lock().await.account_privs(&account).any() {
        return login_page(&st, Some("That account isn't a services operator.")).into_response();
    }
    let mut resp = Redirect::to("/").into_response();
    let cookie = set_cookie(&sign_session(st.key.as_slice(), &account));
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).expect("ascii cookie"));
    resp
}

async fn logout() -> Response {
    let mut resp = Redirect::to("/login").into_response();
    let clear = "panel=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static(clear));
    resp
}

// ---- pages ---------------------------------------------------------------

async fn static_asset(Path(path): Path<String>) -> Response {
    match tmpl::asset(&path) {
        Some((bytes, ctype)) => (
            [
                (header::CONTENT_TYPE, ctype),
                (header::CACHE_CONTROL, "public, max-age=86400"),
            ],
            bytes,
        )
            .into_response(),
        None => (axum::http::StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

// The context every panel page shares: identity, nav highlight, csrf placeholder.
fn base_ctx(st: &AppState, oper: &Oper, active: &str) -> serde_json::Map<String, serde_json::Value> {
    let tier = oper.privs.tier();
    let obj = json!({
        "brand": st.brand,
        "active": active,
        "asset_version": crate::version::VERSION,
        "current_language": "fr",
        "panel_languages": [],
        "panel_perms": ["audit"],
        "is_root": tier == "root",
        "csrf_token": "",
        "request": { "user": { "username": oper.account }, "csp_nonce": "", "get_full_path": "/" },
    });
    match obj {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}

// Render `template` with the base context merged with `extra`, or an error page.
fn page(st: &AppState, oper: &Oper, active: &str, template: &str, extra: serde_json::Value) -> Html<String> {
    let mut ctx = base_ctx(st, oper, active);
    if let serde_json::Value::Object(m) = extra {
        ctx.extend(m);
    }
    let val = minijinja::Value::from_serialize(&serde_json::Value::Object(ctx));
    match tmpl::render(template, val) {
        Ok(html) => Html(html),
        Err(e) => Html(format!("<pre>panel template error in {template}:\n{e:#}</pre>")),
    }
}

// A read-only page with no page-specific data yet (data wired in progressively).
macro_rules! simple_page {
    ($fn:ident, $active:expr, $tpl:expr) => {
        async fn $fn(oper: Oper, State(st): State<AppState>) -> Html<String> {
            page(&st, &oper, $active, $tpl, json!({}))
        }
    };
}
simple_page!(page_users, "users", "ircpanel/users.html");
simple_page!(page_channels, "channels", "ircpanel/channels.html");
simple_page!(page_servers, "servers", "ircpanel/servers.html");
simple_page!(page_trends, "trends", "ircpanel/trends.html");
simple_page!(page_bans, "bans", "ircpanel/bans.html");
simple_page!(page_name_bans, "name_bans", "ircpanel/name_bans.html");
simple_page!(page_exceptions, "exceptions", "ircpanel/exceptions.html");
simple_page!(page_spamfilter, "spamfilter", "ircpanel/spamfilter.html");
simple_page!(page_security_groups, "security_groups", "ircpanel/security_groups.html");
simple_page!(page_ip_whois, "ip_whois", "ircpanel/ip_whois.html");
simple_page!(page_whowas, "whowas", "ircpanel/whowas.html");
simple_page!(page_logs, "logs", "ircpanel/logs.html");
simple_page!(page_opers, "opers", "ircpanel/opers.html");
simple_page!(page_registrations, "registrations", "ircpanel/registrations.html");
simple_page!(page_modules, "modules", "ircpanel/modules.html");
simple_page!(page_audit, "audit", "ircpanel/audit.html");
simple_page!(page_access, "access", "ircpanel/access.html");

async fn page_user_detail(oper: Oper, State(st): State<AppState>, Path(nick): Path<String>) -> Html<String> {
    page(&st, &oper, "users", "ircpanel/user_detail.html", json!({ "nick": nick }))
}
async fn page_channel_detail(oper: Oper, State(st): State<AppState>, Path(slug): Path<String>) -> Html<String> {
    page(&st, &oper, "channels", "ircpanel/channel_detail.html", json!({ "slug": slug }))
}
async fn page_server_detail(oper: Oper, State(st): State<AppState>, Path(name): Path<String>) -> Html<String> {
    page(&st, &oper, "servers", "ircpanel/server_detail.html", json!({ "name": name }))
}

async fn dashboard(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let (_accounts, channels) = e.directory_snapshot();
    let stats = e.stats_snapshot();
    let ban_count = e.akills().len();
    let linked = e.linked();
    drop(e);
    let g = |k: &str| stats.get(k).copied().unwrap_or(0);
    let ctx = json!({
        "stats": {
            "me": { "name": st.brand, "version": crate::version::VERSION },
            "user": { "total": g("users.online"), "local": g("users.local"), "oper": g("opers.total") },
            "channel": { "total": channels.len() },
            "server": { "total": if linked { g("servers.online").max(1) } else { 0 } },
        },
        "ban_count": ban_count,
        "servers": [],
        "top_channels": [],
        "recent_audit": [],
        "geo_rows": [],
        "geo_dots": [],
        "geo_total": 0,
        "geo_local": 0,
        "geo_max": 1,
        "sparks": {},
        "world_svg": "",
        "live_url": "/api/live",
    });
    page(&st, &oper, "dashboard", "ircpanel/dashboard.html", ctx)
}

