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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, FromRequestParts, Query, State};
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
        .route("/", get(dashboard))
        .route("/accounts", get(accounts))
        .route("/channels", get(channels))
        .route("/network", get(network))
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

async fn dashboard(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let (accounts, channels) = e.directory_snapshot();
    let opers = accounts.iter().filter(|a| e.account_privs(&a.name).any()).count();
    let akills = e.akills().len();
    let uptime = e.uptime_secs();
    let linked = e.linked();
    drop(e);

    let stat = |label: &str, value: String| {
        format!("<div class=\"stat\"><div class=\"stat-v\">{}</div><div class=\"stat-l\">{}</div></div>", esc(&value), esc(label))
    };
    let cards = format!(
        "<div class=\"stats\">{}{}{}{}</div>",
        stat("Accounts", accounts.len().to_string()),
        stat("Channels", channels.len().to_string()),
        stat("Operators", opers.to_string()),
        stat("Network bans", akills.to_string()),
    );
    let link = if linked { "<span class=\"ok\">linked</span>" } else { "<span class=\"warn\">not linked</span>" };
    let info = format!(
        "<div class=\"card\"><h2>Server</h2><table class=\"kv\">\
         <tr><td>Version</td><td>{v} ({rev})</td></tr>\
         <tr><td>Built</td><td>{built}</td></tr>\
         <tr><td>Uplink</td><td>{link}</td></tr>\
         <tr><td>Uptime</td><td>{up}</td></tr></table></div>",
        v = esc(crate::version::VERSION),
        rev = esc(&crate::version::revision()),
        built = esc(&crate::version::built()),
        link = link,
        up = esc(&fmt_dur(uptime)),
    );
    Html(shell(&st.brand, Some(&oper), "", &format!("<h1>Dashboard</h1>{cards}{info}")))
}

#[derive(Deserialize)]
struct AccountsQuery {
    #[serde(default)]
    q: String,
}

async fn accounts(oper: Oper, State(st): State<AppState>, Query(q): Query<AccountsQuery>) -> Html<String> {
    let needle = q.q.to_lowercase();
    let e = st.engine.lock().await;
    let (mut accts, _) = e.directory_snapshot();
    accts.retain(|a| needle.is_empty() || a.name.to_lowercase().contains(&needle));
    accts.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    let total = accts.len();
    let rows: String = accts
        .iter()
        .take(500)
        .map(|a| {
            let tier = e.account_privs(&a.name);
            let badges = format!(
                "{}{}{}",
                if a.verified { "" } else { "<span class=\"tag warn\">unverified</span>" },
                if a.suspension.is_some() { "<span class=\"tag bad\">suspended</span>" } else { "" },
                if tier.any() { format!("<span class=\"tag op\">{}</span>", esc(tier.tier())) } else { String::new() },
            );
            format!(
                "<tr><td><a href=\"/accounts?q={n}\">{n}</a></td><td>{email}</td><td>{seen}</td><td>{badges}</td></tr>",
                n = esc(&a.name),
                email = esc(a.email.as_deref().unwrap_or("")),
                seen = esc(&echo_api::human_time(a.last_seen)),
                badges = badges,
            )
        })
        .collect();
    drop(e);

    let capped = if total > 500 { format!(" (showing 500 of {total})") } else { String::new() };
    let body = format!(
        "<h1>Accounts</h1>\
         <form class=\"search\" method=\"get\" action=\"/accounts\"><input name=\"q\" value=\"{q}\" placeholder=\"Search accounts…\"><button>Search</button></form>\
         <div class=\"card\"><table class=\"list\"><thead><tr><th>Account</th><th>Email</th><th>Last seen</th><th></th></tr></thead><tbody>{rows}</tbody></table>\
         <p class=\"muted\">{count} accounts{capped}</p></div>",
        q = esc(&q.q),
        rows = rows,
        count = total,
        capped = capped,
    );
    Html(shell(&st.brand, Some(&oper), "accounts", &body))
}

async fn channels(oper: Oper, State(st): State<AppState>) -> Html<String> {
    Html(shell(&st.brand, Some(&oper), "channels", &soon("Channels")))
}

async fn network(oper: Oper, State(st): State<AppState>) -> Html<String> {
    Html(shell(&st.brand, Some(&oper), "network", &soon("Network")))
}

fn soon(title: &str) -> String {
    format!("<h1>{}</h1><div class=\"card\"><p class=\"muted\">Coming soon.</p></div>", esc(title))
}

fn fmt_dur(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}
