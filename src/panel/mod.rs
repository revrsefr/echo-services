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
        .route("/health", get(health))
        .route("/live", get(live))
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
//
// Every page is a compile-time askama template backed by a typed struct. All
// formatting/derivation happens here in Rust; the templates only interpolate.
// Data comes straight from echo's own engine (the live S2S network view plus the
// account/channel directory) under the shared lock — never from the ircd's RPC.

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

// Render any askama template into an HTML response, or a readable error page.
fn html<T: askama::Template>(t: T) -> Html<String> {
    match t.render() {
        Ok(s) => Html(s),
        Err(e) => Html(format!("<pre>panel template error:\n{e}</pre>")),
    }
}

fn is_root(oper: &Oper) -> bool {
    oper.privs.tier() == "root"
}

// ---- dashboard -----------------------------------------------------------

struct SrvRow {
    name: String,
    users: usize,
    pct: u64,
}
struct ChanRow {
    name: String,
    users: usize,
    pct: u64,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/dashboard.html")]
struct DashboardTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    users: usize,
    opers: usize,
    channels: usize,
    servers: usize,
    bans: usize,
    server_rows: Vec<SrvRow>,
    chan_rows: Vec<ChanRow>,
}

async fn dashboard(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let users = e.net_user_count();
    let channels = e.net_channel_count();
    let servers = e.net_server_count();
    let bans = e.akills().len();
    let opers = e.stats_snapshot().get("opers.total").copied().unwrap_or(0) as usize;
    let srv = e.net_servers();
    let top = e.net_top_channels(6);
    drop(e);

    let max_srv = srv.iter().map(|(_, u)| *u).max().unwrap_or(0).max(1);
    let server_rows = srv
        .into_iter()
        .map(|(name, u)| SrvRow { pct: (u as u64 * 100 / max_srv as u64), name, users: u })
        .collect();
    let max_chan = top.first().map(|(_, u)| *u).unwrap_or(0).max(1);
    let chan_rows = top
        .into_iter()
        .map(|(name, u)| ChanRow { pct: (u as u64 * 100 / max_chan as u64), name, users: u })
        .collect();

    html(DashboardTpl {
        brand: st.brand.clone(),
        active: "dashboard",
        username: oper.account.clone(),
        is_root: is_root(&oper),
        show_audit: true,
        users,
        opers,
        channels,
        servers,
        bans,
        server_rows,
        chan_rows,
    })
}

// ---- placeholder pages (progressively replaced by wired templates) -------

#[derive(askama::Template)]
#[template(path = "ircpanel/placeholder.html")]
struct PlaceholderTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    page_title: &'static str,
}

fn placeholder(st: &AppState, oper: &Oper, active: &'static str, title: &'static str) -> Html<String> {
    html(PlaceholderTpl {
        brand: st.brand.clone(),
        active,
        username: oper.account.clone(),
        is_root: is_root(oper),
        show_audit: true,
        page_title: title,
    })
}

// A gated placeholder page: (handler name, nav key, title).
macro_rules! simple_page {
    ($fn:ident, $active:expr, $title:expr) => {
        async fn $fn(oper: Oper, State(st): State<AppState>) -> Html<String> {
            placeholder(&st, &oper, $active, $title)
        }
    };
}
simple_page!(page_trends, "dashboard", "Tendances");
simple_page!(page_name_bans, "bans", "Bans de pseudo");
simple_page!(page_exceptions, "bans", "Exceptions");
simple_page!(page_spamfilter, "bans", "Filtre anti-spam");
simple_page!(page_security_groups, "bans", "Groupes de sécurité");
simple_page!(page_ip_whois, "users", "IP WHOIS");
simple_page!(page_whowas, "users", "WHOWAS");
simple_page!(page_logs, "audit", "Journaux");
simple_page!(page_audit, "audit", "Audit");
simple_page!(page_access, "opers", "Accès");

// ---- wired data pages ----------------------------------------------------

struct UserRow {
    nick: String,
    ident: String,
    host: String,
    ip: String,
    account: String,
    has_account: bool,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/users.html")]
struct UsersTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    rows: Vec<UserRow>,
    accounts: usize,
    guests: usize,
}

async fn page_users(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let raw = e.net_users();
    drop(e);
    let rows: Vec<UserRow> = raw
        .into_iter()
        .map(|(nick, ident, host, ip, account)| {
            let has_account = !account.is_empty();
            UserRow { nick, ident, host, ip, account, has_account }
        })
        .collect();
    let accounts = rows.iter().filter(|r| r.has_account).count();
    let guests = rows.len() - accounts;
    html(UsersTpl {
        brand: st.brand.clone(),
        active: "users",
        username: oper.account.clone(),
        is_root: is_root(&oper),
        show_audit: true,
        rows,
        accounts,
        guests,
    })
}

struct SrvFull {
    name: String,
    users: usize,
    pct: u64,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/servers.html")]
struct ServersTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    rows: Vec<SrvFull>,
}

async fn page_servers(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let srv = e.net_servers();
    drop(e);
    let max = srv.iter().map(|(_, u)| *u).max().unwrap_or(0).max(1);
    let rows = srv
        .into_iter()
        .map(|(name, u)| SrvFull { pct: (u as u64 * 100 / max as u64), name, users: u })
        .collect();
    html(ServersTpl {
        brand: st.brand.clone(),
        active: "servers",
        username: oper.account.clone(),
        is_root: is_root(&oper),
        show_audit: true,
        rows,
    })
}

struct ChanFullRow {
    name: String,
    users: usize,
    founder: String,
    topic: String,
    registered: bool,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/channels.html")]
struct ChannelsTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    rows: Vec<ChanFullRow>,
}

async fn page_channels(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let live = e.net_channels();
    let (_accts, registered) = e.directory_snapshot();
    drop(e);
    // Index registered channel metadata by lowercase name to merge onto the live set.
    let reg: std::collections::HashMap<String, (String, String)> = registered
        .into_iter()
        .map(|c| (c.name.to_lowercase(), (c.founder, c.topic)))
        .collect();
    let rows = live
        .into_iter()
        .map(|(name, users)| {
            let (founder, topic, registered) = match reg.get(&name.to_lowercase()) {
                Some((f, t)) => (f.clone(), t.clone(), true),
                None => (String::new(), String::new(), false),
            };
            ChanFullRow { name, users, founder, topic, registered }
        })
        .collect();
    html(ChannelsTpl {
        brand: st.brand.clone(),
        active: "channels",
        username: oper.account.clone(),
        is_root: is_root(&oper),
        show_audit: true,
        rows,
    })
}

struct BanRow {
    kind: String,
    mask: String,
    setter: String,
    reason: String,
    set_ago: String,
    expires: String,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/bans.html")]
struct BansTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    rows: Vec<BanRow>,
}

async fn page_bans(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let akills = e.akills();
    drop(e);
    let now = now();
    let rows = akills
        .into_iter()
        .map(|a| BanRow {
            kind: format!("{:?}", a.kind).to_uppercase(),
            mask: a.mask,
            setter: a.setter,
            reason: a.reason,
            set_ago: tmpl::human_ago(a.ts, now),
            expires: match a.expires {
                None => "permanent".to_string(),
                Some(t) if t > now => format!("expire {}", tmpl::human_until(now, t)),
                Some(_) => "expiré".to_string(),
            },
        })
        .collect();
    html(BansTpl {
        brand: st.brand.clone(),
        active: "bans",
        username: oper.account.clone(),
        is_root: is_root(&oper),
        show_audit: true,
        rows,
    })
}

struct OperRow {
    name: String,
    tier: &'static str,
    email: String,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/opers.html")]
struct OpersTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    rows: Vec<OperRow>,
}

async fn page_opers(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let (accts, _chans) = e.directory_snapshot();
    let rows: Vec<OperRow> = accts
        .into_iter()
        .filter_map(|a| {
            let privs = e.account_privs(&a.name);
            privs.any().then(|| OperRow {
                name: a.name,
                tier: privs.tier(),
                email: a.email.unwrap_or_default(),
            })
        })
        .collect();
    drop(e);
    html(OpersTpl {
        brand: st.brand.clone(),
        active: "opers",
        username: oper.account.clone(),
        is_root: is_root(&oper),
        show_audit: true,
        rows,
    })
}

struct RegRow {
    name: String,
    email: String,
    verified: bool,
    registered: String,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/registrations.html")]
struct RegsTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    rows: Vec<RegRow>,
}

async fn page_registrations(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let (accts, _chans) = e.directory_snapshot();
    drop(e);
    let now = now();
    let mut rows: Vec<RegRow> = accts
        .into_iter()
        .map(|a| RegRow {
            registered: tmpl::human_ago(a.ts, now),
            name: a.name,
            email: a.email.unwrap_or_default(),
            verified: a.verified,
        })
        .collect();
    rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    html(RegsTpl {
        brand: st.brand.clone(),
        active: "registrations",
        username: oper.account.clone(),
        is_root: is_root(&oper),
        show_audit: true,
        rows,
    })
}

#[derive(askama::Template)]
#[template(path = "ircpanel/modules.html")]
struct ModulesTpl {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    show_audit: bool,
    rows: Vec<String>,
}

async fn page_modules(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let rows = e.net_module_names();
    drop(e);
    html(ModulesTpl {
        brand: st.brand.clone(),
        active: "modules",
        username: oper.account.clone(),
        is_root: is_root(&oper),
        show_audit: true,
        rows,
    })
}

async fn page_user_detail(oper: Oper, State(st): State<AppState>, Path(_nick): Path<String>) -> Html<String> {
    placeholder(&st, &oper, "users", "Utilisateur")
}
async fn page_channel_detail(oper: Oper, State(st): State<AppState>, Path(_slug): Path<String>) -> Html<String> {
    placeholder(&st, &oper, "channels", "Salon")
}
async fn page_server_detail(oper: Oper, State(st): State<AppState>, Path(_name): Path<String>) -> Html<String> {
    placeholder(&st, &oper, "servers", "Serveur")
}

// ---- JSON endpoints for the live UI --------------------------------------

// The health dot in the topbar: green when echo is linked to the ircd.
async fn health(State(st): State<AppState>) -> Response {
    let e = st.engine.lock().await;
    let ok = e.linked();
    let name = e.net_servers().first().map(|(n, _)| n.clone()).unwrap_or_else(|| st.brand.clone());
    drop(e);
    axum::Json(json!({ "ok": ok, "name": name })).into_response()
}

// Live counters polled by the dashboard.
async fn live(oper: Oper, State(st): State<AppState>) -> Response {
    let _ = oper; // gate to authenticated opers only
    let e = st.engine.lock().await;
    let counts = json!({
        "users": e.net_user_count(),
        "channels": e.net_channel_count(),
        "servers": e.net_server_count(),
        "opers": e.stats_snapshot().get("opers.total").copied().unwrap_or(0),
        "bans": e.akills().len(),
    });
    drop(e);
    axum::Json(json!({ "counts": counts })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template;

    // Every page struct must render to non-empty HTML that extends the shell.
    #[test]
    fn pages_render() {
        let brand = "test".to_string();
        let who = "root".to_string();

        let dash = DashboardTpl {
            brand: brand.clone(),
            active: "dashboard",
            username: who.clone(),
            is_root: true,
            show_audit: true,
            users: 17,
            opers: 1,
            channels: 6,
            servers: 1,
            bans: 2,
            server_rows: vec![SrvRow { name: "irc.a".into(), users: 17, pct: 100 }],
            chan_rows: vec![ChanRow { name: "#a".into(), users: 5, pct: 100 }],
        }
        .render()
        .unwrap();
        assert!(dash.contains("17") && dash.contains("irc.a") && dash.contains("#a"));

        let users = UsersTpl {
            brand: brand.clone(),
            active: "users",
            username: who.clone(),
            is_root: true,
            show_audit: true,
            rows: vec![UserRow {
                nick: "bob".into(),
                ident: "b".into(),
                host: "h".into(),
                ip: "1.2.3.4".into(),
                account: "bob".into(),
                has_account: true,
            }],
            accounts: 1,
            guests: 0,
        }
        .render()
        .unwrap();
        assert!(users.contains("bob") && users.contains("1.2.3.4"));

        assert!(ServersTpl {
            brand: brand.clone(),
            active: "servers",
            username: who.clone(),
            is_root: true,
            show_audit: true,
            rows: vec![SrvFull { name: "irc.a".into(), users: 3, pct: 100 }],
        }
        .render()
        .unwrap()
        .contains("irc.a"));

        assert!(ChannelsTpl {
            brand: brand.clone(),
            active: "channels",
            username: who.clone(),
            is_root: true,
            show_audit: true,
            rows: vec![ChanFullRow {
                name: "#a".into(),
                users: 1,
                founder: "bob".into(),
                topic: "hi".into(),
                registered: true,
            }],
        }
        .render()
        .unwrap()
        .contains("#a"));

        assert!(BansTpl {
            brand: brand.clone(),
            active: "bans",
            username: who.clone(),
            is_root: true,
            show_audit: true,
            rows: vec![BanRow {
                kind: "GLINE".into(),
                mask: "*@bad".into(),
                setter: "op".into(),
                reason: "spam".into(),
                set_ago: "il y a 1 j".into(),
                expires: "permanent".into(),
            }],
        }
        .render()
        .unwrap()
        .contains("*@bad"));

        assert!(OpersTpl {
            brand: brand.clone(),
            active: "opers",
            username: who.clone(),
            is_root: true,
            show_audit: true,
            rows: vec![OperRow { name: "root".into(), tier: "root", email: String::new() }],
        }
        .render()
        .unwrap()
        .contains("root"));

        assert!(RegsTpl {
            brand: brand.clone(),
            active: "registrations",
            username: who.clone(),
            is_root: true,
            show_audit: true,
            rows: vec![RegRow {
                name: "bob".into(),
                email: "b@x".into(),
                verified: true,
                registered: "il y a 2 j".into(),
            }],
        }
        .render()
        .unwrap()
        .contains("bob"));

        assert!(ModulesTpl {
            brand,
            active: "modules",
            username: who,
            is_root: true,
            show_audit: true,
            rows: vec!["m_spamfilter".into()],
        }
        .render()
        .unwrap()
        .contains("m_spamfilter"));
    }
}

