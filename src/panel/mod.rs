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
use crate::engine::{scram, state, Engine};
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
        .route("/search", get(search))
        .route("/logs/events", get(logs_events))
        .route("/logs/tail", get(logs_tail))
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
// Every page is a compile-time askama template backed by a typed struct sharing
// a `Chrome` (topbar/nav identity). All formatting happens here in Rust; the
// templates only interpolate. Data comes straight from echo's own engine — the
// live S2S network view plus the account/channel/xline directory — under the
// shared lock, never from the ircd's RPC.

use axum::extract::Query;
use std::collections::HashMap;

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

// Identity + nav state shared by every page (referenced as `chrome.*` in base.html).
#[derive(Clone)]
struct Chrome {
    brand: String,
    active: &'static str,
    username: String,
    is_root: bool,
    can_audit: bool,
    version: &'static str,
}

fn chrome(st: &AppState, oper: &Oper, active: &'static str) -> Chrome {
    Chrome {
        brand: st.brand.clone(),
        active,
        username: oper.account.clone(),
        is_root: oper.privs.tier() == "root",
        can_audit: true,
        version: crate::version::VERSION,
    }
}

fn pct(part: usize, whole: usize) -> u64 {
    if whole == 0 {
        0
    } else {
        (part as u64 * 100 / whole as u64).min(100)
    }
}

// (expiry text, is-permanent) for an optional absolute expiry.
fn fmt_expiry(expires: Option<u64>, now: u64) -> (String, bool) {
    match expires {
        None => ("permanent".to_string(), true),
        Some(t) if t > now => (tmpl::human_until(now, t), false),
        Some(_) => ("expiré".to_string(), false),
    }
}

// Classify an incident summary into a feed kind (mirrors the dashboard JS).
fn classify(s: &str) -> &'static str {
    let t = s.to_ascii_lowercase();
    if t.contains("kill") || t.contains("line") || t.contains("ban") || t.contains("shun") || t.contains("filter") || t.contains("akill") {
        "mod"
    } else if t.contains("oper") {
        "oper"
    } else if t.contains("link") || t.contains("squit") || t.contains("module") || t.contains("rehash") || t.contains("netsplit") {
        "srv"
    } else if t.contains("connect") || t.contains("join") {
        "join"
    } else if t.contains("quit") || t.contains("disconnect") || t.contains("part") {
        "part"
    } else {
        "log"
    }
}

// ---- dashboard -----------------------------------------------------------

struct SrvCard {
    name: String,
    uplink: String,
    hub: bool,
    users: usize,
    opers: usize,
    pct: u64,
}
struct ChanRank {
    name: String,
    slug: String,
    topic: String,
    users: usize,
    pct: u64,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/dashboard.html")]
struct DashboardTpl {
    chrome: Chrome,
    net_name: String,
    version: &'static str,
    users: usize,
    local: usize,
    opers: usize,
    channels: usize,
    servers: usize,
    bans: usize,
    server_cards: Vec<SrvCard>,
    chan_ranks: Vec<ChanRank>,
}

async fn dashboard(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let users = e.net_user_count();
    let channels = e.net_channel_count();
    let servers = e.net_server_count();
    let bans = e.akills().len();
    let opers = e.net_oper_count();
    let srv = e.net_servers_detailed();
    let mut chans = e.net_channels_detailed();
    let net_name = srv.first().map(|s| s.name.clone()).unwrap_or_else(|| st.brand.clone());
    drop(e);

    let server_cards = srv
        .iter()
        .map(|s| SrvCard {
            name: s.name.clone(),
            uplink: s.uplink.clone(),
            hub: s.uplink.is_empty(),
            users: s.users,
            opers: s.opers,
            pct: pct(s.users, users),
        })
        .collect();
    chans.truncate(8);
    let top = chans.first().map(|c| c.users).unwrap_or(0);
    let chan_ranks = chans
        .into_iter()
        .map(|c| ChanRank {
            slug: tmpl::url_seg(&c.name),
            name: c.name,
            topic: c.topic,
            users: c.users,
            pct: pct(c.users, top),
        })
        .collect();

    html(DashboardTpl {
        chrome: chrome(&st, &oper, "dashboard"),
        net_name,
        version: crate::version::VERSION,
        users,
        local: users,
        opers,
        channels,
        servers,
        bans,
        server_cards,
        chan_ranks,
    })
}

// ---- users ---------------------------------------------------------------

struct URow {
    nick: String,
    slug: String,
    ident: String,
    host: String,
    ip: String,
    account: String,
    has_account: bool,
    is_oper: bool,
    operclass: String,
    modes: String,
    server: String,
    secure: bool,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/users.html")]
struct UsersTpl {
    chrome: Chrome,
    rows: Vec<URow>,
    total: usize,
    accounts: usize,
    guests: usize,
    opers: usize,
}

async fn page_users(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let users = e.net_users_detailed();
    drop(e);
    let rows: Vec<URow> = users
        .into_iter()
        .map(|u| URow {
            has_account: !u.account.is_empty(),
            is_oper: !u.oper.is_empty(),
            operclass: u.oper,
            slug: tmpl::url_seg(&u.nick),
            nick: u.nick,
            ident: u.ident,
            host: u.host,
            ip: u.ip,
            account: u.account,
            modes: u.modes,
            server: u.server,
            secure: u.secure,
        })
        .collect();
    let total = rows.len();
    let accounts = rows.iter().filter(|r| r.has_account).count();
    let opers = rows.iter().filter(|r| r.is_oper).count();
    html(UsersTpl {
        chrome: chrome(&st, &oper, "users"),
        guests: total - accounts,
        total,
        accounts,
        opers,
        rows,
    })
}

// ---- channels ------------------------------------------------------------

struct CRow {
    name: String,
    slug: String,
    topic: String,
    users: usize,
    modes: String,
    secret: bool,
    private: bool,
    inviteonly: bool,
    keyed: bool,
    moderated: bool,
    registered: bool,
    pct: u64,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/channels.html")]
struct ChannelsTpl {
    chrome: Chrome,
    rows: Vec<CRow>,
    total: usize,
    registered: usize,
    moderated: usize,
    members: usize,
}

async fn page_channels(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let chans = e.net_channels_detailed();
    drop(e);
    let max_users = chans.first().map(|c| c.users).unwrap_or(0);
    let members: usize = chans.iter().map(|c| c.users).sum();
    let registered = chans.iter().filter(|c| c.registered).count();
    let moderated = chans.iter().filter(|c| c.moderated).count();
    let total = chans.len();
    let rows = chans
        .into_iter()
        .map(|c| CRow {
            pct: pct(c.users, max_users),
            slug: tmpl::url_seg(&c.name),
            name: c.name,
            topic: c.topic,
            users: c.users,
            modes: c.modes,
            secret: c.secret,
            private: c.private,
            inviteonly: c.inviteonly,
            keyed: c.keyed,
            moderated: c.moderated,
            registered: c.registered,
        })
        .collect();
    html(ChannelsTpl {
        chrome: chrome(&st, &oper, "channels"),
        rows,
        total,
        registered,
        moderated,
        members,
    })
}

// ---- servers -------------------------------------------------------------

struct SRow {
    name: String,
    uplink: String,
    hub: bool,
    users: usize,
    opers: usize,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/servers.html")]
struct ServersTpl {
    chrome: Chrome,
    rows: Vec<SRow>,
    count: usize,
    users: usize,
    opers: usize,
    hub_name: String,
    tree_html: String,
}

// Build the nested <li>/<ul> topology under `parent` (matched by uplink name).
// A node with no known parent is a root; the hub (empty uplink) gets the badge.
fn render_tree(servers: &[state::NetSrv], parent: &str) -> String {
    let mut out = String::new();
    for s in servers.iter().filter(|s| s.uplink == parent) {
        let hub = s.uplink.is_empty();
        out.push_str("<li><div class=\"net-node");
        if hub {
            out.push_str(" is-hub");
        }
        out.push_str("\"><span class=\"net-node-ico\"><svg viewBox=\"0 0 24 24\"><rect x=\"3\" y=\"4\" width=\"18\" height=\"6\" rx=\"1.5\"/><rect x=\"3\" y=\"14\" width=\"18\" height=\"6\" rx=\"1.5\"/><path d=\"M7 7h.01M7 17h.01\"/></svg></span>");
        out.push_str(&format!(
            "<span class=\"net-node-body\"><a class=\"net-node-name\" href=\"/servers/{}\">{}</a><span class=\"net-node-meta\"><span title=\"utilisateurs\">👤 {}</span><span title=\"opérateurs\">⚡ {}</span></span></span>",
            tmpl::url_seg(&s.name), esc(&s.name), s.users, s.opers
        ));
        if hub {
            out.push_str("<span class=\"net-hub-badge\">HUB</span>");
        }
        out.push_str("</div>");
        let kids = render_tree(servers, &s.name);
        if !kids.is_empty() {
            out.push_str("<ul>");
            out.push_str(&kids);
            out.push_str("</ul>");
        }
        out.push_str("</li>");
    }
    out
}

async fn page_servers(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let srv = e.net_servers_detailed();
    drop(e);
    let count = srv.len();
    let users: usize = srv.iter().map(|s| s.users).sum();
    let opers: usize = srv.iter().map(|s| s.opers).sum();
    let hub_name = srv.iter().find(|s| s.uplink.is_empty()).or_else(|| srv.first()).map(|s| s.name.clone()).unwrap_or_default();
    let names: std::collections::HashSet<String> = srv.iter().map(|s| s.name.clone()).collect();
    // Roots = empty uplink or an uplink we don't actually know (orphans surface at top).
    let mut tree_html = render_tree(&srv, "");
    for s in &srv {
        if !s.uplink.is_empty() && !names.contains(&s.uplink) {
            tree_html.push_str(&render_tree(&srv, &s.uplink));
        }
    }
    let rows = srv
        .into_iter()
        .map(|s| SRow {
            hub: s.uplink.is_empty(),
            name: s.name,
            uplink: s.uplink,
            users: s.users,
            opers: s.opers,
        })
        .collect();
    html(ServersTpl {
        chrome: chrome(&st, &oper, "servers"),
        rows,
        count,
        users,
        opers,
        hub_name,
        tree_html,
    })
}

// ---- protection: bans / name-bans / exceptions / spamfilter --------------

struct PRow {
    kind: String,
    mask: String,
    reason: String,
    set_by: String,
    set_ago: String,
    expires: String,
    perm: bool,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/bans.html")]
struct BansTpl {
    chrome: Chrome,
    rows: Vec<PRow>,
    total: usize,
    perm: usize,
    heading: &'static str,
    subtitle: &'static str,
    empty: &'static str,
}

// Server bans (user/host/realname/shun/channel), from the akill store.
async fn page_bans(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let akills = e.akills();
    drop(e);
    let now = now();
    let rows: Vec<PRow> = akills
        .into_iter()
        .filter(|a| !matches!(a.kind, echo_api::XlineKind::Qline))
        .map(|a| {
            let (expires, perm) = fmt_expiry(a.expires, now);
            PRow {
                kind: a.kind.wire().to_string(),
                mask: a.mask,
                reason: a.reason,
                set_by: a.setter,
                set_ago: tmpl::human_ago(a.ts, now),
                expires,
                perm,
            }
        })
        .collect();
    let total = rows.len();
    let perm = rows.iter().filter(|r| r.perm).count();
    html(BansTpl {
        chrome: chrome(&st, &oper, "bans"),
        rows,
        total,
        perm,
        heading: "Bans serveur",
        subtitle: "Lignes X actives sur le réseau : G-lines, shuns, R-lines, C-bans.",
        empty: "Aucun ban serveur actif.",
    })
}

// Name bans (Q-lines: forbidden nicks).
async fn page_name_bans(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let akills = e.akills();
    drop(e);
    let now = now();
    let rows: Vec<PRow> = akills
        .into_iter()
        .filter(|a| matches!(a.kind, echo_api::XlineKind::Qline))
        .map(|a| {
            let (expires, perm) = fmt_expiry(a.expires, now);
            PRow {
                kind: "Q".to_string(),
                mask: a.mask,
                reason: a.reason,
                set_by: a.setter,
                set_ago: tmpl::human_ago(a.ts, now),
                expires,
                perm,
            }
        })
        .collect();
    let total = rows.len();
    let perm = rows.iter().filter(|r| r.perm).count();
    html(BansTpl {
        chrome: chrome(&st, &oper, "name_bans"),
        rows,
        total,
        perm,
        heading: "Bans de nom",
        subtitle: "Pseudos interdits sur le réseau (Q-lines / SQLINE).",
        empty: "Aucun ban de nom actif.",
    })
}

// Exceptions (session-limit exceptions).
async fn page_exceptions(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let excs = e.session_exceptions();
    drop(e);
    let rows: Vec<PRow> = excs
        .into_iter()
        .map(|(mask, limit, reason)| PRow {
            kind: format!("{limit}×"),
            mask,
            reason,
            set_by: String::new(),
            set_ago: String::new(),
            expires: "permanent".to_string(),
            perm: true,
        })
        .collect();
    let total = rows.len();
    html(BansTpl {
        chrome: chrome(&st, &oper, "exceptions"),
        rows,
        total,
        perm: total,
        heading: "Exceptions de session",
        subtitle: "Masques autorisés à dépasser la limite de sessions par IP.",
        empty: "Aucune exception configurée.",
    })
}

struct FRow {
    pattern: String,
    action: String,
    flags: String,
    reason: String,
    set_ago: String,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/spamfilter.html")]
struct SpamTpl {
    chrome: Chrome,
    rows: Vec<FRow>,
    total: usize,
}

async fn page_spamfilter(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let filters = e.filters();
    drop(e);
    let now = now();
    let rows: Vec<FRow> = filters
        .into_iter()
        .map(|f| FRow {
            pattern: f.pattern,
            action: f.action,
            flags: f.flags,
            reason: f.reason,
            set_ago: tmpl::human_ago(f.ts, now),
        })
        .collect();
    let total = rows.len();
    html(SpamTpl { chrome: chrome(&st, &oper, "spamfilter"), rows, total })
}

#[derive(askama::Template)]
#[template(path = "ircpanel/security_groups.html")]
struct SecGroupsTpl {
    chrome: Chrome,
}

async fn page_security_groups(oper: Oper, State(st): State<AppState>) -> Html<String> {
    html(SecGroupsTpl { chrome: chrome(&st, &oper, "security_groups") })
}

// ---- system: opers / registrations / modules / audit / whowas / logs -----

struct ORow {
    name: String,
    tier: String,
    online: usize,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/opers.html")]
struct OpersTpl {
    chrome: Chrome,
    rows: Vec<ORow>,
}

async fn page_opers(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let (accts, _chans) = e.directory_snapshot();
    let users = e.net_users_detailed();
    let mut rows: Vec<ORow> = accts
        .into_iter()
        .filter_map(|a| {
            let privs = e.account_privs(&a.name);
            if !privs.any() {
                return None;
            }
            let online = users.iter().filter(|u| u.account.eq_ignore_ascii_case(&a.name)).count();
            Some(ORow { name: a.name, tier: privs.tier().to_string(), online })
        })
        .collect();
    drop(e);
    rows.sort_by_key(|a| a.name.to_lowercase());
    html(OpersTpl { chrome: chrome(&st, &oper, "opers"), rows })
}

struct REvt {
    when: String,
    user: String,
    email: String,
    verified: bool,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/registrations.html")]
struct RegTpl {
    chrome: Chrome,
    total: usize,
    reg_24h: usize,
    reg_7d: usize,
    verified: usize,
    pending: usize,
    days: Vec<(u32, u64)>, // (count, height %)
    recent: Vec<REvt>,
}

async fn page_registrations(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let (mut accts, _chans) = e.directory_snapshot();
    drop(e);
    let now = now();
    let total = accts.len();
    let reg_24h = accts.iter().filter(|a| now.saturating_sub(a.ts) < 86_400).count();
    let reg_7d = accts.iter().filter(|a| now.saturating_sub(a.ts) < 7 * 86_400).count();
    let verified = accts.iter().filter(|a| a.verified).count();
    let pending = total - verified;
    // 14-day histogram, index 0 = 13 days ago … 13 = today.
    let mut counts = vec![0u32; 14];
    for a in &accts {
        let age_days = now.saturating_sub(a.ts) / 86_400;
        if age_days < 14 {
            counts[13 - age_days as usize] += 1;
        }
    }
    let days_max = counts.iter().copied().max().unwrap_or(0).max(1);
    let days: Vec<(u32, u64)> = counts.into_iter().map(|c| (c, pct(c as usize, days_max as usize))).collect();
    accts.sort_by_key(|a| std::cmp::Reverse(a.ts));
    let recent: Vec<REvt> = accts
        .into_iter()
        .take(14)
        .map(|a| REvt {
            when: tmpl::fmt_dt(a.ts),
            user: a.name,
            email: a.email.unwrap_or_default(),
            verified: a.verified,
        })
        .collect();
    html(RegTpl {
        chrome: chrome(&st, &oper, "registrations"),
        total,
        reg_24h,
        reg_7d,
        verified,
        pending,
        days,
        recent,
    })
}

#[derive(askama::Template)]
#[template(path = "ircpanel/modules.html")]
struct ModulesTpl {
    chrome: Chrome,
    rows: Vec<String>,
    total: usize,
}

async fn page_modules(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let rows = e.net_module_names();
    drop(e);
    let total = rows.len();
    html(ModulesTpl { chrome: chrome(&st, &oper, "modules"), rows, total })
}

struct AuditRow {
    when: String,
    ago: String,
    id: String,
    summary: String,
    kind: &'static str,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/audit.html")]
struct AuditTpl {
    chrome: Chrome,
    rows: Vec<AuditRow>,
    total: usize,
}

async fn page_audit(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let incs = e.recent_incidents(400);
    drop(e);
    let now = now();
    let total = incs.len();
    let rows: Vec<AuditRow> = incs
        .into_iter()
        .map(|i| AuditRow {
            when: tmpl::fmt_dt(i.ts),
            ago: tmpl::human_ago(i.ts, now),
            kind: classify(&i.summary),
            id: i.id,
            summary: i.summary,
        })
        .collect();
    html(AuditTpl { chrome: chrome(&st, &oper, "audit"), rows, total })
}

#[derive(askama::Template)]
#[template(path = "ircpanel/whowas.html")]
struct WhowasTpl {
    chrome: Chrome,
    q: String,
    rows: Vec<URow>,
}

// WHOWAS: echo has no history store; we answer live from the current network
// view so a nick lookup still returns its present session.
async fn page_whowas(oper: Oper, State(st): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Html<String> {
    let q = p.get("q").cloned().unwrap_or_default();
    let mut rows = Vec::new();
    if !q.is_empty() {
        let e = st.engine.lock().await;
        if let Some(u) = e.net_user_detail(&q) {
            rows.push(URow {
                has_account: !u.account.is_empty(),
                is_oper: !u.oper.is_empty(),
                operclass: u.oper,
                slug: tmpl::url_seg(&u.nick),
                nick: u.nick,
                ident: u.ident,
                host: u.host,
                ip: u.ip,
                account: u.account,
                modes: u.modes,
                server: u.server,
                secure: u.secure,
            });
        }
        drop(e);
    }
    html(WhowasTpl { chrome: chrome(&st, &oper, "whowas"), q, rows })
}

// IP WHOIS: no GeoIP, but echo knows every session's IP and every ban — so we
// answer "who is on this IP" and "which bans match it".
struct IpUser {
    nick: String,
    slug: String,
    ident: String,
    host: String,
    account: String,
    is_oper: bool,
    server: String,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/ip_whois.html")]
struct IpWhoisTpl {
    chrome: Chrome,
    q: String,
    ip: String,
    users: Vec<IpUser>,
    bans: Vec<PRow>,
}

async fn page_ip_whois(oper: Oper, State(st): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Html<String> {
    let q = p.get("ip").cloned().unwrap_or_default();
    let (mut users, mut bans) = (Vec::new(), Vec::new());
    if !q.is_empty() {
        let e = st.engine.lock().await;
        for u in e.net_users_detailed() {
            if u.ip == q {
                users.push(IpUser {
                    is_oper: !u.oper.is_empty(),
                    slug: tmpl::url_seg(&u.nick),
                    nick: u.nick,
                    ident: u.ident,
                    host: u.host,
                    account: u.account,
                    server: u.server,
                });
            }
        }
        let now = now();
        for a in e.akills() {
            if a.mask.contains(&q) || q.contains(a.mask.trim_start_matches("*@")) {
                let (expires, perm) = fmt_expiry(a.expires, now);
                bans.push(PRow {
                    kind: a.kind.wire().to_string(),
                    mask: a.mask,
                    reason: a.reason,
                    set_by: a.setter,
                    set_ago: tmpl::human_ago(a.ts, now),
                    expires,
                    perm,
                });
            }
        }
        drop(e);
    }
    html(IpWhoisTpl { chrome: chrome(&st, &oper, "ip_whois"), ip: q.clone(), q, users, bans })
}

#[derive(askama::Template)]
#[template(path = "ircpanel/logs.html")]
struct LogsTpl {
    chrome: Chrome,
}

async fn page_logs(oper: Oper, State(st): State<AppState>) -> Html<String> {
    html(LogsTpl { chrome: chrome(&st, &oper, "logs") })
}

struct GrantRow {
    name: String,
    tier: String,
    perms: Vec<String>,
    expires: String,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/access.html")]
struct AccessTpl {
    chrome: Chrome,
    grants: Vec<GrantRow>,
    total: usize,
}

async fn page_access(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let grants_raw = e.opers_grants();
    let now = now();
    let mut grants: Vec<GrantRow> = grants_raw
        .into_iter()
        .map(|(name, perms, expires)| {
            let tier = e.account_privs(&name).tier().to_string();
            GrantRow {
                name,
                tier,
                perms,
                expires: expires.map(tmpl::fmt_date).unwrap_or_else(|| "permanent".into()),
            }
        })
        .collect();
    let _ = now;
    drop(e);
    grants.sort_by_key(|a| a.name.to_lowercase());
    let total = grants.len();
    html(AccessTpl { chrome: chrome(&st, &oper, "access"), grants, total })
}

#[derive(askama::Template)]
#[template(path = "ircpanel/trends.html")]
struct TrendsTpl {
    chrome: Chrome,
    users: usize,
    channels: usize,
    servers: usize,
    opers: usize,
}

async fn page_trends(oper: Oper, State(st): State<AppState>) -> Html<String> {
    let e = st.engine.lock().await;
    let (users, channels, servers, opers) = (e.net_user_count(), e.net_channel_count(), e.net_server_count(), e.net_oper_count());
    drop(e);
    html(TrendsTpl { chrome: chrome(&st, &oper, "trends"), users, channels, servers, opers })
}

// ---- detail pages --------------------------------------------------------

struct UChan {
    name: String,
    slug: String,
    prefix: &'static str,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/user_detail.html")]
struct UserDetailTpl {
    chrome: Chrome,
    found: bool,
    initial: String,
    nick: String,
    ident: String,
    host: String,
    ip: String,
    gecos: String,
    account: String,
    is_oper: bool,
    operclass: String,
    modes: String,
    server: String,
    secure: bool,
    channels: Vec<UChan>,
    // account facts (if registered)
    registered: bool,
    email: String,
    verified: bool,
    joined: String,
}

async fn page_user_detail(oper: Oper, State(st): State<AppState>, Path(nick): Path<String>) -> Html<String> {
    let e = st.engine.lock().await;
    let u = e.net_user_detail(&nick);
    let mut t = UserDetailTpl {
        chrome: chrome(&st, &oper, "users"),
        found: false,
        initial: String::new(),
        nick: nick.clone(),
        ident: String::new(),
        host: String::new(),
        ip: String::new(),
        gecos: String::new(),
        account: String::new(),
        is_oper: false,
        operclass: String::new(),
        modes: String::new(),
        server: String::new(),
        secure: false,
        channels: Vec::new(),
        registered: false,
        email: String::new(),
        verified: false,
        joined: String::new(),
    };
    if let Some(u) = u {
        let chans = e.net_user_channels(&u.uid);
        if !u.account.is_empty() {
            let (accts, _) = e.directory_snapshot();
            if let Some(a) = accts.into_iter().find(|a| a.name.eq_ignore_ascii_case(&u.account)) {
                t.registered = true;
                t.email = a.email.unwrap_or_default();
                t.verified = a.verified;
                t.joined = tmpl::fmt_date(a.ts);
            }
        }
        t.found = true;
        t.nick = u.nick;
        t.ident = u.ident;
        t.host = u.host;
        t.ip = u.ip;
        t.gecos = u.gecos;
        t.is_oper = !u.oper.is_empty();
        t.operclass = u.oper;
        t.modes = u.modes;
        t.server = u.server;
        t.secure = u.secure;
        t.account = u.account;
        t.channels = chans.into_iter().map(|(name, prefix)| UChan { slug: tmpl::url_seg(&name), name, prefix }).collect();
    }
    drop(e);
    t.initial = t.nick.chars().next().map(|c| c.to_ascii_uppercase().to_string()).unwrap_or_else(|| "?".into());
    html(t)
}

struct CMember {
    nick: String,
    slug: String,
    prefix: &'static str,
    account: String,
    is_oper: bool,
}

#[derive(askama::Template)]
#[template(path = "ircpanel/channel_detail.html")]
struct ChannelDetailTpl {
    chrome: Chrome,
    found: bool,
    name: String,
    topic: String,
    topic_setter: String,
    users: usize,
    modes: String,
    secret: bool,
    private: bool,
    inviteonly: bool,
    keyed: bool,
    moderated: bool,
    registered: bool,
    members: Vec<CMember>,
}

async fn page_channel_detail(oper: Oper, State(st): State<AppState>, Path(name): Path<String>) -> Html<String> {
    let e = st.engine.lock().await;
    let c = e.net_channel_detail(&name);
    let members = e.net_channel_members(&name);
    drop(e);
    let mut t = ChannelDetailTpl {
        chrome: chrome(&st, &oper, "channels"),
        found: false,
        name: name.clone(),
        topic: String::new(),
        topic_setter: String::new(),
        users: 0,
        modes: String::new(),
        secret: false,
        private: false,
        inviteonly: false,
        keyed: false,
        moderated: false,
        registered: false,
        members: Vec::new(),
    };
    if let Some(c) = c {
        t.found = true;
        t.name = c.name;
        t.topic = c.topic;
        t.topic_setter = c.topic_setter;
        t.users = c.users;
        t.modes = c.modes;
        t.secret = c.secret;
        t.private = c.private;
        t.inviteonly = c.inviteonly;
        t.keyed = c.keyed;
        t.moderated = c.moderated;
        t.registered = c.registered;
        t.members = members
            .into_iter()
            .map(|m| CMember { slug: tmpl::url_seg(&m.nick), nick: m.nick, prefix: m.prefix, account: m.account, is_oper: m.oper })
            .collect();
    }
    html(t)
}

#[derive(askama::Template)]
#[template(path = "ircpanel/server_detail.html")]
struct ServerDetailTpl {
    chrome: Chrome,
    found: bool,
    name: String,
    uplink: String,
    hub: bool,
    users: usize,
    opers: usize,
}

async fn page_server_detail(oper: Oper, State(st): State<AppState>, Path(name): Path<String>) -> Html<String> {
    let e = st.engine.lock().await;
    let srv = e.net_servers_detailed().into_iter().find(|s| s.name.eq_ignore_ascii_case(&name));
    drop(e);
    let mut t = ServerDetailTpl {
        chrome: chrome(&st, &oper, "servers"),
        found: false,
        name,
        uplink: String::new(),
        hub: false,
        users: 0,
        opers: 0,
    };
    if let Some(s) = srv {
        t.found = true;
        t.name = s.name;
        t.hub = s.uplink.is_empty();
        t.uplink = s.uplink;
        t.users = s.users;
        t.opers = s.opers;
    }
    html(t)
}

// ---- JSON endpoints ------------------------------------------------------

async fn health(State(st): State<AppState>) -> Response {
    let e = st.engine.lock().await;
    let ok = e.linked();
    let name = e.net_servers_detailed().first().map(|s| s.name.clone()).unwrap_or_else(|| st.brand.clone());
    drop(e);
    axum::Json(json!({ "ok": ok, "name": name })).into_response()
}

// Live counters + event feed for the dashboard. `?since=<ts>` returns only newer
// incidents; `?counts=1` also returns the headline gauges.
async fn live(oper: Oper, State(st): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Response {
    let _ = oper;
    let since: u64 = p.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let want_counts = p.contains_key("counts");
    let e = st.engine.lock().await;
    let counts = if want_counts {
        json!({
            "users": e.net_user_count(),
            "local": e.net_user_count(),
            "channels": e.net_channel_count(),
            "servers": e.net_server_count(),
            "opers": e.net_oper_count(),
            "bans": e.akills().len(),
        })
    } else {
        serde_json::Value::Null
    };
    let incs = e.recent_incidents(80);
    drop(e);
    let mut last_id = since;
    let mut events: Vec<serde_json::Value> = incs
        .into_iter()
        .filter(|i| i.ts > since)
        .map(|i| {
            last_id = last_id.max(i.ts);
            json!({ "timestamp": i.ts, "subsystem": classify(&i.summary), "msg": i.summary })
        })
        .collect();
    // oldest-first so the client prepends newest to the top.
    events.reverse();
    let mut body = json!({ "events": events, "last_id": last_id });
    if want_counts {
        body["counts"] = counts;
    }
    axum::Json(body).into_response()
}

// Global topbar search over the live network + ban store.
async fn search(oper: Oper, State(st): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Response {
    let _ = oper;
    let q = p.get("q").cloned().unwrap_or_default().to_lowercase();
    if q.len() < 2 {
        return axum::Json(json!({})).into_response();
    }
    let e = st.engine.lock().await;
    let users: Vec<serde_json::Value> = e
        .net_users_detailed()
        .into_iter()
        .filter(|u| u.nick.to_lowercase().contains(&q) || u.account.to_lowercase().contains(&q))
        .take(6)
        .map(|u| json!({ "name": u.nick, "info": if u.account.is_empty() { u.host } else { u.account } }))
        .collect();
    let channels: Vec<serde_json::Value> = e
        .net_channels_detailed()
        .into_iter()
        .filter(|c| c.name.to_lowercase().contains(&q))
        .take(6)
        .map(|c| json!({ "name": c.name, "info": format!("{} membres", c.users) }))
        .collect();
    let servers: Vec<serde_json::Value> = e
        .net_servers_detailed()
        .into_iter()
        .filter(|s| s.name.to_lowercase().contains(&q))
        .take(6)
        .map(|s| json!({ "name": s.name, "info": format!("{} users", s.users) }))
        .collect();
    let bans: Vec<serde_json::Value> = e
        .akills()
        .into_iter()
        .filter(|b| b.mask.to_lowercase().contains(&q))
        .take(6)
        .map(|b| json!({ "name": b.mask, "info": b.reason }))
        .collect();
    drop(e);
    axum::Json(json!({ "users": users, "channels": channels, "servers": servers, "bans": bans })).into_response()
}

// Structured event log for the logs page (incidents as level/subsystem rows).
async fn logs_events(oper: Oper, State(st): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Response {
    let _ = oper;
    let since: u64 = p.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let e = st.engine.lock().await;
    let incs = e.recent_incidents(500);
    drop(e);
    let mut last_id = since;
    let mut events: Vec<serde_json::Value> = incs
        .into_iter()
        .filter(|i| i.ts > since)
        .map(|i| {
            last_id = last_id.max(i.ts);
            let kind = classify(&i.summary);
            let level = if kind == "mod" { "warn" } else { "info" };
            json!({ "timestamp": i.ts * 1000, "subsystem": kind, "event_id": i.id, "msg": i.summary, "level": level })
        })
        .collect();
    events.reverse();
    axum::Json(json!({ "events": events, "last_id": last_id })).into_response()
}

// Plain-text tail for the logs page (recent incident summaries).
async fn logs_tail(oper: Oper, State(st): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Response {
    let _ = oper;
    let lines: usize = p.get("lines").and_then(|s| s.parse().ok()).unwrap_or(300);
    let e = st.engine.lock().await;
    let incs = e.recent_incidents(lines);
    drop(e);
    let out: Vec<String> = incs
        .into_iter()
        .rev()
        .map(|i| format!("[{}] {} {}", tmpl::fmt_dt(i.ts), i.id, i.summary))
        .collect();
    axum::Json(json!({ "lines": out })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template;

    fn ch(active: &'static str) -> Chrome {
        Chrome { brand: "t".into(), active, username: "root".into(), is_root: true, can_audit: true, version: "0" }
    }

    #[test]
    fn all_pages_render() {
        assert!(DashboardTpl {
            chrome: ch("dashboard"), net_name: "irc.a".into(), version: "0",
            users: 5, local: 5, opers: 1, channels: 2, servers: 1, bans: 0,
            server_cards: vec![SrvCard { name: "irc.a".into(), uplink: String::new(), hub: true, users: 5, opers: 1, pct: 100 }],
            chan_ranks: vec![ChanRank { name: "#a".into(), slug: "%23a".into(), topic: "hi".into(), users: 3, pct: 100 }],
        }.render().unwrap().contains("irc.a"));

        assert!(UsersTpl {
            chrome: ch("users"), total: 1, accounts: 1, guests: 0, opers: 1,
            rows: vec![URow { nick: "bob".into(), slug: "bob".into(), ident: "b".into(), host: "h".into(), ip: "1.2.3.4".into(), account: "bob".into(), has_account: true, is_oper: true, operclass: "netadmin".into(), modes: "iox".into(), server: "irc.a".into(), secure: true }],
        }.render().unwrap().contains("bob"));

        assert!(ChannelsTpl {
            chrome: ch("channels"), total: 1, registered: 1, moderated: 0, members: 3,
            rows: vec![CRow { name: "#a".into(), slug: "%23a".into(), topic: "hi".into(), users: 3, modes: "nt".into(), secret: false, private: false, inviteonly: false, keyed: false, moderated: false, registered: true, pct: 100 }],
        }.render().unwrap().contains("#a"));

        assert!(ServersTpl { chrome: ch("servers"), count: 1, users: 5, opers: 1, hub_name: "irc.a".into(), tree_html: "<li>irc.a</li>".into(), rows: vec![SRow { name: "irc.a".into(), uplink: String::new(), hub: true, users: 5, opers: 1 }] }.render().unwrap().contains("irc.a"));

        let pr = || vec![PRow { kind: "G".into(), mask: "*@bad".into(), reason: "spam".into(), set_by: "op".into(), set_ago: "1j".into(), expires: "permanent".into(), perm: true }];
        assert!(BansTpl { chrome: ch("bans"), rows: pr(), total: 1, perm: 1, heading: "Bans", subtitle: "s", empty: "none" }.render().unwrap().contains("*@bad"));
        assert!(SpamTpl { chrome: ch("spamfilter"), total: 1, rows: vec![FRow { pattern: "*evil*".into(), action: "block".into(), flags: "*".into(), reason: "x".into(), set_ago: "1j".into() }] }.render().unwrap().contains("evil"));
        assert!(SecGroupsTpl { chrome: ch("security_groups") }.render().is_ok());
        assert!(OpersTpl { chrome: ch("opers"), rows: vec![ORow { name: "root".into(), tier: "root".into(), online: 1 }] }.render().unwrap().contains("root"));
        assert!(RegTpl { chrome: ch("registrations"), total: 1, reg_24h: 1, reg_7d: 1, verified: 1, pending: 0, days: vec![(0u32, 0u64); 14], recent: vec![REvt { when: "01/01".into(), user: "bob".into(), email: "b@x".into(), verified: true }] }.render().unwrap().contains("bob"));
        assert!(ModulesTpl { chrome: ch("modules"), rows: vec!["m_x".into()], total: 1 }.render().unwrap().contains("m_x"));
        assert!(AuditTpl { chrome: ch("audit"), total: 1, rows: vec![AuditRow { when: "01/01".into(), ago: "1j".into(), id: "AB12".into(), summary: "did a thing".into(), kind: "log" }] }.render().unwrap().contains("did a thing"));
        assert!(WhowasTpl { chrome: ch("whowas"), q: String::new(), rows: vec![] }.render().is_ok());
        assert!(IpWhoisTpl { chrome: ch("ip_whois"), q: String::new(), ip: String::new(), users: vec![], bans: vec![] }.render().is_ok());
        assert!(LogsTpl { chrome: ch("logs") }.render().is_ok());
        assert!(AccessTpl { chrome: ch("access"), grants: vec![GrantRow { name: "root".into(), tier: "root".into(), perms: vec!["admin".into()], expires: "permanent".into() }], total: 1 }.render().unwrap().contains("root"));
        assert!(TrendsTpl { chrome: ch("trends"), users: 5, channels: 2, servers: 1, opers: 1 }.render().is_ok());
        assert!(UserDetailTpl { chrome: ch("users"), found: true, initial: "B".into(), nick: "bob".into(), ident: "b".into(), host: "h".into(), ip: "1.2.3.4".into(), gecos: "Bob".into(), account: "bob".into(), is_oper: false, operclass: String::new(), modes: "ix".into(), server: "irc.a".into(), secure: true, channels: vec![UChan { name: "#a".into(), slug: "%23a".into(), prefix: "@" }], registered: true, email: "b@x".into(), verified: true, joined: "01/01/2026".into() }.render().unwrap().contains("bob"));
        assert!(ChannelDetailTpl { chrome: ch("channels"), found: true, name: "#a".into(), topic: "hi".into(), topic_setter: "bob".into(), users: 1, modes: "nt".into(), secret: false, private: false, inviteonly: false, keyed: false, moderated: false, registered: true, members: vec![CMember { nick: "bob".into(), slug: "bob".into(), prefix: "@", account: "bob".into(), is_oper: false }] }.render().unwrap().contains("#a"));
        assert!(ServerDetailTpl { chrome: ch("servers"), found: true, name: "irc.a".into(), uplink: String::new(), hub: true, users: 5, opers: 1 }.render().unwrap().contains("irc.a"));
    }
}
