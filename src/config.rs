use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub uplink: Uplink,
    pub server: Server,
    // Node-to-node replication. Absent = single node, no gossip.
    #[serde(default)]
    pub gossip: Option<Gossip>,
    #[serde(default)]
    pub peer: Vec<Peer>,
    // Outbound email (password resets). Absent = email features are off.
    #[serde(default)]
    pub email: Option<Email>,
    // Directory replication (gRPC), for websites mirroring the account/channel
    // directory. Absent = the RPC server does not start.
    #[serde(default)]
    pub grpc: Option<Grpc>,
    // JSON-RPC stats endpoint (plain HTTP+JSON) for a website's stats pages.
    // Absent = it does not start. Bind to localhost; a token is required.
    #[serde(default)]
    pub jsonrpc: Option<JsonRpc>,
    // Liveness + Prometheus metrics endpoint (plain HTTP). Absent = it does not
    // start. Bind to localhost; unauthenticated by design (read-only gauges).
    #[serde(default)]
    pub health: Option<Health>,
    // Web admin panel (plain HTTP; put it behind a TLS reverse proxy). Absent =
    // it does not start. Staff log in with their echo account; only operators
    // may enter, and each action is gated by their oper tier.
    #[serde(default)]
    pub panel: Option<Panel>,
    // Localization. Absent = English only. `default` is the reply language for
    // users with no preference; `dir` holds `<code>.json` catalogs; `available`
    // lists the codes a user may pick with NickServ SET LANGUAGE.
    #[serde(default)]
    pub language: Option<Language>,
    // Which service modules to start. Absent = the full standard suite (all the
    // pseudo-clients); listing it trims that set. Every service is first-class.
    #[serde(default)]
    pub modules: Modules,
    // Services operators: accounts granted privileges. Absent = no opers.
    #[serde(default)]
    pub oper: Vec<Oper>,
    // Staff audit feed. Absent = no audit log is emitted.
    #[serde(default)]
    pub log: Option<Log>,
    // Inactivity-expiry. Absent = accounts and channels never expire.
    #[serde(default)]
    pub expire: Option<Expire>,
    // Per-IP session limiting. Absent = unlimited.
    #[serde(default)]
    pub session: Option<Session>,
    // Account authority. Absent = built-in (echo owns accounts). With
    // `external = true`, an outside authority (e.g. the website) owns identity
    // and pushes accounts in; IRC can only authenticate.
    #[serde(default)]
    pub auth: Option<Auth>,
    // Website single-use keycards (passwordless web login). Absent = keycard
    // credentials (`kc_…` over SASL) are not honoured.
    #[serde(default)]
    pub keycard: Option<Keycard>,
    // DictServ dictionary lookups (dict.org / RFC 2229). Absent = the service does
    // not load and echo makes no outbound lookup requests. Opt-in on purpose.
    #[serde(default)]
    pub dictserv: Option<Dict>,
    // Registration policy. Absent = defaults (the look-alike guard is on).
    #[serde(default)]
    pub register: Register,
    // Which InspIRCd matching-extbans AKICK may use. Absent = every extban echo
    // knows (full compatibility). List `enabled` to restrict it — e.g. drop the
    // ones your ircd doesn't provide.
    #[serde(default)]
    pub extban: Option<Extban>,
    // Native anti-abuse engine (connection/flood/pattern screening). Absent, or
    // enabled=false, = the subsystem is inert; report_only=true (the default when
    // enabled) reports detections to the log channel without enforcing. Every
    // threshold is a config key with a literal default.
    #[serde(default)]
    pub security: Option<Security>,
    // Registration MX-blacklist: reject signups whose email domain's mail servers
    // (MX → A/AAAA) match a hostname glob or IP CIDR — the stable way to stop
    // disposable-email abuse. Absent = off. Native DNS, no external service.
    #[serde(default)]
    pub mxbl: Option<MxBlocklist>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Security {
    // Master switch. false (default) = the anti-abuse engine does nothing at all.
    #[serde(default)]
    pub enabled: bool,
    // When true (the default), detections are only announced to the log channel,
    // never enforced. Run this way until the thresholds are trusted, then set it
    // false to arm kills/bans.
    #[serde(default = "sec_true")]
    pub report_only: bool,
    // Connection screening (per-IP / per-range connection floods).
    #[serde(default)]
    pub connect: ConnectRules,
    // IPs/CIDRs never screened or banned — trusted infrastructure (loopback, the
    // services host, gateways). Defaults to loopback so arming can't cut off the
    // local bots/services link. Bare IP = exact match; "a.b.c.0/24" / "2001:db8::/32".
    #[serde(default = "sec_exempt_ips")]
    pub exempt_ips: Vec<String>,
    // Connection pattern rules: each connecting nick!ident@host(#gecos) is matched
    // against these (globs by default, regex opt-in). A hit is reported (or, when
    // armed, killed + G-lined). The native equivalent of the ozone/Sigyn pattern DB.
    #[serde(default)]
    pub pattern: Vec<Pattern>,
    // Behavioural heuristics on join/part/quit/nick events (cycle, join-spam-part,
    // broken-client quit flood, mass-join, nick-change flood).
    #[serde(default)]
    pub behavior: BehaviorRules,
    // Content heuristics on channel messages echo sees (a bot is present) — the
    // additive ones the kickers don't do: highlight-spam (mass-ping).
    #[serde(default)]
    pub content: ContentRules,
    // Never screen network operators (staff). Default on.
    #[serde(default = "sec_true")]
    pub exempt_opers: bool,
    // Never screen users logged into an account. Default OFF — a compromised
    // account can still spam.
    #[serde(default)]
    pub exempt_accounts: bool,
    // For content checks, never screen a voiced/opped channel member. Default on.
    #[serde(default = "sec_true")]
    pub exempt_voice: bool,
    // Staff-feed alert rate-limit: at most announce_permit SECURITY alerts to the
    // log channel per announce_life s, so a sustained flood can't spam it. (Only the
    // announcement is throttled — enforcement still runs on every trigger.)
    #[serde(default = "sec_ann_permit")]
    pub announce_permit: u32,
    #[serde(default = "sec_ann_life")]
    pub announce_life: u64,
    // Abuse cascade: > cascade_permit total triggers within cascade_life s raises a
    // one-shot "consider raising DEFCON" alert.
    #[serde(default = "sec_casc_permit")]
    pub cascade_permit: u32,
    #[serde(default = "sec_casc_life")]
    pub cascade_life: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConnectRules {
    #[serde(default = "sec_true")]
    pub enabled: bool,
    // More than `flood_permit` connections from one IP within `flood_life`
    // seconds trips a connection-flood.
    #[serde(default = "sec_conn_permit")]
    pub flood_permit: u32,
    #[serde(default = "sec_conn_life")]
    pub flood_life: u64,
    // The same, aggregated over the IP's /24 (v4) or /64 (v6) — catches clone
    // floods spread across a subnet.
    #[serde(default = "sec_range_permit")]
    pub range_permit: u32,
    #[serde(default = "sec_range_life")]
    pub range_life: u64,
    // Seconds the auto network-ban lasts when armed; 0 = kill the connection only.
    #[serde(default = "sec_conn_ban")]
    pub ban_duration: u64,
}

impl Default for ConnectRules {
    fn default() -> Self {
        Self {
            enabled: sec_true(),
            flood_permit: sec_conn_permit(),
            flood_life: sec_conn_life(),
            range_permit: sec_range_permit(),
            range_life: sec_range_life(),
            ban_duration: sec_conn_ban(),
        }
    }
}

fn sec_true() -> bool {
    true
}
fn sec_conn_permit() -> u32 {
    6
}
fn sec_conn_life() -> u64 {
    10
}
fn sec_range_permit() -> u32 {
    12
}
fn sec_range_life() -> u64 {
    20
}
fn sec_conn_ban() -> u64 {
    3600
}

#[derive(Debug, Deserialize, Clone)]
pub struct Pattern {
    // The glob (default) or regex to match. Globs use `*`/`?`; matching is
    // case-insensitive either way.
    pub mask: String,
    // Which part of the connecting identity to test: "mask" (nick!ident@host,
    // default), "full" (nick!ident@host#gecos), "nick", "ident", "host", "gecos".
    #[serde(default = "pat_field")]
    pub field: String,
    // Treat `mask` as a regular expression instead of a glob.
    #[serde(default)]
    pub regex: bool,
    // Shown in the alert and used as the ban reason.
    #[serde(default = "pat_reason")]
    pub reason: String,
    // Seconds the G-line lasts when armed (0 = kill the connection only).
    #[serde(default = "sec_conn_ban")]
    pub ban: u64,
}

fn sec_exempt_ips() -> Vec<String> {
    vec!["127.0.0.0/8".to_string(), "::1".to_string()]
}
fn pat_field() -> String {
    "mask".to_string()
}
fn pat_reason() -> String {
    "matched a security pattern".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct BehaviorRules {
    #[serde(default = "sec_true")]
    pub enabled: bool,
    // Nick-change flood: > nick_permit changes from one user within nick_life s.
    #[serde(default = "sec_nick_permit")]
    pub nick_permit: u32,
    #[serde(default = "sec_nick_life")]
    pub nick_life: u64,
    // Join/part cycling: > cycle_permit parts from one user within cycle_life s.
    #[serde(default = "sec_cycle_permit")]
    pub cycle_permit: u32,
    #[serde(default = "sec_cycle_life")]
    pub cycle_life: u64,
    // Join-spam-part: > joinpart_permit parts each within joinpart_grace s of the
    // join, counted over joinpart_life s.
    #[serde(default = "sec_joinpart_permit")]
    pub joinpart_permit: u32,
    #[serde(default = "sec_joinpart_life")]
    pub joinpart_life: u64,
    #[serde(default = "sec_joinpart_grace")]
    pub joinpart_grace: u64,
    // Mass-join: > massjoin_permit joins to one channel from a single /24 (v4) /
    // /64 (v6) within massjoin_life s — the clone-raid signal.
    #[serde(default = "sec_massjoin_permit")]
    pub massjoin_permit: u32,
    #[serde(default = "sec_massjoin_life")]
    pub massjoin_life: u64,
    // Broken-client quit flood: > quit_permit quits whose reason contains one of
    // `quit_reasons` from one IP within quit_life s.
    #[serde(default = "sec_quit_permit")]
    pub quit_permit: u32,
    #[serde(default = "sec_quit_life")]
    pub quit_life: u64,
    #[serde(default = "sec_quit_reasons")]
    pub quit_reasons: Vec<String>,
    // Seconds the auto G-line lasts when armed (0 = kill the connection only).
    #[serde(default = "sec_conn_ban")]
    pub ban_duration: u64,
}

impl Default for BehaviorRules {
    fn default() -> Self {
        Self {
            enabled: sec_true(),
            nick_permit: sec_nick_permit(),
            nick_life: sec_nick_life(),
            cycle_permit: sec_cycle_permit(),
            cycle_life: sec_cycle_life(),
            joinpart_permit: sec_joinpart_permit(),
            joinpart_life: sec_joinpart_life(),
            joinpart_grace: sec_joinpart_grace(),
            massjoin_permit: sec_massjoin_permit(),
            massjoin_life: sec_massjoin_life(),
            quit_permit: sec_quit_permit(),
            quit_life: sec_quit_life(),
            quit_reasons: sec_quit_reasons(),
            ban_duration: sec_conn_ban(),
        }
    }
}

fn sec_nick_permit() -> u32 {
    5
}
fn sec_nick_life() -> u64 {
    30
}
fn sec_cycle_permit() -> u32 {
    6
}
fn sec_cycle_life() -> u64 {
    20
}
fn sec_joinpart_permit() -> u32 {
    4
}
fn sec_joinpart_life() -> u64 {
    30
}
fn sec_joinpart_grace() -> u64 {
    10
}
fn sec_massjoin_permit() -> u32 {
    8
}
fn sec_massjoin_life() -> u64 {
    8
}
fn sec_quit_permit() -> u32 {
    4
}
fn sec_quit_life() -> u64 {
    30
}
fn sec_quit_reasons() -> Vec<String> {
    vec!["Excess Flood".to_string(), "Max SendQ exceeded".to_string()]
}

#[derive(Debug, Deserialize, Clone)]
pub struct ContentRules {
    #[serde(default = "sec_true")]
    pub enabled: bool,
    // A single message that mentions >= highlight_nicks distinct channel members
    // (each nick at least highlight_min_len chars, to skip trivial nicks) is a
    // highlight-spam (mass-ping) message.
    #[serde(default = "sec_hl_nicks")]
    pub highlight_nicks: u32,
    #[serde(default = "sec_hl_min_len")]
    pub highlight_min_len: u32,
    // > highlight_permit such messages from one user within highlight_life s trips.
    #[serde(default = "sec_hl_permit")]
    pub highlight_permit: u32,
    #[serde(default = "sec_hl_life")]
    pub highlight_life: u64,
    // Bad-unicode: a message of at least badunicode_min chars whose combining-mark /
    // invisible-char fraction reaches badunicode_score (zalgo, zero-width injection),
    // more than badunicode_permit times within badunicode_life s.
    #[serde(default = "sec_bu_score")]
    pub badunicode_score: f64,
    #[serde(default = "sec_bu_min")]
    pub badunicode_min: u32,
    #[serde(default = "sec_bu_permit")]
    pub badunicode_permit: u32,
    #[serde(default = "sec_bu_life")]
    pub badunicode_life: u64,
    // Repeat-wave: the same normalised line of at least repeat_min chars posted more
    // than repeat_permit times in a channel within repeat_life s (copy-paste spam);
    // the offending line is surfaced in the alert as a suggested filter pattern.
    #[serde(default = "sec_rpt_min")]
    pub repeat_min: u32,
    #[serde(default = "sec_rpt_permit")]
    pub repeat_permit: u32,
    #[serde(default = "sec_rpt_life")]
    pub repeat_life: u64,
    // Seconds the auto G-line lasts when armed (0 = kill the connection only).
    #[serde(default = "sec_conn_ban")]
    pub ban_duration: u64,
}

impl Default for ContentRules {
    fn default() -> Self {
        Self {
            enabled: sec_true(),
            highlight_nicks: sec_hl_nicks(),
            highlight_min_len: sec_hl_min_len(),
            highlight_permit: sec_hl_permit(),
            highlight_life: sec_hl_life(),
            badunicode_score: sec_bu_score(),
            badunicode_min: sec_bu_min(),
            badunicode_permit: sec_bu_permit(),
            badunicode_life: sec_bu_life(),
            repeat_min: sec_rpt_min(),
            repeat_permit: sec_rpt_permit(),
            repeat_life: sec_rpt_life(),
            ban_duration: sec_conn_ban(),
        }
    }
}

fn sec_hl_nicks() -> u32 {
    6
}
fn sec_hl_min_len() -> u32 {
    3
}
fn sec_hl_permit() -> u32 {
    1
}
fn sec_hl_life() -> u64 {
    15
}
fn sec_bu_score() -> f64 {
    0.30
}
fn sec_bu_min() -> u32 {
    8
}
fn sec_bu_permit() -> u32 {
    1
}
fn sec_bu_life() -> u64 {
    20
}
fn sec_rpt_min() -> u32 {
    10
}
fn sec_rpt_permit() -> u32 {
    5
}
fn sec_rpt_life() -> u64 {
    20
}
fn sec_ann_permit() -> u32 {
    8
}
fn sec_ann_life() -> u64 {
    10
}
fn sec_casc_permit() -> u32 {
    15
}
fn sec_casc_life() -> u64 {
    30
}

#[derive(Debug, Deserialize, Clone)]
pub struct MxBlocklist {
    // Master switch (default off — opt-in).
    #[serde(default)]
    pub enabled: bool,
    // Recursive DNS resolver "ip[:port]". Empty = the first nameserver in
    // /etc/resolv.conf (falling back to systemd-resolved's 127.0.0.53).
    #[serde(default)]
    pub resolver: String,
    // MX hostname globs to block (e.g. "*.disposable-mail.example").
    #[serde(default)]
    pub mx_globs: Vec<String>,
    // MX-server IP CIDRs to block (e.g. "203.0.113.0/24"). Only consulted when set,
    // since matching them costs an extra A/AAAA lookup per mail server.
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    // Per-DNS-query timeout, milliseconds.
    #[serde(default = "mxbl_timeout")]
    pub timeout_ms: u64,
}

fn mxbl_timeout() -> u64 {
    2000
}

#[derive(Debug, Deserialize, Clone)]
pub struct Language {
    // Reply language for users who haven't picked one (a code like "en" or "fr").
    #[serde(default = "default_language")]
    pub default: String,
    // Directory holding the `<code>.json` translation catalogs (english id -> text).
    #[serde(default = "default_language_dir")]
    pub dir: String,
    // Codes a user may select with NickServ SET LANGUAGE. Empty = only the default.
    #[serde(default)]
    pub available: Vec<String>,
}

fn default_language() -> String {
    "en".to_string()
}

fn default_language_dir() -> String {
    "lang".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct Extban {
    // Enabled extban names ("account", "realname", "country", …). Empty = all.
    #[serde(default)]
    pub enabled: Vec<String>,
}

// Redeeming a website login keycard: a member already authenticated on the
// website connects with a one-time `kc_…` token instead of their password. We
// hand it to Django's localhost login-token endpoint, which redeems it and
// confirms the account. `url` is that endpoint; `api_key` matches its X-API-Key.
#[derive(Debug, Deserialize, Clone)]
pub struct Keycard {
    pub url: String,
    pub api_key: String,
}

// DictServ. `server` is a DICT-protocol endpoint (RFC 2229); dict.org hosts the
// standard databases (WordNet, GCIDE, thesaurus, …).
#[derive(Debug, Deserialize, Clone)]
pub struct Dict {
    #[serde(default = "default_dict_server")]
    pub server: String,
}

fn default_dict_server() -> String {
    "dict.org:2628".to_string()
}

// Registration policy.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct Register {
    // Reject look-alike / mixed-script / invisible registration names. On by
    // default; turn it off for a community that legitimately uses mixed or
    // non-Latin names. Reloadable with REHASH.
    pub confusable_check: bool,
    // Invite-only registration: a new account stays pending until an existing
    // member vouches for it (NickServ VOUCH), instead of confirming by email.
    // Off by default. Reloadable with REHASH.
    #[serde(default)]
    pub vouch: bool,
}

impl Default for Register {
    fn default() -> Self {
        Self { confusable_check: true, vouch: false }
    }
}

// Account-authority configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct Auth {
    #[serde(default)]
    pub external: bool,
}

// Session limiting: the default connections allowed per IP (0/absent = off),
// which OperServ EXCEPTION entries can raise or lower per IP-mask.
#[derive(Debug, Deserialize, Clone)]
pub struct Session {
    #[serde(default)]
    pub default_limit: u32,
}

impl Session {
    pub fn limit(&self) -> Option<u32> {
        (self.default_limit > 0).then_some(self.default_limit)
    }
}

// Inactivity-expiry thresholds, in days. A zero (or omitted) field leaves that
// kind never expiring, so an operator can expire only accounts, only channels,
// or both.
#[derive(Debug, Deserialize, Clone)]
pub struct Expire {
    #[serde(default)]
    pub accounts_days: u64,
    #[serde(default)]
    pub channels_days: u64,
    // Days before expiry to email a warning to the owner (0 = no warning email).
    #[serde(default)]
    pub warn_days: u64,
}

impl Expire {
    // The thresholds in seconds, or None where that kind is disabled (zero days).
    pub fn account_ttl(&self) -> Option<u64> {
        (self.accounts_days > 0).then(|| self.accounts_days.saturating_mul(86_400))
    }
    pub fn channel_ttl(&self) -> Option<u64> {
        (self.channels_days > 0).then(|| self.channels_days.saturating_mul(86_400))
    }
    // The warning lead time in seconds, or None if warnings are off.
    pub fn warn_ttl(&self) -> Option<u64> {
        (self.warn_days > 0).then(|| self.warn_days.saturating_mul(86_400))
    }
}

// The staff audit feed: notable service actions are announced to this channel
// so operators can see who did what.
#[derive(Debug, Deserialize, Clone)]
pub struct Log {
    pub channel: String,
    // Masks NOTIFY never announces, three kinds: `#channel` mutes that channel,
    // `server:<glob>` (or `via:`) mutes everyone on a matching server — the handle
    // on a relay whose users have clean nicks — and any other mask (nick glob /
    // user@host / extban) mutes a user. E.g. "*/*" silences PyLink relays that
    // suffix nicks, "server:chatnova.relay" a relay that doesn't, "#staff" keeps a
    // broad `#*` watch out of a channel. Reloadable with REHASH.
    #[serde(default)]
    pub notify_exclude: Vec<String>,
}

// One services operator: an account and the privileges it holds.
#[derive(Debug, Deserialize, Clone)]
pub struct Oper {
    pub account: String,
    #[serde(default)]
    pub privs: Vec<String>, // fine-grained: auspex, oper, suspend, admin, root
    // A tier shortcut: "operator", "administrator", or "root" — expands to the
    // matching privilege (which implies the lower tiers). Combined with `privs`.
    #[serde(default, rename = "type")]
    pub oper_type: Option<String>,
}

impl Oper {
    // Every privilege-name granted, from both the `type` shortcut and the explicit
    // `privs` list.
    fn all_priv_names(&self) -> Vec<String> {
        let mut names = self.privs.clone();
        if let Some(t) = &self.oper_type {
            names.push(t.clone());
        }
        names
    }
}

impl Config {
    // The account -> privileges table (casefolded keys) built from [[oper]].
    pub fn opers(&self) -> std::collections::HashMap<String, echo_api::Privs> {
        let mut map = std::collections::HashMap::new();
        for o in &self.oper {
            map.insert(o.account.to_ascii_lowercase(), echo_api::Privs::from_names(&o.all_priv_names()));
        }
        map
    }

    // (account, unrecognised-privilege-name) pairs across all [[oper]] blocks, so
    // the caller can warn about a typo that would otherwise silently grant nothing.
    pub fn oper_priv_warnings(&self) -> Vec<(String, String)> {
        self.oper
            .iter()
            .flat_map(|o| {
                let (_, unknown) = echo_api::Privs::parse_names(&o.all_priv_names());
                unknown.into_iter().map(move |name| (o.account.clone(), name))
            })
            .collect()
    }
}

// The service modules to bring up at burst. Each name maps to a compiled-in
// module crate the daemon knows how to construct (see main.rs). Names not built
// in are ignored.
#[derive(Debug, Deserialize)]
pub struct Modules {
    #[serde(default = "default_services")]
    pub services: Vec<String>,
}

impl Default for Modules {
    fn default() -> Self {
        Modules { services: default_services() }
    }
}

// The full standard suite: every pseudo-client is a first-class service and
// comes up by default. An admin trims the list; there is no second tier.
fn default_services() -> Vec<String> {
    [
        "nickserv", "chanserv", "botserv", "hostserv", "memoserv", "operserv", "statserv",
        "groupserv", "infoserv", "reportserv", "helpserv", "chanfix", "diceserv", "gameserv", "debugserv",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Debug, Deserialize, Clone)]
pub struct Grpc {
    // Address to accept client connections on, e.g. "127.0.0.1:50051".
    pub bind: String,
    // Bearer token every RPC must present (`authorization: Bearer <token>`).
    pub token: String,
    // Optional server-side TLS (no client cert required, unlike gossip's mTLS —
    // a subscriber is a website backend, not a federation peer).
    #[serde(default)]
    pub tls: Option<ServerTls>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerTls {
    pub cert: String, // certificate chain (PEM)
    pub key: String,  // private key (PEM)
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonRpc {
    // Address to accept HTTP on, e.g. "127.0.0.1:5601". Keep it on localhost and
    // let a reverse proxy terminate TLS / HTTP-2 / HTTP-3.
    pub bind: String,
    // Bearer token every request must present (`authorization: Bearer <token>`).
    pub token: String,
    // Browser origins allowed to call this cross-site (CORS), e.g.
    // ["https://tchatou.fr", "https://swaygo.fr"]. Empty = no browser access.
    #[serde(default)]
    pub origins: Vec<String>,
    // Terminate TLS here (enabling HTTP/2). Absent = plain HTTP, for when a
    // reverse proxy does TLS. Reuses the same cert/key shape as [grpc].
    #[serde(default)]
    pub tls: Option<ServerTls>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Health {
    // Address to accept HTTP on, e.g. "127.0.0.1:9099". Keep it on localhost:
    // the endpoint is unauthenticated and serves read-only gauges for a monitor
    // (Prometheus scrape of /metrics, or /health for a liveness probe).
    pub bind: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Panel {
    // Address to accept HTTP on, e.g. "127.0.0.1:9100". Serve it through a TLS
    // reverse proxy — the session cookie and passwords must not cross plain HTTP.
    pub bind: String,
    // Network name shown in the panel header. Defaults to the server name.
    #[serde(default)]
    pub brand: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Email {
    // Sender address stamped on outgoing mail.
    pub from: String,
    // A shell command the message is piped to on stdin, e.g. "sendmail -t" or
    // "msmtp -t". Run via `sh -c`, so redirection and pipes work.
    pub command: String,
    // Display name shown in email templates (header/footer).
    #[serde(default = "default_brand")]
    pub brand: String,
    // Accent colour (any CSS colour) for the email template.
    #[serde(default = "default_accent")]
    pub accent: String,
    // Optional logo image URL shown in the email header (must be a hosted image;
    // email clients don't render inline SVG or data URIs).
    #[serde(default)]
    pub logo: String,
    // Optional base URL of a web endpoint that confirms an account from a code,
    // e.g. "https://example.net/confirm". When set, confirmation emails include a
    // one-click link (`<url>?account=<name>&code=<code>`) alongside the CONFIRM
    // command; the endpoint calls the gRPC Confirm RPC.
    #[serde(default)]
    pub confirm_url: String,
}

fn default_brand() -> String {
    "Network Services".to_string()
}

fn default_accent() -> String {
    "#4f46e5".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct Gossip {
    // Address to accept peer connections on. Absent = dial-only node.
    pub bind: Option<String>,
    // Shared secret both nodes must present.
    pub secret: String,
    // Mutual-TLS for the peer link. Absent = plaintext.
    #[serde(default)]
    pub tls: Option<Tls>,
    // Tier C per-origin signing (see docs/federation.md). Absent = flat trust.
    #[serde(default)]
    pub signing: Option<Signing>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Signing {
    // This node's base64 Ed25519 secret key (from `echo --gen-gossip-key`).
    pub key: String,
    // origin SID -> its base64 Ed25519 public key. Include your own SID plus each peer's.
    #[serde(default)]
    pub trust: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Tls {
    pub cert: String, // our certificate chain (PEM)
    pub key: String,  // our private key (PEM)
    pub ca: String,   // CA bundle that must have signed a peer's certificate (PEM)
}

#[derive(Debug, Deserialize, Clone)]
pub struct Peer {
    pub addr: String,
    // TLS server name to expect from this peer; must match its certificate.
    #[serde(default = "default_peer_name")]
    pub name: String,
}

fn default_peer_name() -> String {
    "echo".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Uplink {
    pub host: String,
    pub port: u16,
    pub password: String,
    // Connect to the uplink over TLS, authenticated by pinning the server's SPKI
    // fingerprint (base64 SHA256 of its SubjectPublicKeyInfo) rather than a CA — the
    // link cert is typically self-signed. Off by default (plaintext, e.g. loopback).
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub spki_fingerprint: String,
}

#[derive(Debug, Deserialize)]
pub struct Server {
    pub name: String,
    pub sid: String,
    pub description: String,
    #[serde(default = "default_protocol")]
    pub protocol: u32,
    // PBKDF2 cost baked into new SCRAM verifiers at registration. High by
    // default for offline-attack resistance; lower it if registration latency
    // on the single-threaded link matters more than verifier strength.
    #[serde(default = "default_scram_iterations")]
    pub scram_iterations: u32,
    // Nick prefix a user is renamed to on NickServ LOGOUT (they keep the ircd's
    // guest number appended, e.g. Guest12345). Must start with a letter — the
    // ircd rejects a digit-leading SVSNICK and falls back to the raw uuid.
    #[serde(default = "default_guest_nick")]
    pub guest_nick: String,
    // Hostname the service pseudo-clients wear (NickServ!services@<here>). Empty
    // falls back to the server name, so NickServ shows as ...@services.tchatou.fr
    // rather than the generic default.
    #[serde(default)]
    pub service_host: String,
    // User modes the service pseudo-clients (services + bots) are introduced with.
    // Default "iHkB": invisible, hideoper, servprotect (unkillable — needs the
    // services server U-lined), bot. NOT +T (block-CTCP): echo answers CTCP
    // VERSION/PING/TIME/CLIENTINFO itself (and ignores the rest), so a blanket
    // ircd block would only stop those introspection replies. Set per the ircd's
    // loaded modules; add "T" back to have the ircd drop all CTCP instead.
    #[serde(default = "default_service_modes")]
    pub service_modes: String,
    // Oper type the service pseudo-clients are flagged with, so WHOIS shows
    // "is a <this>". Default "Network Service". Empty leaves them non-opers.
    #[serde(default = "default_service_oper_type")]
    pub service_oper_type: String,
    // Channel every service pseudo-client (NickServ, ChanServ, …) joins at
    // startup. Default "#services"; empty leaves them out of any channel.
    #[serde(default = "default_services_channel")]
    pub services_channel: String,
    // Emit IRCv3 standard replies (FAIL/WARN/NOTE) for service errors instead of
    // plain notices. On by default: echoIRCd re-emits them and degrades to a plain
    // notice for clients that didn't negotiate standard-replies.
    #[serde(default = "default_true")]
    pub standard_replies: bool,
}

fn default_true() -> bool {
    true
}
fn default_services_channel() -> String {
    "#services".to_string()
}

fn default_service_modes() -> String {
    "iHkB".to_string() // invisible, hideoper, servprotect, bot — CTCP handled by echo, not blocked at the ircd
}

fn default_service_oper_type() -> String {
    "Network Service".to_string()
}

fn default_protocol() -> u32 {
    1206 // InspIRCd 4 spanning-tree protocol (1205 = insp3)
}

fn default_guest_nick() -> String {
    "Guest".to_string()
}

fn default_scram_iterations() -> u32 {
    crate::engine::scram::DEFAULT_ITERATIONS
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    // Catch the common misconfigurations up front with a clear message, rather
    // than failing cryptically at link time.
    fn validate(&self) -> anyhow::Result<()> {
        let sid = &self.server.sid;
        if sid.len() != 3 || !sid.chars().all(|c| c.is_ascii_alphanumeric()) {
            anyhow::bail!("server.sid must be exactly 3 alphanumeric characters (got {sid:?})");
        }
        if self.server.name.trim().is_empty() {
            anyhow::bail!("server.name must not be empty");
        }
        if self.uplink.host.trim().is_empty() {
            anyhow::bail!("uplink.host must not be empty");
        }
        // A too-low PBKDF2 cost (notably a stray 0) would silently mint near-plaintext
        // SCRAM verifiers for every new registration; refuse it loudly.
        if self.server.scram_iterations < 1000 {
            anyhow::bail!("server.scram_iterations = {} is too low (use at least 1000; default {})", self.server.scram_iterations, default_scram_iterations());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Oper;
    use echo_api::Priv;

    fn oper(privs: &[&str], oper_type: Option<&str>) -> Oper {
        Oper {
            account: "reverse".into(),
            privs: privs.iter().map(|s| s.to_string()).collect(),
            oper_type: oper_type.map(str::to_string),
        }
    }

    #[test]
    fn oper_type_shortcut_resolves_to_the_tier_it_names() {
        // `type = "root"` must grant the full root privilege set. This is the seam
        // that, if it read the (now empty) `privs` field instead, would silently
        // strip a `type`-only oper of every privilege.
        let privs = echo_api::Privs::from_names(&oper(&[], Some("root")).all_priv_names());
        assert!(privs.has(Priv::Root) && privs.has(Priv::Admin) && privs.has(Priv::Oper) && privs.has(Priv::Auspex));
        assert_eq!(privs.tier(), "Services Root");

        // The tier aliases resolve too, and `type` combines with explicit `privs`.
        let admin = echo_api::Privs::from_names(&oper(&[], Some("administrator")).all_priv_names());
        assert!(admin.has(Priv::Admin) && !admin.has(Priv::Root));
        let combined = echo_api::Privs::from_names(&oper(&["auspex"], Some("suspend")).all_priv_names());
        assert!(combined.contains(Priv::Auspex) && combined.contains(Priv::Suspend));
    }
}
