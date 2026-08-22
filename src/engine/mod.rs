pub mod db;
pub mod scram;
pub mod service;
pub mod state;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::sync::mpsc;

use crate::proto::{AuthThen, NetAction, NetEvent, RegReply};
use db::{Db, LogEntry, NewsKind, RegError};
use scram::Verifier;
use echo_api::Privs;
use service::{Sender, Service, ServiceCtx};
use state::Network;

// SASL mechanisms we offer, strongest first. Advertised to the uplink as the
// `sasl=` capability value (IRCv3 SASL 3.2 mechanism list) and the set we accept.
const SASL_MECHS: &str = "EXTERNAL,SCRAM-SHA-512,SCRAM-SHA-256,PLAIN";

// The in-channel fantasy trigger, e.g. `!op`.
const FANTASY_PREFIX: &str = "!";

// A community vote lapses if it isn't reached within this many seconds.
const VOTE_TTL: u64 = 120;

// A client's base64 response is split into chunks of this length; a chunk
// shorter than this (or a lone "+") marks the end of the response (SASL 3.1).
const MAX_AUTHENTICATE: usize = 400;

// Upper bound on a reassembled response, to cap a pre-auth client's buffer.
const MAX_SASL_RESPONSE: usize = 8 * 1024;

// A client's in-progress SASL exchange.
enum SaslSession {
    // PLAIN: the base64 response reassembled from the uplink's chunks.
    Plain { response: String },
    // SCRAM: which hash, and where we are in the challenge/response.
    Scram { hash: scram::Hash, step: ScramStep },
    // EXTERNAL: the TLS cert fingerprints the ircd relayed for this client.
    External { fingerprints: Vec<String> },
}

// An in-progress exchange with its last-activity stamp, so abandoned sessions
// can be swept. The ircd does not always tell us a mid-SASL client vanished, so
// without this the uid-keyed map would grow without bound (a memory-exhaustion
// DoS: open a connection, send AUTHENTICATE, drop, repeat).
struct TimedSession {
    touched: Instant,
    session: SaslSession,
}

// How long an idle SASL exchange lives before it is swept. A real exchange
// completes in well under a second; each step refreshes the stamp.
const SASL_SESSION_TTL: Duration = Duration::from_secs(60);
// Hard ceiling on concurrent in-progress exchanges, bounding worst-case memory
// under a burst faster than the TTL.
const MAX_SASL_SESSIONS: usize = 4096;

// The SCRAM state advances client-first -> client-final -> ack.
enum ScramStep {
    ClientFirst,
    ClientFinal {
        account: String,
        verifier: Verifier,
        client_first_bare: String,
        server_first: String,
        gs2_header: String,
        nonce: String,
    },
    Ack {
        account: String,
    },
}

// Outcome of an authority-originated account operation (see grpc.rs and the
// `authority_*` methods below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityStatus {
    Ok,
    AlreadyExists,
    NotFound,
    RateLimited,
    Invalid,
    Internal,
}

pub struct Engine {
    services: Vec<Box<dyn Service>>,
    network: Network,
    db: Db,
    sasl_sessions: HashMap<String, TimedSession>, // client uid -> in-progress exchange
    sasl_source: HashMap<String, (Instant, String)>, // client uid -> real host/IP from the SASL H message
    reg_limiter: RegLimiter,
    cmd_limiter: CmdLimiter, // per-host flood control for service commands
    dict_limiter: DictLimiter, // global rate cap on outbound DICT lookups
    chan_service: Option<String>, // uid to source channel modes from (ChanServ)
    nick_service: Option<String>, // uid of the account service (NickServ), for its notices
    irc_out: Option<mpsc::UnboundedSender<NetAction>>, // services-initiated actions -> the uplink
    opers: HashMap<String, Privs>, // casefolded account -> privileges (from [[oper]] config)
    sid: String, // our services SID, for minting bot uids
    // Nick-protection enforcement. `synced` gates it until the uplink's initial
    // burst is done, so a relink doesn't enforce every already-online user.
    synced: bool,
    guest_nick: String, // base for the Guest#### rename on enforcement
    service_host: String, // hostname the service pseudo-clients wear
    service_oper_type: String, // oper type our services are flagged with (WHOIS "is a <this>"); empty = don't oper
    services_channel: String, // channel all service pseudo-clients join at startup; empty = none
    standard_replies: bool, // emit IRCv3 FAIL/WARN/NOTE for service errors; off = degrade to notices
    config_path: String, // path to config.toml, so OperServ REHASH can re-read it live
    enforce_seq: u32,   // counter appended to guest_nick
    pending_enforce: Vec<PendingEnforce>, // registered nicks awaiting identify-or-rename
    bot_uids: HashMap<String, String>, // casefolded bot nick -> live uid (per connection)
    services_signon: u64, // burst time our pseudo-clients signed on, for WHOIS IDLE replies
    bot_idents: HashMap<String, u64>, // casefolded bot nick -> hash of user/host/gecos (to spot BOT CHANGE)
    next_bot_index: u32,
    bot_channels: std::collections::HashSet<(String, String)>, // (bot nick lc, channel) the bot has joined
    // Ephemeral per-channel, per-user chatter tracking for the FLOOD and REPEAT
    // kickers. Only channels with one of those kickers ever get an entry; a
    // user's entry is dropped when they part or quit, so this stays bounded.
    // Keyed by the uplink-canonical channel string (never event-logged).
    chatter: HashMap<String, HashMap<String, ChatterState>>,
    now_override: Option<u64>, // test clock (unix secs); None = real wall time
    // Compiled BADWORDS matchers, one RegexSet per channel, rebuilt lazily when
    // the channel's badword revision changes. A RegexSet matches a line against
    // every pattern in a single linear pass (and the regex crate is backtracking-
    // free, so user patterns can't blow up). Never event-logged.
    badword_cache: HashMap<String, CachedBadwords>,
    // Compiled auto-response TRIGGER matchers, one per channel, rebuilt lazily on
    // a revision change (same scheme as badwords). Never event-logged.
    trigger_cache: HashMap<String, CachedTriggers>,
    // Kicker bans (times-to-ban) awaiting BANEXPIRE removal. Swept on each event.
    pending_unbans: Vec<PendingUnban>,
    // In-flight community !votekick/!voteban tallies, keyed by (channel_lc,
    // target_nick_lc). Ephemeral; expire after VOTE_TTL.
    votes: HashMap<(String, String), VoteState>,
    // Staff audit channel: notable service actions are announced here. None =
    // no audit feed.
    log_channel: Option<String>,
    // DebugServ's uid, when that module is enabled — the live activity feed
    // (auth, sessions, lifecycle) speaks as it. Empty = DebugServ isn't running,
    // and the committed-event feed falls back to a server notice.
    debugserv_uid: String,
    // Inactivity-expiry thresholds in seconds. None = that kind never expires.
    account_ttl: Option<u64>,
    channel_ttl: Option<u64>,
    // How long before expiry to email a warning (seconds). None = no warnings.
    expire_warn: Option<u64>,
    // Default connections allowed per IP. None = session limiting is off.
    session_limit: Option<u32>,
}

struct VoteState {
    ban: bool,
    voters: std::collections::HashSet<String>, // voter uids, one vote each
    started: u64,
}

// A user sitting on a registered nick they haven't identified to. If still
// unidentified on that nick when `deadline` passes, they're renamed to a guest.
struct PendingEnforce {
    uid: String,
    nick: String, // the registered nick they must identify to (lowercased account)
    deadline: u64, // unix secs
}

// How long a user has to identify to a registered nick before being renamed.
const ENFORCE_GRACE: u64 = 60;

struct CachedBadwords {
    rev: u64,
    ts: u64, // channel registration ts, so a drop+re-register (rev resets to 0) can't alias
    set: regex::RegexSet,
}

struct CachedTriggers {
    rev: u64,
    ts: u64, // see CachedBadwords.ts
    entries: Vec<TriggerRt>,
}

// A compiled trigger, with its own last-fired time for the cooldown.
struct TriggerRt {
    re: regex::Regex,
    response: String,
    cooldown: u32,
    last_fired: u64,
}

// One user's recent-chatter counters in one channel (FLOOD + REPEAT kickers,
// plus the running kick count that drives times-to-ban).
#[derive(Default)]
struct ChatterState {
    flood_start: u64, // window start (unix secs)
    flood_lines: u16, // lines since flood_start
    last_hash: u64,   // case-insensitive hash of the previous line
    repeats: u16,     // consecutive identical lines seen so far (0 on the first)
    kicks: u16,       // times kicked so far (reset when it triggers a ban)
    warned: bool,     // whether the one-time warning has been given
}

// A kicker ban awaiting automatic removal (BANEXPIRE).
struct PendingUnban {
    at: u64,      // unix secs when it should be lifted
    from: String, // the bot uid that placed it, to source the -b from
    channel: String,
    mask: String,
}

mod dispatch;
mod kicker;
mod register;
mod sasl;

impl Engine {
    pub fn new(services: Vec<Box<dyn Service>>, db: Db) -> Self {
        let chan_service = services.iter().find(|s| s.manages_channels()).map(|s| s.uid().to_string());
        let nick_service = services.iter().find(|s| s.manages_accounts()).map(|s| s.uid().to_string());
        // Network-wide help index: every service that publishes topics, so HelpServ
        // can front help for the whole network through NetView.
        let mut network = Network::default();
        network.help_catalog = services
            .iter()
            .filter_map(|s| {
                let (blurb, topics) = s.help_topics();
                (!topics.is_empty()).then(|| (s.nick().to_string(), blurb, topics))
            })
            .collect();
        // Restore persisted stats so they survive a restart.
        network.seed_stats(db.persisted_stats());
        network.seed_chan_activity(db.persisted_chan_stats());
        network.seed_incidents(db.persisted_incidents());
        Self {
            services,
            network,
            db,
            sasl_sessions: HashMap::new(),
            sasl_source: HashMap::new(),
            reg_limiter: RegLimiter::new(),
            cmd_limiter: CmdLimiter::default(),
            dict_limiter: DictLimiter::new(),
            chan_service,
            nick_service,
            irc_out: None,
            opers: HashMap::new(),
            sid: String::new(),
            synced: false,
            guest_nick: "Guest".to_string(),
            service_host: "services.local".to_string(),
            service_oper_type: String::new(),
            services_channel: String::new(),
            standard_replies: false,
            config_path: String::new(),
            enforce_seq: 0,
            pending_enforce: Vec::new(),
            bot_uids: HashMap::new(),
            services_signon: 0,
            bot_idents: HashMap::new(),
            next_bot_index: 0,
            bot_channels: std::collections::HashSet::new(),
            chatter: HashMap::new(),
            now_override: None,
            badword_cache: HashMap::new(),
            trigger_cache: HashMap::new(),
            pending_unbans: Vec::new(),
            votes: HashMap::new(),
            log_channel: None,
            debugserv_uid: String::new(),
            account_ttl: None,
            channel_ttl: None,
            expire_warn: None,
            session_limit: None,
        }
    }

    // Increment a shared stat counter (held on the network view, so services and
    // the gRPC API read from one place).
    pub fn bump(&mut self, key: &str) {
        self.network.bump(key);
    }

    // Per-channel activity (lines + top talkers) for the stats APIs.
    pub fn channel_activity(&self, channel: &str) -> Option<(u64, Vec<(String, u64)>)> {
        self.network.channel_activity(channel)
    }

    // The shared counters plus live gauges derived from the store, for the gRPC
    // Stats API. Any service's counters ride in here alongside these.
    pub fn stats_snapshot(&self) -> std::collections::BTreeMap<String, u64> {
        let mut m: std::collections::BTreeMap<String, u64> = self.network.stat_counters().clone();
        m.insert("accounts.total".to_string(), self.db.accounts().count() as u64);
        m.insert("channels.total".to_string(), self.db.channels().count() as u64);
        m.insert("bots.total".to_string(), self.db.bots().count() as u64);
        m.insert("opers.total".to_string(), self.opers.len() as u64);
        m
    }

    // The stat snapshot plus event-log position, for the health/metrics endpoint.
    // The log gauges (seq/lamport/entries) let a monitor watch replication progress
    // and catch a stalled or non-advancing log before users notice.
    pub fn health_metrics(&self) -> std::collections::BTreeMap<String, u64> {
        let mut m = self.stats_snapshot();
        // lamport is monotonic (survives compaction) — the "log advancing" gauge;
        // entries is the current in-memory log size (drops at each compaction).
        m.insert("event.lamport".to_string(), self.db.lamport());
        m.insert("log.entries".to_string(), self.db.log_len() as u64);
        m
    }

    // Snapshot the accumulated stat counters to the log (periodically and on
    // shutdown) so StatServ / the Stats API keep their history across a restart.
    // Only the real counters are persisted; the live gauges above are re-derived.
    pub fn persist_stats(&mut self) {
        let counters = self.network.stat_counters().clone();
        let chan_stats = self.network.chan_activity_snapshot();
        if counters.is_empty() && chan_stats.is_empty() {
            return;
        }
        if let Err(err) = self.db.persist_stats(&counters, chan_stats) {
            tracing::warn!(%err, "failed to persist stat counters");
        }
    }

    // Snapshot the recent-incident ring (OperServ LOGSEARCH) so it survives a
    // restart. Flushed on the same cadence as the stat counters.
    pub fn persist_incidents(&mut self) {
        let (seq, incidents) = self.network.incidents_snapshot();
        if incidents.is_empty() {
            return;
        }
        if let Err(err) = self.db.persist_incidents(seq, incidents) {
            tracing::warn!(%err, "failed to persist incidents");
        }
    }

    // Wall-clock seconds, overridable in tests so the time-based FLOOD kicker is
    // deterministic.
    fn now_secs(&self) -> u64 {
        self.now_override.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
    }

    // Wire the channel the link layer drains, so the engine can push actions to the
    // uplink that no ircd event asked for (here: a forced logout after losing a
    // registration conflict).
    pub fn set_irc_out(&mut self, tx: mpsc::UnboundedSender<NetAction>) {
        self.irc_out = Some(tx);
    }

    // Load the services-operator table (casefolded account -> privileges).
    pub fn set_opers(&mut self, opers: HashMap<String, Privs>) {
        self.network.set_config_opers(opers.keys().cloned().collect());
        self.opers = opers;
    }

    // The privileges an account holds, empty if it is not an oper. The declarative
    // config opers and the runtime OPER grants are unioned, so either source can
    // make an account an operator.
    fn oper_privs(&self, account: &str) -> Privs {
        let config = self.opers.get(&account.to_ascii_lowercase()).copied().unwrap_or_default();
        match self.db.oper_privs_of(account, self.now_secs()) {
            Some(runtime) => config.union(runtime),
            None => config,
        }
    }

    // Our services SID, needed to mint valid bot uids.
    pub fn set_sid(&mut self, sid: String) {
        self.sid = sid;
    }

    // The staff channel notable service actions are announced to.
    pub fn set_log_channel(&mut self, channel: Option<String>) {
        self.log_channel = channel;
    }

    // DebugServ's uid — the live activity feed is sent as PRIVMSGs from it into
    // the log channel. Set from main.rs when the module is enabled.
    pub fn set_debugserv_uid(&mut self, uid: impl Into<String>) {
        self.debugserv_uid = uid.into();
    }

    // Build a DebugServ feed line for the log channel, or None when DebugServ
    // isn't running (no uid) / there's no log channel / we're not linked yet.
    // `cat` is a short category tag (AUTH, SESS, ACCT, CHAN, OPER, NET).
    fn feed(&self, cat: &str, text: String) -> Option<NetAction> {
        let channel = self.log_channel.as_deref()?;
        if self.debugserv_uid.is_empty() || self.sid.is_empty() {
            return None;
        }
        Some(NetAction::Privmsg {
            from: self.debugserv_uid.clone(),
            to: channel.to_string(),
            text: format!("\x02[{cat}]\x02 {text}"),
        })
    }

    // "nick (host)" for a live uid, for the feed — the host makes an auth line
    // actionable (where did this login come from). Falls back gracefully.
    fn who(&self, uid: &str) -> String {
        let nick = self.network.nick_of(uid).unwrap_or("?");
        match self.network.host_of(uid) {
            Some(host) => format!("\x02{nick}\x02 ({host})"),
            None => format!("\x02{nick}\x02"),
        }
    }

    // OperServ NOTIFY: if `uid` matches a live watch carrying `flag`, build a staff
    // feed line "nick!ident@host <what>". `chan` scopes a channel-mask watch to the
    // relevant channel. None when nothing matches, the user is unknown, or there is
    // no feed sink. The cheap `any_notifies` gate keeps the common (no-watch) path
    // off the per-event identity lookup.
    fn notify_line(&self, flag: char, uid: &str, chan: Option<&str>, what: &str) -> Option<NetAction> {
        if !self.db.any_notifies() {
            return None;
        }
        let target = self.network.ban_target(uid)?;
        if !self.db.notify_flags(Some(&target), chan).contains(flag) {
            return None;
        }
        // The feed lands in the oper-only staff channel, so a watch line carries the
        // forensic detail a cloak hides: the real IP (with rdns if it differs), the
        // login, and the origin server. The connection port is not available — the
        // ircd's s2s UID burst never sends it. `nick!ident@host` keeps the cloak so
        // it still correlates with what ordinary users see.
        let mut parts: Vec<String> = Vec::new();
        if !target.ip.is_empty() {
            let mut s = format!("IP: \x02{}\x02", target.ip);
            if !target.realhost.is_empty() && target.realhost != target.ip {
                s.push_str(&format!(" DNS: {}", target.realhost));
            }
            parts.push(s);
        }
        if let Some(account) = target.account {
            parts.push(format!("Account: \x02{account}\x02"));
        }
        if !target.server.is_empty() {
            parts.push(format!("Server: {}", target.server));
        }
        let detail = if parts.is_empty() { String::new() } else { format!(" · {}", parts.join(" · ")) };
        let who = format!("\x02{}\x02!{}@{}", target.nick, target.ident, target.host);
        self.feed("NOTIFY", format!("{who} {what}{detail}"))
    }

    // Membership cleanup shared by PART and KICK: drop the user from the channel,
    // forget their chatter, and re-add an assigned bot that was evicted (an op can't
    // kick the channel's own bot). Any reconcile actions are returned.
    fn member_left(&mut self, channel: &str, uid: &str) -> Vec<NetAction> {
        self.network.channel_part(channel, uid);
        self.prune_channel_if_gone(channel);
        self.forget_chatter(channel, uid);
        if let Some(bot_lc) = self.bot_uids.iter().find_map(|(lc, u)| (u == uid).then(|| lc.clone())) {
            if self.bot_channels.remove(&(bot_lc, channel.to_string())) {
                return self.reconcile_bots();
            }
        }
        Vec::new()
    }

    // Inactivity-expiry thresholds (seconds); None leaves that kind never
    // expiring. `warn` is the lead time before expiry to email a warning (None =
    // no warning emails).
    pub fn set_expiry(&mut self, account_ttl: Option<u64>, channel_ttl: Option<u64>, warn: Option<u64>) {
        self.account_ttl = account_ttl;
        self.channel_ttl = channel_ttl;
        self.expire_warn = warn;
    }

    // The default per-IP connection limit (None = session limiting off).
    pub fn set_session_limit(&mut self, limit: Option<u32>) {
        self.session_limit = limit;
    }

    // The effective session limit for `ip`: a matching exception's allowance, else
    // the default. None means unlimited (limiting off, or an exception of 0). At
    // DEFCON 2 or lower the base tightens to a single session regardless of config.
    fn session_limit_for(&self, ip: &str) -> Option<u32> {
        let default = if self.db.defcon() <= 2 { 1 } else { self.session_limit? };
        let limit = self.db.session_exception_for(ip).unwrap_or(default);
        (limit > 0).then_some(limit)
    }

    // Bring the network's bot pseudo-clients in line with the registry: introduce
    // any new bots, quit any that were deleted. Run at burst and after commands.
    fn reconcile_bots(&mut self) -> Vec<NetAction> {
        let mut out = Vec::new();
        let live: Vec<(String, String, String, String)> =
            self.db.bots().map(|b| (b.nick.clone(), b.user.clone(), b.host.clone(), b.gecos.clone())).collect();
        for (nick, user, host, gecos) in &live {
            let k = nick.to_ascii_lowercase();
            let ident = ident_hash(user, host, gecos);
            // A BOT CHANGE that kept the nick but altered the identity: quit the
            // stale client so it is reintroduced (and rejoins its channels) below.
            if self.bot_uids.contains_key(&k) && self.bot_idents.get(&k) != Some(&ident) {
                if let Some(uid) = self.bot_uids.remove(&k) {
                    out.push(NetAction::QuitUser { uid, reason: "Bot changed".to_string() });
                }
                self.network.bot_forget(&k);
                self.bot_channels.retain(|(b, _)| *b != k);
            }
            if !self.bot_uids.contains_key(&k) {
                let uid = format!("{}B{:05}", self.sid, self.next_bot_index);
                self.next_bot_index += 1;
                out.push(NetAction::IntroduceUser { uid: uid.clone(), nick: nick.clone(), ident: user.clone(), host: host.clone(), gecos: gecos.clone() });
                self.network.bot_connect(nick, &uid);
                self.bot_uids.insert(k.clone(), uid);
                self.bot_idents.insert(k, ident);
            }
        }
        let live_keys: std::collections::HashSet<String> = live.iter().map(|(n, ..)| n.to_ascii_lowercase()).collect();
        let removed: Vec<String> = self.bot_uids.keys().filter(|k| !live_keys.contains(*k)).cloned().collect();
        for k in removed {
            if let Some(uid) = self.bot_uids.remove(&k) {
                out.push(NetAction::QuitUser { uid, reason: "Bot removed".to_string() });
            }
            self.bot_idents.remove(&k);
            self.network.bot_forget(&k);
            self.bot_channels.retain(|(b, _)| *b != k); // its channel memberships go with it
        }
        // Join assigned channels, part unassigned ones (for still-live bots).
        let assigned: Vec<(String, String)> = self.db.channels()
            .filter_map(|c| c.assigned_bot.as_ref().map(|b| (b.to_ascii_lowercase(), c.name.clone())))
            .collect();
        let desired: std::collections::HashSet<(String, String)> =
            assigned.into_iter().filter(|(b, _)| self.bot_uids.contains_key(b)).collect();
        for (bot_lc, chan) in &desired {
            if !self.bot_channels.contains(&(bot_lc.clone(), chan.clone())) {
                if let Some(uid) = self.bot_uids.get(bot_lc) {
                    // BotServ bots join as protected admins + op (+ao) so they hold
                    // op and ordinary ops still can't kick or deop them — the
                    // standard bot default.
                    out.push(NetAction::ServiceJoin { uid: uid.clone(), channel: chan.clone(), modes: "ao".into() });
                    // The bot's join (re)creates the channel on the uplink, and the
                    // uplink sends IJOIN (no modes) for later member joins — so nothing
                    // else re-applies the registered mode-lock (+r). Re-assert it here.
                    if let Some(modes) = self.db.channel(chan).map(|c| c.lock_modes()).filter(|m| !m.is_empty()) {
                        let from = self.channel_mode_source(chan);
                        out.push(NetAction::ChannelMode { from, channel: chan.clone(), modes });
                    }
                    self.bot_channels.insert((bot_lc.clone(), chan.clone()));
                }
            }
        }
        let to_part: Vec<(String, String)> = self.bot_channels.iter().filter(|bc| !desired.contains(*bc)).cloned().collect();
        for (bot_lc, chan) in to_part {
            self.bot_channels.remove(&(bot_lc.clone(), chan.clone()));
            if let Some(uid) = self.bot_uids.get(&bot_lc) {
                out.push(NetAction::ServicePart { uid: uid.clone(), channel: chan });
            }
        }
        out
    }

    // Finish a SASL login, unless the account is suspended.
    // Where a login attempt came from, for the auth feed: the client's real
    // host/IP from the SASL H message while mid-SASL (the client isn't a
    // connected user yet), or the live user's nick@host for a NickServ IDENTIFY.
    fn auth_source(&self, client: &str) -> String {
        if let Some((_, src)) = self.sasl_source.get(client) {
            return safe(src);
        }
        match (self.network.nick_of(client), self.network.host_of(client)) {
            (Some(nick), Some(host)) => format!("{}@{}", safe(nick), safe(host)),
            (Some(nick), None) => safe(nick),
            _ => "unknown".to_string(),
        }
    }

    // One login attempt -> a clean admin feed line + an on-disk audit record.
    // Covers every mechanism (SASL PLAIN/SCRAM/EXTERNAL, NickServ IDENTIFY).
    // `account` is who they authenticated as (or tried to) — it can be attacker-
    // supplied on a failure, so it is sanitised; no secret is ever included.
    fn auth_report(&self, ok: bool, account: Option<&str>, mech: &str, client: &str, reason: Option<&str>) -> Option<NetAction> {
        let source = self.auth_source(client);
        let acct = safe(account.unwrap_or("*"));
        tracing::info!(target: "echo::auth", ok, account = %acct, mech, source = %source, reason = reason.unwrap_or("-"), "login attempt");
        let body = if ok {
            format!("\x02{acct}\x02 login ok · {mech} · from {source}")
        } else {
            format!("\x02{acct}\x02 login \x02FAILED\x02 · {mech} · from {source} · {}", reason.unwrap_or("denied"))
        };
        self.feed("AUTH", body)
    }

    fn sasl_login(&self, mech: &str, agent: &str, client: &str, account: String) -> Vec<NetAction> {
        if self.db.is_suspended(&account) {
            let mut out = sasl_fail(agent, client);
            out.extend(self.auth_report(false, Some(&account), mech, client, Some("account suspended")));
            return out;
        }
        let mut out = sasl_success(agent, client, account.clone());
        out.extend(self.auth_report(true, Some(&account), mech, client, None));
        out
    }

    // A SASL rejection plus an auth-feed line naming why — for the credential
    // failures worth surfacing (bad password, bad/unknown cert, unknown account).
    fn sasl_deny(&self, mech: &str, agent: &str, client: &str, account: Option<&str>, reason: &str) -> Vec<NetAction> {
        let mut out = sasl_fail(agent, client);
        out.extend(self.auth_report(false, account, mech, client, Some(reason)));
        out
    }

    // The login side-effects — auto-join, vhost, and a waiting-memo notice — for a
    // user who is already authenticated the instant they connect: they logged in
    // via SASL during registration, so the NickServ IDENTIFY path (which applies
    // these itself) never ran for them. Mirrors modules/nickserv/src/identify.rs.
    fn login_connect_effects(&self, uid: &str, account: &str) -> Vec<NetAction> {
        let mut out = Vec::new();
        for entry in self.db.ajoin_list(account) {
            out.push(NetAction::ForceJoin { uid: uid.to_string(), channel: entry.channel.clone(), key: entry.key.clone() });
        }
        if let Some(vhost) = self.db.active_vhost(account) {
            // apply_vhost semantics: an ident@host spec sets the ident as well.
            match vhost.split_once('@') {
                Some((ident, host)) => {
                    out.push(NetAction::SetIdent { uid: uid.to_string(), ident: ident.to_string() });
                    out.push(NetAction::SetHost { uid: uid.to_string(), host: host.to_string() });
                }
                None => out.push(NetAction::SetHost { uid: uid.to_string(), host: vhost }),
            }
        }
        // Publish the account's public profile as IRCv3 metadata on this session,
        // so clients (Orbit) show avatar/bio/etc. Metadata lives on the connection,
        // so it must be re-sent on every login.
        for field in echo_api::ProfileField::ALL {
            if let Some(v) = self.db.profile_field(account, field) {
                out.push(NetAction::Metadata { target: uid.to_string(), key: field.meta_key().to_string(), value: v });
            }
        }
        // Re-apply the account's OperServ SWHOIS line (per-connection on the ircd).
        if let Some(swhois) = self.db.swhois(account) {
            out.push(NetAction::Metadata { target: uid.to_string(), key: "swhois".to_string(), value: swhois });
        }
        // Re-apply the account's persistent SIGNORE list (per-connection too).
        let signore = self.db.signore(account);
        if !signore.is_empty() {
            out.push(NetAction::Metadata { target: uid.to_string(), key: "signore".to_string(), value: signore.join(" ") });
        }
        let unread = self.db.unread_memos(account);
        if unread > 0 && self.db.memo_notify_on(account) {
            if let Some(ns) = &self.nick_service {
                out.push(NetAction::Notice {
                    from: ns.clone(),
                    to: uid.to_string(),
                    text: echo_api::render_plural(&self.lang_for_account(account), unread as u64, "You have \x02{unread}\x02 new memo. Read it with \x02/msg MemoServ READ NEW\x02.", "You have \x02{unread}\x02 new memos. Read them with \x02/msg MemoServ READ NEW\x02.", &[("unread", unread.to_string())]),
                });
            }
        }
        out
    }

    fn emit_irc(&self, action: NetAction) {
        if let Some(tx) = &self.irc_out {
            let _ = tx.send(action); // unbounded: never blocks; only fails if the link is down
        }
    }

    // Cost of a fresh SCRAM verifier; read by the link layer for off-thread derivation.
    pub fn scram_iterations(&self) -> u32 {
        self.db.scram_iterations
    }

    // Gossip pass-throughs to the account store, used by the replication layer.
    pub fn gossip_digest(&self) -> HashMap<String, (u64, u64)> {
        self.db.version_vector()
    }

    pub fn gossip_missing(&self, peer: &HashMap<String, (u64, u64)>) -> Vec<LogEntry> {
        self.db.missing_for(peer)
    }

    // A full read of current directory state, for the gRPC Snapshot RPC.
    pub fn directory_snapshot(&self) -> (Vec<db::Account>, Vec<db::ChannelInfo>) {
        (self.db.accounts().cloned().collect(), self.db.channels().cloned().collect())
    }

    // Read accessors for the admin panel (in-process, under the shared lock).
    pub fn account_privs(&self, account: &str) -> Privs {
        self.oper_privs(account)
    }
    pub fn akills(&self) -> Vec<echo_api::AkillView> {
        self.db.akills()
    }
    pub fn filters(&self) -> Vec<echo_api::FilterView> {
        self.db.filters()
    }
    pub fn session_exceptions(&self) -> Vec<(String, u32, String)> {
        self.db.session_exceptions()
    }
    pub fn opers_grants(&self) -> Vec<(String, Vec<String>, Option<u64>)> {
        self.db.opers_list()
    }
    // Recent moderation/action incidents (newest first) for the live feed / audit / logs.
    pub fn recent_incidents(&self, limit: usize) -> Vec<echo_api::IncidentView> {
        self.network.search_incidents("", limit)
    }
    // Live network view (from the uplink burst) for the panel.
    pub fn net_user_count(&self) -> usize {
        self.network.user_count()
    }
    pub fn net_channel_count(&self) -> usize {
        self.network.channel_count()
    }
    pub fn net_server_count(&self) -> usize {
        self.network.server_count()
    }
    pub fn net_module_names(&self) -> Vec<String> {
        self.network.module_names()
    }
    pub fn net_oper_count(&self) -> usize {
        self.network.oper_count()
    }
    pub fn net_users_detailed(&self) -> Vec<state::NetUser> {
        self.network.users_detailed()
    }
    pub fn net_user_detail(&self, nick: &str) -> Option<state::NetUser> {
        self.network.user_detail(nick)
    }
    pub fn net_user_channels(&self, uid: &str) -> Vec<(String, &'static str)> {
        self.network.user_channels(uid)
    }
    pub fn net_servers_detailed(&self) -> Vec<state::NetSrv> {
        self.network.servers_detailed()
    }
    pub fn net_channel_members(&self, name: &str) -> Vec<state::NetMember> {
        self.network.channel_member_views(name)
    }
    // Live channels with each one's registered flag resolved against the channel db.
    pub fn net_channels_detailed(&self) -> Vec<state::NetChan> {
        let mut v = self.network.channels_detailed();
        for c in &mut v {
            c.registered = self.db.channel(&c.name).is_some();
        }
        v
    }
    pub fn net_channel_detail(&self, name: &str) -> Option<state::NetChan> {
        self.network.channel_detail(name).map(|mut c| {
            c.registered = self.db.channel(&c.name).is_some();
            c
        })
    }

    pub fn gossip_ingest(&mut self, entry: LogEntry) -> std::io::Result<()> {
        // If ingesting a peer's entry removed an account a local session or channel
        // relied on (lost a conflict, or dropped elsewhere), clean up after it.
        let gone = match self.db.ingest(entry)? {
            Some(db::IngestEffect::TakenOver(a)) => {
                // The account still exists (its home moved) — end local sessions
                // using the old credential, but keep the channels it founded.
                self.handle_account_gone(&a, "collided with another network and no longer belongs to you", false);
                false
            }
            Some(db::IngestEffect::Dropped(a)) => {
                self.handle_account_gone(&a, "was dropped", true);
                true
            }
            Some(db::IngestEffect::Suspended(a)) => {
                // A gossiped suspension keeps the account and its channels, but its
                // live sessions here must end (a local SUSPEND logs them out too).
                self.logout_account_sessions(&a, "was suspended");
                false
            }
            Some(db::IngestEffect::BanAdded { kind, mask, setter, duration, reason }) => {
                // Push the gossiped network ban to our ircd now, rather than only
                // holding it for the next netburst.
                self.emit_irc(NetAction::AddLine { kind, mask, setter, duration, reason });
                false
            }
            Some(db::IngestEffect::BanLifted { kind, mask }) => {
                self.emit_irc(NetAction::DelLine { kind, mask });
                false
            }
            None => false,
        };
        // handle_account_gone may have released a channel that had a bot assigned.
        // This runs outside the dispatch path (which reconciles for local
        // commands), so reconcile here or the bot lingers in a released channel.
        if gone {
            for action in self.reconcile_bots() {
                self.emit_irc(action);
            }
        }
        Ok(())
    }

    // An account a local session was using is gone or moved. Log out those
    // sessions (their credential may have changed). Only release the channels it
    // founded when `release_channels` — i.e. the account is genuinely gone (dropped
    // or expired). A takeover leaves the account in place (its home just moved), so
    // its channels keep a valid founder by name and must NOT be dropped.
    fn handle_account_gone(&mut self, account: &str, reason: &str, release_channels: bool) {
        let victims = self.network.uids_logged_into(account);
        // A channel with a valid successor is inherited rather than released.
        let (inherited, orphaned) = if release_channels {
            self.db.release_founded_channels(account)
        } else {
            (Vec::new(), Vec::new())
        };
        let (cs, ns) = (self.chan_service.clone(), self.nick_service.clone());
        // Release the registered mode on each dropped (not inherited) channel.
        for chan in &orphaned {
            if let Some(cs) = &cs {
                self.emit_irc(NetAction::ChannelMode { from: cs.clone(), channel: chan.clone(), modes: "-r".to_string() });
            }
        }
        // Tell any online successor they inherited a channel.
        for (chan, s) in &inherited {
            if let (Some(ns), Some(uid)) = (&ns, self.network.uids_logged_into(s).into_iter().next()) {
                let text = echo_api::render(&self.lang_for_account(s), "You are now the founder of \x02{chan}\x02 (inherited from \x02{account}\x02).", &[("chan", chan.to_string()), ("account", account.to_string())]);
                self.emit_irc(NetAction::Notice { from: ns.clone(), to: uid, text });
            }
        }
        // Log out and inform each local session that held the name.
        for uid in victims {
            self.logout_uid(&uid, account, reason);
            if !orphaned.is_empty() {
                if let Some(ns) = &ns {
                    let text = echo_api::render(&self.lang_for_uid(&uid), "Channels you had registered as \x02{account}\x02 were released: {list}.", &[("account", account.to_string()), ("list", orphaned.join(", "))]);
                    self.emit_irc(NetAction::Notice { from: ns.clone(), to: uid.clone(), text });
                }
            }
        }
    }

    // Forget a user who left the network (QUIT or KILL): drop their membership,
    // any half-finished SASL exchange, and their pending nick-protection timer.
    fn forget_user(&mut self, uid: &str) -> Vec<NetAction> {
        // Let services drop state keyed on this uid (e.g. GamesServ guest games)
        // before the uid can be recycled to a new connection; collect any notices
        // they hand back (e.g. telling an opponent their game just ended).
        let mut notices = Vec::new();
        {
            let Self { services, network, db, .. } = self;
            for svc in services.iter_mut() {
                notices.extend(svc.on_user_quit(uid, &*network, &*db));
            }
        }
        let chans = self.network.channels_of(uid);
        self.network.user_quit(uid);
        for c in &chans {
            self.prune_channel_if_gone(c);
        }
        self.sasl_sessions.remove(uid);
        self.sasl_source.remove(uid); // the captured SASL host/IP dies with the connection too
        self.pending_enforce.retain(|p| p.uid != uid);
        self.forget_chatter_everywhere(uid);
        notices
    }

    // Forget a channel once it's truly gone on the ircd — no members AND no resident
    // services bot (bots keep a channel alive without being tracked as members).
    // Pruning it stops a stale key/mode leaking to a later channel of the same name,
    // while keeping a botted/persistent channel's live state intact.
    fn prune_channel_if_gone(&mut self, channel: &str) {
        if self.network.channel_members(channel).next().is_some() {
            return;
        }
        if self.bot_channels.iter().any(|(_, c)| c.eq_ignore_ascii_case(channel)) {
            return;
        }
        self.network.remove_channel(channel);
    }

    // Log a single session out of `account`, telling them why (services-sourced).
    fn logout_uid(&mut self, uid: &str, account: &str, reason: &str) {
        if let Some(action) = self.feed("SESS", format!("{} logged out of \x02{account}\x02 ({reason})", self.who(uid))) {
            self.emit_irc(action);
        }
        for act in echo_api::vhost_restore_actions(&self.network, &self.db, uid, account) {
            self.emit_irc(act);
        }
        self.network.clear_account(uid);
        self.emit_irc(NetAction::Metadata { target: uid.to_string(), key: "accountname".to_string(), value: String::new() });
        if let Some(ns) = self.nick_service.clone() {
            // `clear_account(uid)` above already dropped the uid→account map, so
            // resolve the language from the account name, not the (now-anonymous) uid.
            let lang = self.lang_for_account(account);
            let reason = echo_api::render(&lang, reason, &[]);
            let text = echo_api::render(&lang, "Your account \x02{account}\x02 {reason}. You have been logged out.", &[("account", account.to_string()), ("reason", reason)]);
            self.emit_irc(NetAction::Notice { from: ns, to: uid.to_string(), text });
        }
    }

    // Log out every local session identified to `account` — e.g. after a gossiped
    // suspension. Unlike `handle_account_gone` the account and its channels stay
    // put; only the live sessions end.
    fn logout_account_sessions(&mut self, account: &str, reason: &str) {
        for uid in self.network.uids_logged_into(account) {
            self.logout_uid(&uid, account, reason);
        }
    }

    // Compact the log if it has grown past the live account count. Returns
    // whether it rewrote anything.
    pub fn maybe_compact(&mut self) -> std::io::Result<bool> {
        if self.db.should_compact() {
            self.db.compact()?;
            return Ok(true);
        }
        Ok(false)
    }

    // One ChanFix scoring pass over the live network (run periodically).
    pub fn chanfix_tick(&mut self) {
        self.network.chanfix_sample();
    }

    // Drop accounts and channels left inactive past the configured thresholds.
    // Lazy: computed from stored last-activity stamps on this periodic pass, with
    // no per-record timer. Opers, accounts with a live session, and occupied
    // channels are spared; each expiry is announced to the audit channel. Emits
    // cleanup directly over the outbound path (like a takeover cleanup).
    // The language to address `account`'s owner in: their stored preference, or
    // the network default.
    fn lang_for_account(&self, account: &str) -> String {
        self.db.language_of(account).unwrap_or_else(|| self.db.default_language())
    }

    // The language to address the user on `uid` in: their logged-in account's
    // preference, or the network default (e.g. an unidentified user).
    fn lang_for_uid(&self, uid: &str) -> String {
        self.network
            .account_of(uid)
            .and_then(|a| self.db.language_of(a))
            .unwrap_or_else(|| self.db.default_language())
    }

    // Forget kicker caches for channels that no longer exist (dropped by command
    // or expired), so a long-running process doesn't accumulate them. Correctness
    // never relied on this — entries are keyed by (rev, ts) and a re-registered
    // channel gets a fresh ts, so a stale entry can't false-match; this only
    // reclaims memory. Runs on the periodic sweep, covering both drop paths.
    fn prune_kicker_caches(&mut self) {
        let (dead_bw, dead_tr) = {
            let db = &self.db;
            (
                self.badword_cache.keys().filter(|c| db.channel(c.as_str()).is_none()).cloned().collect::<Vec<_>>(),
                self.trigger_cache.keys().filter(|c| db.channel(c.as_str()).is_none()).cloned().collect::<Vec<_>>(),
            )
        };
        for c in dead_bw {
            self.badword_cache.remove(&c);
        }
        for c in dead_tr {
            self.trigger_cache.remove(&c);
        }
    }

    pub fn expire_sweep(&mut self) {
        let now = self.now_secs();
        // First, warn owners whose account/channel is approaching expiry and for
        // whom we have an email — a chance to keep it before it's dropped.
        if let Some(lead) = self.expire_warn.filter(|_| self.db.email_enabled()) {
            if let Some(ttl) = self.account_ttl {
                for (account, email, left) in self.db.accounts_to_warn(now, ttl, lead) {
                    let mail = echo_api::email::expiry_warning(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), echo_api::email::ExpiryTarget::Account, &account, &human_duration(left), &self.lang_for_account(&account));
                    self.emit_irc(NetAction::SendEmail { to: email, subject: mail.subject, text: mail.text, html: Some(mail.html) });
                    self.db.mark_account_warned(&account);
                }
            }
            if let Some(ttl) = self.channel_ttl {
                for (channel, email, left, lang) in self.db.channels_to_warn(now, ttl, lead) {
                    let mail = echo_api::email::expiry_warning(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), echo_api::email::ExpiryTarget::Channel, &channel, &human_duration(left), &lang);
                    self.emit_irc(NetAction::SendEmail { to: email, subject: mail.subject, text: mail.text, html: Some(mail.html) });
                    self.db.mark_channel_warned(&channel);
                }
            }
        }
        if let Some(ttl) = self.account_ttl {
            for account in self.db.expired_accounts(now, ttl) {
                // Never expire an operator's account or one still in use. oper_privs
                // unions config [[oper]] AND runtime OperServ OPER grants — self.opers
                // is config-only, so a runtime-granted oper was being dropped.
                if self.oper_privs(&account).any() || !self.network.uids_logged_into(&account).is_empty() {
                    continue;
                }
                if self.db.drop_account(&account).unwrap_or(false) {
                    self.handle_account_gone(&account, "expired after a long period of inactivity", true);
                    self.audit(format!("Account \x02{account}\x02 expired after inactivity."));
                }
            }
        }
        if let Some(ttl) = self.channel_ttl {
            let cs = self.chan_service.clone();
            for channel in self.db.expired_channels(now, ttl) {
                // A channel people are currently sitting in is still in use.
                if self.network.channel_members(&channel).next().is_some() {
                    continue;
                }
                if self.db.drop_channel(&channel).is_ok() {
                    if let Some(cs) = &cs {
                        self.emit_irc(NetAction::ChannelMode { from: cs.clone(), channel: channel.clone(), modes: "-r".to_string() });
                    }
                    self.audit(format!("Channel \x02{channel}\x02 expired after inactivity."));
                }
            }
        }
        // A channel dropped above — expired, or orphaned by an expired founder —
        // takes its assigned bot with it. Command-driven drops reconcile via the
        // dispatch path, but this sweep runs outside it, so reconcile here or the
        // bot lingers in a channel it no longer serves until the next netburst.
        for action in self.reconcile_bots() {
            self.emit_irc(action);
        }
        self.prune_kicker_caches();
    }

    // The news items of `kind` as server-sourced notices to `uid`, each tagged
    // with `label` so it reads as an announcement. Empty if we have no SID yet.
    fn news_notices(&self, kind: NewsKind, label: &str, uid: &str) -> Vec<NetAction> {
        if self.sid.is_empty() {
            return Vec::new();
        }
        self.db
            .news(kind)
            .into_iter()
            .map(|n| NetAction::Notice { from: self.sid.clone(), to: uid.to_string(), text: format!("[\x02{label}\x02] {}", n.text) })
            .collect()
    }

    // The guest-nick base used when nick-protection renames an unidentified user.
    pub fn set_guest_nick(&mut self, base: &str) {
        if !base.is_empty() {
            self.guest_nick = base.to_string();
        }
    }

    // The hostname the service pseudo-clients wear (NickServ!services@<host>).
    pub fn set_service_host(&mut self, host: &str) {
        if !host.is_empty() {
            self.service_host = host.to_string();
        }
    }

    // Oper type our services are flagged with at introduction (empty = don't oper).
    pub fn set_service_oper_type(&mut self, oper_type: impl Into<String>) {
        self.service_oper_type = oper_type.into();
    }

    // Channel all service pseudo-clients join at startup (empty = none).
    pub fn set_services_channel(&mut self, channel: impl Into<String>) {
        self.services_channel = channel.into();
    }

    pub fn set_standard_replies(&mut self, on: bool) {
        self.standard_replies = on;
    }

    pub fn set_config_path(&mut self, path: impl Into<String>) {
        self.config_path = path.into();
    }

    // Whether our pseudo-clients have signed on to the uplink (a fresh burst sets
    // `services_signon`), and for how long — for the Admin/`echorpc` status view.
    pub fn linked(&self) -> bool {
        self.services_signon > 0
    }
    pub fn uptime_secs(&self) -> u64 {
        if self.services_signon == 0 {
            0
        } else {
            self.now_secs().saturating_sub(self.services_signon)
        }
    }

    // Re-read config.toml and apply the settings that are safe to change while
    // linked, reporting the outcome to the oper who ran REHASH. A parse error
    // keeps the running configuration untouched (validate-or-keep, like an ircd
    // rehash). Server identity (name/sid/protocol/uplink), service umodes and the
    // keycard endpoint are NOT reloadable — they need a restart.
    // Reload config.toml and apply the reloadable settings live. Returns whether
    // the new config actually loaded (a parse error keeps the running config) plus
    // the notices to deliver to the requester and the staff log channel.
    pub fn rehash(&mut self, requester: &str, agent: &str) -> (bool, Vec<NetAction>) {
        let path = self.config_path.clone();
        // Who ran it, for the DebugServ log-channel line (account, else nick).
        let oper = self
            .network
            .account_of(requester)
            .or_else(|| self.network.nick_of(requester))
            .unwrap_or("an operator")
            .to_string();
        let notice = |text: String| NetAction::Notice { from: agent.to_string(), to: requester.to_string(), text };
        let cfg = match crate::config::Config::load(&path) {
            Ok(cfg) => cfg,
            Err(e) => {
                let mut out = Vec::new();
                if let Some(line) = self.feed("OPER", format!("\x02{oper}\x02 ran \x02REHASH\x02 · config.toml failed to parse, keeping the running config · {e}")) {
                    out.push(line);
                }
                out.push(notice(format!("REHASH failed: {e}. The running configuration is unchanged.")));
                return (false, out);
            }
        };
        let opers = cfg.opers();
        let oper_count = opers.len();
        self.set_opers(opers);
        self.set_service_oper_type(cfg.server.service_oper_type.clone());
        self.set_services_channel(cfg.server.services_channel.clone());
        self.set_standard_replies(cfg.server.standard_replies);
        self.set_log_channel(cfg.log.as_ref().map(|l| l.channel.clone()));
        self.db.set_notify_exclude(cfg.log.as_ref().map(|l| l.notify_exclude.clone()).unwrap_or_default());
        self.db.set_confusable_check(cfg.register.confusable_check);
        self.db.set_registration_vouch(cfg.register.vouch);
        self.set_guest_nick(&cfg.server.guest_nick);
        if let Some(expire) = &cfg.expire {
            self.set_expiry(expire.account_ttl(), expire.channel_ttl(), expire.warn_ttl());
        }
        if let Some(session) = &cfg.session {
            self.set_session_limit(session.limit());
        }
        let sr = if self.standard_replies { "on" } else { "off" };
        let chan = if self.services_channel.is_empty() { "(none)" } else { &self.services_channel };
        let opers_word = if oper_count == 1 { "oper" } else { "opers" };
        let mut out = Vec::new();
        // Announce it in the log channel so staff see who reloaded what, when.
        if let Some(line) = self.feed("OPER", format!("\x02{oper}\x02 reloaded the configuration live · \x02{oper_count}\x02 {opers_word} · standard-replies \x02{sr}\x02 · services \x02{chan}\x02 · no restart needed")) {
            out.push(line);
        }
        out.push(notice(format!("Configuration reloaded from \x02{path}\x02.")));
        out.push(notice(format!(
            "Applied: \x02{oper_count}\x02 oper(s), standard-replies \x02{sr}\x02, services channel \x02{chan}\x02, service oper-type \x02{}\x02.",
            if self.service_oper_type.is_empty() { "(none)" } else { &self.service_oper_type },
        )));
        out.push(notice("Not reloadable (need a RESTART): server name/SID/protocol, uplink, service umodes, keycard.".to_string()));
        // Flag any typo'd privilege names so they don't silently grant nothing.
        for (account, name) in cfg.oper_priv_warnings() {
            out.push(notice(format!(
                "\x02Warning:\x02 oper \x02{account}\x02 has an unknown privilege \x02{name}\x02 (valid: {}) — ignored.",
                echo_api::Priv::valid_names()
            )));
        }
        (true, out)
    }

    // Rehash driven by the gRPC control CLI. There's no oper session to notice, so
    // the per-requester replies are dropped, but the staff log-channel line is still
    // delivered and the real load result is reported back to the caller.
    pub fn control_rehash(&mut self) -> (bool, String) {
        let (ok, actions) = self.rehash("gRPC control", "");
        for action in actions {
            if matches!(action, NetAction::Privmsg { .. }) {
                self.emit_irc(action);
            }
        }
        let msg = if ok { "configuration reloaded" } else { "reload failed; running configuration unchanged" };
        (ok, msg.to_string())
    }

    // A user arrived on (or changed to) a registered nick: if they aren't logged
    // into that account, prompt them to IDENTIFY and schedule a rename. Gated on
    // `synced` so a netburst can't enforce every already-online user; a user who
    // authenticated via SASL already has their account set, so they're skipped.
    fn enforce_registered_nick(&mut self, uid: &str, nick: &str) -> Vec<NetAction> {
        if !self.synced {
            return Vec::new();
        }
        let Some(account) = self.db.resolve_account(nick) else { return Vec::new() };
        let account = account.to_string();
        if self.network.account_of(uid) == Some(account.as_str()) {
            return Vec::new(); // already identified to it
        }
        if !self.db.account_wants_protect(&account) {
            return Vec::new(); // owner turned nick protection off (SET KILL OFF)
        }
        let Some(ns) = self.nick_service.clone() else { return Vec::new() };
        let deadline = self.now_secs() + ENFORCE_GRACE;
        self.pending_enforce.retain(|p| p.uid != uid);
        self.pending_enforce.push(PendingEnforce { uid: uid.to_string(), nick: nick.to_string(), deadline });
        vec![NetAction::Notice {
            from: ns,
            to: uid.to_string(),
            text: format!(
                "This nickname is registered to \x02{account}\x02. Log in with \x02/msg NickServ IDENTIFY <password>\x02 within {ENFORCE_GRACE} seconds or you will be renamed."
            ),
        }]
    }

    // Rename anyone who never identified to their registered nick in time. Run on
    // a short cadence from main; emits via the same irc_out path as the other sweeps.
    pub fn enforce_sweep(&mut self) {
        let now = self.now_secs();
        let mut fire = Vec::new();
        let mut i = 0;
        while i < self.pending_enforce.len() {
            if self.pending_enforce[i].deadline <= now {
                let p = self.pending_enforce.remove(i);
                let still_there = self.network.uid_by_nick(&p.nick) == Some(p.uid.as_str());
                let identified = self.network.account_of(&p.uid) == self.db.resolve_account(&p.nick);
                // Re-check protection at fire time: the owner may have turned KILL
                // off during the grace window, in which case don't rename.
                let account = self.db.resolve_account(&p.nick).map(str::to_string);
                let wants = account.as_deref().is_some_and(|a| self.db.account_wants_protect(a));
                if still_there && !identified && wants {
                    fire.push(p.uid);
                }
            } else {
                i += 1;
            }
        }
        for uid in fire {
            let guest = echo_api::next_guest_nick(&self.guest_nick, &mut self.enforce_seq, &self.network, &self.db);
            if let Some(ns) = self.nick_service.clone() {
                let text = echo_api::render(&self.db.default_language(), "You didn't identify in time; you've been renamed.", &[]);
                self.emit_irc(NetAction::Notice { from: ns, to: uid.clone(), text });
            }
            self.emit_irc(NetAction::ForceNick { uid, nick: guest });
        }
    }

    // Record a line to the searchable incident log and, if an audit channel is
    // configured, announce it there. For actions not tied to a command (expiry).
    fn audit(&mut self, text: String) {
        let now = self.now_secs();
        self.network.record_incident(text.clone(), now);
        // Prefer DebugServ's voice; fall back to a server notice when it's off.
        if let Some(action) = self.feed("SVC", text.clone()) {
            self.emit_irc(action);
        } else if let (Some(channel), false) = (&self.log_channel, self.sid.is_empty()) {
            self.emit_irc(NetAction::Notice { from: self.sid.clone(), to: channel.clone(), text });
        }
    }

    #[cfg(test)]
    pub(crate) fn test_register(&mut self, name: &str) {
        self.db.register(name, "pw", None).unwrap();
    }

    // Simulate a uid being logged into `account`, for tests that need
    // `authority_force_logout` to have a live session to clear.
    #[cfg(test)]
    pub(crate) fn test_login(&mut self, uid: &str, account: &str) {
        self.network.set_account(uid, account);
    }

    #[cfg(test)]
    pub(crate) fn test_has_account(&self, name: &str) -> bool {
        self.db.exists(name)
    }

    #[cfg(test)]
    pub(crate) fn test_register_pw(&mut self, name: &str, pw: &str) {
        self.db.register(name, pw, None).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn test_account_verifier(&self, name: &str) -> Option<String> {
        self.db.test_verifier(name)
    }

    #[cfg(test)]
    pub(crate) fn test_register_channel(&mut self, name: &str, founder: &str) {
        self.db.register_channel(name, founder).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn test_has_channel(&self, name: &str) -> bool {
        self.db.channel(name).is_some()
    }

    // Insert or refresh a client's in-progress SASL session, stamped now.
    fn stash_sasl(&mut self, client: String, session: SaslSession) {
        self.sasl_sessions.insert(client, TimedSession { touched: Instant::now(), session });
    }

    // Remember a client's real host/IP from the SASL H message so the auth feed
    // can show where the login came from (the client isn't a connected user yet,
    // so the network map can't resolve it). Host and IP arrive as two fields.
    fn remember_sasl_source(&mut self, client: &str, data: &[String]) {
        let src = match (data.first(), data.get(1)) {
            (Some(host), Some(ip)) if host != ip => format!("{host} [{ip}]"),
            (Some(only), _) => only.clone(),
            _ => return,
        };
        self.sasl_source.insert(client.to_string(), (Instant::now(), src));
    }

    // Evict exchanges idle past the TTL. Run before starting a new one so a
    // dropped-mid-auth client the ircd never reported cannot pile up.
    fn sweep_sasl(&mut self) {
        let now = Instant::now();
        self.sasl_sessions.retain(|_, t| now.duration_since(t.touched) < SASL_SESSION_TTL);
        self.sasl_source.retain(|_, (t, _)| now.duration_since(*t) < SASL_SESSION_TTL);
    }

    // Sent right after the SERVER line: burst, introduce every service, endburst.
    // Whether `uid` is one of our own pseudo-clients — a service or a bot — so we
    // answer a WHOIS IDLE request for it (and only it).
    fn is_own_client(&self, uid: &str) -> bool {
        self.services.iter().any(|s| s.uid() == uid) || self.bot_uids.values().any(|v| v == uid)
    }

    // Restore a user's host after they deoper: their services vhost if one is
    // assigned, otherwise the connect-time cloak the oper vhost had replaced (the
    // ircd doesn't put it back itself). An `ident@host` vhost also sets the ident.
    fn restore_host_after_deoper(&self, uid: &str) -> Vec<NetAction> {
        let vhost = self.network.account_of(uid).and_then(|a| self.db.active_vhost(a));
        let Some(host) = vhost.or_else(|| self.network.host_of(uid).map(str::to_string)) else {
            return Vec::new();
        };
        match host.split_once('@') {
            Some((ident, h)) => vec![
                NetAction::SetIdent { uid: uid.to_string(), ident: ident.to_string() },
                NetAction::SetHost { uid: uid.to_string(), host: h.to_string() },
            ],
            None => vec![NetAction::SetHost { uid: uid.to_string(), host }],
        }
    }

    pub fn startup_actions(&mut self) -> Vec<NetAction> {
        // Fresh link: our pseudo-clients (re)sign on now — remember it for IDLE.
        self.services_signon = self.now_secs();
        // Fresh link: forget bot uids minted on any previous connection.
        self.bot_uids.clear();
        self.bot_idents.clear();
        self.bot_channels.clear();
        self.network.clear_bots();
        self.network.clear_servers(); // the burst re-introduces the server tree
        // A re-link's burst re-introduces every user and channel, but the
        // half-finished SASL exchanges and armed nick-enforcement timers from the
        // dropped connection are orphaned — forget them so a re-link (were one ever
        // added in-process) can't act on stale connection state. Today the process
        // exits on uplink loss and systemd restarts it, so this is defensive.
        self.sasl_sessions.clear();
        self.sasl_source.clear();
        self.pending_enforce.clear();
        self.next_bot_index = 0;
        let mut out = vec![NetAction::Burst];
        for svc in &self.services {
            out.push(NetAction::IntroduceUser {
                uid: svc.uid().to_string(),
                nick: svc.nick().to_string(),
                ident: "services".to_string(),
                host: self.service_host.clone(),
                gecos: svc.gecos().to_string(),
            });
            // Oper them up so WHOIS labels them a network service (the oper line).
            if !self.service_oper_type.is_empty() {
                out.push(NetAction::OperType { uid: svc.uid().to_string(), oper_type: self.service_oper_type.clone() });
            }
            // All service pseudo-clients sit in the services channel (configurable).
            if !self.services_channel.is_empty() {
                out.push(NetAction::ServiceJoin { uid: svc.uid().to_string(), channel: self.services_channel.clone(), modes: "o".into() });
            }
        }
        // Advertise our SASL mechanisms so the uplink can offer `sasl=PLAIN` to
        // clients in CAP LS (IRCv3 SASL 3.2).
        // Introduce the registered bots too.
        out.extend(self.reconcile_bots());
        // DebugServ must be a member of its feed channel to speak there — unless it
        // already joined it above as the services channel.
        if let (false, Some(chan)) = (self.debugserv_uid.is_empty(), self.log_channel.clone()) {
            if !chan.eq_ignore_ascii_case(&self.services_channel) {
                out.push(NetAction::ServiceJoin { uid: self.debugserv_uid.clone(), channel: chan, modes: "o".into() });
            }
        }
        // Re-assert the network bans over the fresh link, each with its remaining
        // duration so the ircd expires it at the right time (permanent = 0).
        let now = self.now_secs();
        for a in self.db.akills() {
            let duration = a.expires.map(|e| e.saturating_sub(now)).unwrap_or(0);
            out.push(NetAction::AddLine { kind: a.kind.wire().to_string(), mask: a.mask, setter: a.setter, duration, reason: a.reason });
        }
        // Re-assert a Q-line for every forbidden nick, so a FORBID keeps the nick
        // unusable across a relink (services X-lines don't survive the split).
        for f in self.db.forbids() {
            if matches!(f.kind, echo_api::ForbidKind::Nick) {
                out.push(NetAction::AddLine { kind: echo_api::XlineKind::Qline.wire().to_string(), mask: f.mask, setter: f.setter, duration: 0, reason: f.reason });
            }
        }
        // Re-assert the spam filters so they survive an ircd restart (m_filter has
        // no s2s delete, so echo is the durable source of truth for them).
        for f in self.db.filters() {
            let duration = f.expires.map(|e| e.saturating_sub(now)).unwrap_or(0);
            out.push(NetAction::Metadata { target: "*".to_string(), key: "filter".to_string(), value: echo_api::encode_filter(&f.pattern, &f.action, &f.flags, duration, &f.reason) });
        }
        // Re-introduce our juped servers over the fresh link.
        for (name, sid, reason) in self.db.jupes() {
            out.push(NetAction::JupeServer { name, sid, reason });
        }
        out.push(NetAction::Metadata {
            target: "*".to_string(),
            key: "saslmechlist".to_string(),
            value: SASL_MECHS.to_string(),
        });
        out.push(NetAction::EndBurst);
        out
    }

    pub fn handle(&mut self, event: NetEvent) -> Vec<NetAction> {
        // Lift any kicker bans whose BANEXPIRE has elapsed (cheap when none are
        // pending, which is the usual case).
        let out = self.sweep_unbans();
        let evout = match event {
            NetEvent::Ping { token, from } => vec![NetAction::Pong { token, from }],
            NetEvent::Idle { requester, target } => {
                // A routed WHOIS (2-param / mIRC double-click) of one of our
                // pseudo-clients asks us for its idle/signon; answer or that WHOIS
                // shows nothing at all. Services are always active (idle 0).
                if self.is_own_client(&target) {
                    vec![NetAction::IdleReply { target, requester, signon: self.services_signon, idle: 0 }]
                } else {
                    Vec::new()
                }
            }
            NetEvent::UserAttrs { uid, ident, realhost, gecos } => {
                // Full identity (ident/host/gecos) is known now, so this is where a
                // connect watch can match the whole nick!user@host#gecos.
                self.network.set_user_attrs(&uid, ident, realhost, gecos);
                self.notify_line('c', &uid, None, "connected").into_iter().collect()
            }
            NetEvent::UserCert { uid, fp } => {
                self.network.set_user_cert(&uid, fp.clone());
                // Transparent certfp login: a cert already registered to an account
                // logs that account in the moment they connect — no SASL EXTERNAL and
                // no NickServ IDENTIFY needed. Skip when already authed (e.g. they used
                // SASL during registration) or the cert was rejected (empty fp).
                if fp.is_empty() || self.network.account_of(&uid).is_some() {
                    return Vec::new();
                }
                let Some(account) = self.db.certfp_owner(&fp).map(str::to_string) else {
                    return Vec::new();
                };
                if self.db.is_suspended(&account) {
                    return Vec::new();
                }
                self.network.set_account(&uid, &account);
                let mut out = vec![NetAction::Metadata {
                    target: uid.clone(),
                    key: "accountname".to_string(),
                    value: account.clone(),
                }];
                if let Some(ns) = &self.nick_service {
                    out.push(NetAction::Notice {
                        from: ns.clone(),
                        to: uid.clone(),
                        text: format!(
                            "You are now identified for \x02{account}\x02 (via your certificate fingerprint)."
                        ),
                    });
                }
                out.extend(self.auth_report(true, Some(&account), "CERTFP", &uid, None));
                out.extend(self.login_connect_effects(&uid, &account));
                out
            }
            NetEvent::ServerInfo { sid, name } => {
                self.network.set_server_name(&sid, name);
                Vec::new()
            }
            NetEvent::ExtbanRegistry { entries } => {
                let names = entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(" ");
                tracing::info!(count = entries.len(), extbans = %names, "learned ircd extban set");
                self.db.set_live_extbans(entries);
                Vec::new()
            }
            NetEvent::ChanModeRegistry { modes } => {
                let prefixes = modes.iter().filter(|c| c.is_prefix()).map(|c| c.letter).collect::<String>();
                tracing::info!(count = modes.len(), prefixes = %prefixes, "learned ircd channel-mode set");
                self.db.set_live_chanmodes(modes);
                Vec::new()
            }
            NetEvent::ModulesAvailable { modules } => {
                self.network.learn_modules(modules);
                Vec::new()
            }
            NetEvent::CapabEnd => {
                verify_ircd_dependencies(&self.network);
                Vec::new()
            }
            NetEvent::ServProtect { letter, requested } => {
                if requested {
                    tracing::info!(mode = %letter, "services are servprotected (+{letter})");
                } else {
                    tracing::warn!(mode = %letter, "service_modes does not request servprotect (+{letter}) — echo's pseudoclients can be killed or hijacked by operators; add it to [server] service_modes");
                }
                Vec::new()
            }
            NetEvent::Casemapping { name } => {
                // echo folds identifiers as ascii. Verify the ircd agrees, rather than
                // assuming it silently — a mismatch would desync account/channel identity.
                if name.eq_ignore_ascii_case("ascii") {
                    tracing::info!(casemapping = %name, "ircd casemapping matches echo (ascii)");
                } else {
                    tracing::warn!(casemapping = %name, "ircd CASEMAPPING is not ascii — echo compares identifiers as ascii, so nicks/channels differing only by rfc1459-equivalent characters may be mismatched; keep the ircd on CASEMAPPING=ascii");
                }
                Vec::new()
            }
            NetEvent::UserConnect { uid, nick, host, ip } => {
                let arriving_nick = nick.clone();
                self.network.user_connect(uid.clone(), nick, host, ip.clone());
                // DEFCON 1 is a full lockdown: no new connections are accepted.
                if self.db.defcon() == 1 && !self.sid.is_empty() {
                    return self.finish(out, vec![NetAction::KillUser {
                        from: self.sid.clone(),
                        uid,
                        reason: "The network is in lockdown (DEFCON 1). Please try again later.".to_string(),
                    }]);
                }
                // Enforce the session limit: kill the connection that puts an IP
                // over its allowance (default limit, raised/lowered by exceptions).
                if let Some(limit) = self.session_limit_for(&ip) {
                    if self.network.session_count(&ip) > limit {
                        return self.finish(out, vec![NetAction::KillUser {
                            from: self.sid.clone(),
                            uid,
                            reason: format!("Session limit exceeded ({limit} from {ip})"),
                        }]);
                    }
                }
                // Greet with the logon news, and — separately — prompt-then-
                // enforce if they arrived on a registered nick they aren't
                // identified to.
                let mut out = self.news_notices(NewsKind::Logon, "News", &uid);
                out.extend(self.enforce_registered_nick(&uid, &arriving_nick));
                // A user already logged in the moment they connect (SASL during
                // registration) never ran the IDENTIFY path, so give them their
                // auto-join, vhost, and waiting-memo notice here.
                if let Some(account) = self.network.account_of(&uid).map(str::to_string) {
                    out.extend(self.login_connect_effects(&uid, &account));
                }
                out
            }
            NetEvent::AccountLogin { uid, account } => {
                // The ircd told us who a user is logged in as (e.g. replayed on our
                // netburst). Restore the mapping so services recognise the login;
                // no side-effects — the burst already put them in their channels.
                if account.is_empty() {
                    self.network.clear_account(&uid);
                } else {
                    self.network.set_account(&uid, &account);
                    self.pending_enforce.retain(|p| p.uid != uid);
                }
                Vec::new()
            }
            NetEvent::SignoreSet { uid, list } => {
                // A logged-in user edited their SIGNORE list on the ircd; persist it to
                // their account so it's replayed on the next login. With no known
                // account there's nothing to store it on, so drop it.
                if let Some(account) = self.network.account_of(&uid).map(str::to_string) {
                    let _ = self.db.set_signore(&account, list);
                }
                Vec::new()
            }
            NetEvent::NickChange { uid, nick } => {
                let new_nick = nick.clone();
                let old_nick = self.network.nick_of(&uid).unwrap_or("?").to_string();
                self.network.user_nick_change(&uid, nick);
                self.pending_enforce.retain(|p| p.uid != uid); // they left the old nick
                let mut out = self.enforce_registered_nick(&uid, &new_nick);
                out.extend(self.enforce_akick_on_nick(&uid));
                // The ircd drops +r on any nick change (m_services), but a logged-in
                // user keeps their account across a rename, so re-assert +r on the
                // new nick — otherwise identifying under a guest nick then switching
                // to the account nick would silently lose the registered mode.
                if self.network.account_of(&uid).is_some() {
                    out.push(NetAction::UserMode { uid: uid.clone(), modes: "+r".to_string() });
                }
                if let Some(line) = self.notify_line('n', &uid, None, &format!("changed nick (was {old_nick})")) {
                    out.push(line);
                }
                out
            }
            // The uplink finished its initial burst: from here on connections are
            // live, so nick-protection prompts/enforcement are safe to run.
            NetEvent::EndBurst => {
                self.synced = true;
                Vec::new()
            }
            // A registered channel just (re)appeared: re-assert +r. Fires on
            // creation and on the uplink burst, so registered channels regain the
            // mode after emptying, and after a services relink.
            NetEvent::ChannelCreate { channel } => {
                let from = self.channel_mode_source(&channel);
                match self.db.channel(&channel) {
                    Some(info) => {
                        let mut out = vec![NetAction::ChannelMode { from: from.clone(), channel: channel.clone(), modes: info.lock_modes() }];
                        // KEEPTOPIC: restore the remembered topic on a recreated channel,
                        // credited to whoever originally set it.
                        if info.settings.keeptopic && !info.topic.is_empty() {
                            out.push(NetAction::Topic { from, channel, topic: info.topic.clone(), setter: info.topic_setter.clone() });
                        }
                        out
                    }
                    None => Vec::new(),
                }
            }
            // Enforce the mode lock: revert any change that broke it.
            NetEvent::ChannelModeChange { channel, modes, setter } => {
                self.network.apply_channel_mode(&channel, &modes);
                let mut out: Vec<NetAction> = self.notify_line('m', &setter, Some(&channel), &format!("set mode {modes} on {channel}")).into_iter().collect();
                let from = self.channel_mode_source(&channel);
                if let Some(revert) = self.db.channel(&channel).and_then(|info| info.enforce(&modes)) {
                    out.push(NetAction::ChannelMode { from, channel, modes: revert });
                }
                out
            }
            // On join: record membership, enforce the auto-kick list, give access
            // members their status mode, and send the entry message.
            NetEvent::Join { uid, channel, op } => {
                self.network.channel_join(&channel, &uid, op);
                // A watched user (or any user of a watched channel) joining: emit a
                // staff line regardless of what enforcement below does.
                let mut watch: Vec<NetAction> = self.notify_line('j', &uid, Some(&channel), &format!("joined {channel}")).into_iter().collect();
                // A join to a registered channel is activity: keep it from expiring.
                if self.db.channel(&channel).is_some() {
                    self.db.mark_channel_used(&channel, self.now_secs());
                }
                // A suspended channel is frozen: no auto-op, akick, or entry message.
                if self.db.is_channel_suspended(&channel) {
                    return self.finish(out, watch);
                }
                let account = self.network.account_of(&uid).map(str::to_string);
                let from = self.channel_mode_source(&channel);
                // Group-aware: a member of a group that holds channel access gets
                // the group's status mode too.
                let mode = account.as_deref().and_then(|a| self.db.channel_join_mode(&channel, a));
                // Op-level access is a capability, not a specific mode string — a
                // SOP auto-gets "+ao", so never compare the mode against "+o".
                let has_op_access = account.as_deref().is_some_and(|a| self.db.channel(&channel).is_some_and(|c| c.is_op(a)));
                let entrymsg = self.db.channel(&channel).map(|c| c.entrymsg.clone()).filter(|m| !m.is_empty());
                // Computed before the match below moves `channel` into its actions.
                let greet = self.greet_on_join(&channel, account.as_deref());
                let mut acts = std::mem::take(&mut watch);
                // A services bot assigned here is opped on join and is never subject
                // to secureops/restricted — it's staff, not a member.
                let is_bot = self.bot_uids.values().any(|b| b == &uid);
                // A user barred by the deny flag never keeps status (#549).
                let denied = account.as_deref().is_some_and(|a| self.db.channel(&channel).is_some_and(|c| c.denied(a)));
                // SECUREOPS: a user who arrives opped (FJOIN prefix) but lacks op-level
                // access loses it, unless we're about to grant it to them anyway.
                if op && !is_bot && (denied || (!has_op_access && self.db.channel(&channel).is_some_and(|c| c.settings.secureops))) {
                    acts.push(NetAction::ChannelMode { from: from.clone(), channel: channel.clone(), modes: format!("-o {uid}") });
                }
                // RESTRICTED: only users with access (or opers) may be in the channel.
                if mode.is_none() && !is_bot && self.db.channel(&channel).is_some_and(|c| c.settings.restricted) {
                    let is_oper = account.as_deref().is_some_and(|a| self.oper_privs(a).any());
                    if !is_oper {
                        acts.push(NetAction::Kick { from, channel, uid, reason: "This channel is restricted to users with access.".to_string() });
                        return self.finish(out, acts);
                    }
                }
                // AUTOOP (on by default): the channel must allow it and the user
                // must want it (NickServ SET AUTOOP) — either can opt out.
                let autoop = self.db.channel(&channel).is_none_or(|c| !c.settings.noautoop)
                    && account.as_deref().is_none_or(|a| self.db.account_wants_autoop(a));
                match mode {
                    // A user with access gets their status mode, plus the entry message.
                    Some(m) => {
                        if let Some(msg) = entrymsg {
                            acts.push(NetAction::Notice { from: from.clone(), to: uid.clone(), text: msg });
                        }
                        if autoop {
                            acts.push(NetAction::ChannelMode { from, channel, modes: echo_api::status_mode(m, &uid) });
                        }
                    }
                    // No access: an auto-kick match is banned and kicked, else greeted.
                    None => {
                        let hit = self.akick_hit(&uid, &channel);
                        if !hit.is_empty() {
                            acts.extend(hit);
                        } else if let Some(msg) = entrymsg {
                            acts.push(NetAction::Notice { from, to: uid, text: msg });
                        }
                    }
                }
                // GREET: if the channel shows greets and this member has channel
                // access + a personal greet, the assigned bot displays it.
                if let Some(g) = greet {
                    acts.push(g);
                    self.bump("botserv.greet");
                }
                acts
            }
            NetEvent::Part { uid, channel, reason } => {
                // Match before dropping membership so the identity is still resolvable.
                let what = if reason.is_empty() { format!("left {channel}") } else { format!("left {channel} ({reason})") };
                let mut out: Vec<NetAction> = self.notify_line('p', &uid, Some(&channel), &what).into_iter().collect();
                out.extend(self.member_left(&channel, &uid));
                out
            }
            NetEvent::Kicked { channel, uid, by, reason } => {
                // Two watches can fire: the victim and the kicker. Resolve nicks and
                // match before the membership drop.
                let bynick = self.network.nick_of(&by).unwrap_or(&by).to_string();
                let victim = self.network.nick_of(&uid).unwrap_or(&uid).to_string();
                let tail = if reason.is_empty() { String::new() } else { format!(" ({reason})") };
                let mut out = Vec::new();
                if let Some(l) = self.notify_line('k', &uid, Some(&channel), &format!("was kicked from {channel} by {bynick}{tail}")) {
                    out.push(l);
                }
                if let Some(l) = self.notify_line('k', &by, Some(&channel), &format!("kicked {victim} from {channel}{tail}")) {
                    out.push(l);
                }
                out.extend(self.member_left(&channel, &uid));
                out
            }
            // A channel was renamed elsewhere (a client on another server, or an
            // ircd oper override). Move our membership projection, and — if it was
            // a registered channel we didn't rename ourselves — move the
            // registration too so the DB name matches the live channel.
            NetEvent::ChannelRename { old, new } => {
                self.network.channel_rename(&old, &new);
                if self.db.channel(&old).is_some() && self.db.channel(&new).is_none() {
                    let _ = self.db.rename_channel(&old, &new);
                }
                Vec::new()
            }
            NetEvent::ChannelOp { channel, uid, op } => {
                self.network.set_op(&channel, &uid, op);
                // SECUREOPS: a user who gains +o without op-level access loses it.
                // A services bot assigned here is staff, not a member — never subject
                // to secureops (the Join path exempts it the same way).
                let is_bot = self.bot_uids.values().any(|b| b == &uid);
                if op && !is_bot {
                    let account = self.network.account_of(&uid).map(str::to_string);
                    if let Some(c) = self.db.channel(&channel) {
                        // Strip +o for a denied user (always), or under secureops from a
                        // user without op-level access.
                        let denied = account.as_deref().is_some_and(|a| c.denied(a));
                        let secure = c.settings.secureops && !account.as_deref().is_some_and(|a| c.is_op(a));
                        if denied || secure {
                            let from = self.chan_service.clone().unwrap_or_default();
                            return self.finish(out, vec![NetAction::ChannelMode { from, channel, modes: format!("-o {uid}") }]);
                        }
                    }
                }
                Vec::new()
            }
            NetEvent::ChannelVoice { channel, uid, voice } => {
                self.network.set_voice(&channel, &uid, voice);
                // SECUREVOICES: a user who gains +v without voice-level (or higher)
                // access loses it. A services bot is staff, never a member.
                let is_bot = self.bot_uids.values().any(|b| b == &uid);
                if voice && !is_bot {
                    let account = self.network.account_of(&uid).map(str::to_string);
                    if let Some(c) = self.db.channel(&channel) {
                        // Strip +v for a denied user (always), or under securevoices from
                        // a user without voice-level (or higher) access.
                        let denied = account.as_deref().is_some_and(|a| c.denied(a));
                        let secure = c.settings.securevoices && !account.as_deref().is_some_and(|a| c.join_mode(a).is_some());
                        if denied || secure {
                            let from = self.chan_service.clone().unwrap_or_default();
                            return self.finish(out, vec![NetAction::ChannelMode { from, channel, modes: format!("-v {uid}") }]);
                        }
                    }
                }
                Vec::new()
            }
            NetEvent::ChannelKey { channel, key } => {
                self.network.set_channel_key(&channel, key);
                Vec::new()
            }
            NetEvent::TopicChange { channel, setter, topic, setby } => {
                let watch = self.notify_line('t', &setter, Some(&channel), &format!("changed the topic of {channel}"));
                // Who set it, as a stable nick!ident@host — NEVER the source uid, which
                // is recycled to another user the instant this connection drops. Prefer
                // the ircd's own setby mask; else snapshot the still-connected source.
                let author = if !setby.is_empty() {
                    setby
                } else {
                    match self.network.nick_of(&setter) {
                        Some(nick) => match (self.network.ident_of(&setter), self.network.host_of(&setter)) {
                            (Some(ident), Some(host)) => format!("{nick}!{ident}@{host}"),
                            _ => nick.to_string(),
                        },
                        None => String::new(),
                    }
                };
                self.network.set_channel_topic(&channel, topic.clone(), author.clone());
                let info = self.db.channel(&channel).map(|c| (c.settings.keeptopic, c.settings.topiclock, c.topic.clone(), c.topic_setter.clone()));
                // The setter may change a locked topic only with op-level access.
                let authorized = self.network.account_of(&setter).and_then(|a| self.db.channel(&channel).map(|c| c.is_op(a))).unwrap_or(false);
                let mut out: Vec<NetAction> = match info {
                    // TOPICLOCK + unauthorised: put the kept topic back, keeping its author.
                    Some((_, true, stored, stored_by)) if !authorized => {
                        let from = self.chan_service.clone().unwrap_or_default();
                        vec![NetAction::Topic { from, channel, topic: stored, setter: stored_by }]
                    }
                    // Otherwise remember the new topic if the channel keeps it.
                    Some((keep, lock, _, _)) if keep || lock => {
                        let _ = self.db.set_channel_topic(&channel, &topic, &author);
                        Vec::new()
                    }
                    _ => Vec::new(),
                };
                out.extend(watch);
                out
            }
            NetEvent::Quit { uid, reason } => {
                // Match before we forget them, so their identity is still resolvable.
                let what = if reason.is_empty() { "disconnected".to_string() } else { format!("disconnected ({reason})") };
                let mut out: Vec<NetAction> = self.notify_line('d', &uid, None, &what).into_iter().collect();
                out.extend(self.forget_user(&uid));
                out
            }
            NetEvent::UserMode { uid, modes } => {
                self.network.apply_user_mode(&uid, &modes);
                let mut out: Vec<NetAction> = self.notify_line('u', &uid, None, &format!("set user mode {modes}")).into_iter().collect();
                // On deoper the ircd leaves the oper vhost applied; put back the user's
                // services vhost, or the connect-time cloak if they have none (#462).
                if !self.is_own_client(&uid) && mode_removed(&modes, 'o') {
                    out.extend(self.restore_host_after_deoper(&uid));
                }
                out
            }
            NetEvent::OperUp { uid, oper_type } => {
                self.network.set_user_oper(&uid, oper_type.clone());
                let what = if oper_type.is_empty() { "opered up".to_string() } else { format!("opered up as \x02{oper_type}\x02") };
                let mut out: Vec<NetAction> = self.notify_line('o', &uid, None, &what).into_iter().collect();
                // #556: once linked (not on the burst), warn an oper who authed with a
                // TLS cert that isn't on their account — the ircd only checks the oper
                // block, never the account's own cert list.
                if self.synced {
                    if let (Some(ns), Some(account), Some(fp)) = (self.nick_service.clone(), self.network.account_of(&uid).map(str::to_string), self.network.fingerprint_of(&uid).map(|f| f.to_ascii_lowercase())) {
                        let certs = self.db.certfps(&account);
                        if !certs.is_empty() && !certs.contains(&fp) {
                            let lang = self.lang_for_uid(&uid);
                            let text = echo_api::render(&lang, "You opered up with a TLS certificate fingerprint that isn't on your account. Add it with \x02/msg NickServ CERT ADD\x02.", &[]);
                            out.push(NetAction::Notice { from: ns, to: uid.clone(), text });
                        }
                    }
                }
                out
            }
            NetEvent::UserKilled { uid } => {
                // A killed service agent (NickServ, ChanServ, …) has a fixed uid;
                // bring it straight back so an oper can't KILL it off the network.
                if let Some(intro) = self.services.iter().find(|s| s.uid() == uid).map(|s| NetAction::IntroduceUser {
                    uid: s.uid().to_string(),
                    nick: s.nick().to_string(),
                    ident: "services".to_string(),
                    host: s.host().to_string(),
                    gecos: s.gecos().to_string(),
                }) {
                    return self.finish(out, vec![intro]);
                }
                // If the ircd killed one of our bots, forget it so reconcile
                // reintroduces it (and rejoins its channels); a killed real user is
                // simply gone.
                if let Some(bot_lc) = self.bot_uids.iter().find_map(|(lc, u)| (u == &uid).then(|| lc.clone())) {
                    self.bot_uids.remove(&bot_lc);
                    self.bot_idents.remove(&bot_lc);
                    self.network.bot_forget(&bot_lc);
                    self.bot_channels.retain(|(b, _)| *b != bot_lc);
                    let bots = self.reconcile_bots();
                    return self.finish(out, bots);
                }
                self.forget_user(&uid)
            }
            NetEvent::ServerLink { sid, parent } => {
                self.network.server_link(&sid, &parent);
                Vec::new()
            }
            NetEvent::ServerSplit { server } => {
                // A hub's SQUIT arrives once but takes its whole subtree with it;
                // forget every user behind the departed server and its descendants.
                for sid in self.network.server_split(&server) {
                    for uid in self.network.uids_on_server(&sid) {
                        // Drop guest games as usual, but swallow the opponent notices:
                        // a netsplit is a mass event and must not spray "opponent left".
                        let _ = self.forget_user(&uid);
                    }
                }
                Vec::new()
            }
            NetEvent::Privmsg { from, to, text, msgid } => self.dispatch(&from, &to, &text, msgid),
            NetEvent::AccountRequest { reqid, origin, kind, account, p2, p3 } => {
                self.account_request(reqid, origin, kind, account, p2, p3)
            }
            NetEvent::Sasl { client, mode, data, .. } => self.sasl(client, mode, data),
            _ => Vec::new(),
        };
        // In tests there is no link layer to run DeferAuthenticate off-thread, so
        // resolve it inline (test iteration counts are cheap) — the login finish is
        // exactly what the link layer produces, and it must happen before
        // track_accounts so the login is recorded within this handle().
        self.finish(out, evout)
    }

    // The shared tail of `handle`: fold committed events into account tracking,
    // append them to any output already pending (kicker-ban unbans swept at the
    // top of `handle`), stamp every user-removal with a searchable incident id,
    // and degrade IRCv3 standard replies when they can't be sent. Every early
    // return in `handle` routes through here, so none of these side-effects is
    // skipped on the kill/kick/restricted paths.
    fn finish(&mut self, mut out: Vec<NetAction>, evout: Vec<NetAction>) -> Vec<NetAction> {
        #[cfg(test)]
        let evout: Vec<NetAction> = evout
            .into_iter()
            .flat_map(|a| match a {
                NetAction::DeferAuthenticate { verifier, password, then } => {
                    let ok = crate::engine::scram::verify_plain(crate::engine::scram::Hash::Sha256, &verifier, &password);
                    self.complete_authenticate(ok, then)
                }
                other => vec![other],
            })
            .collect();
        self.track_accounts(&evout);
        out.extend(evout);
        // Give every user-removal a traceable incident id, stamped into its reason
        // and recorded in the searchable log (OperServ LOGSEARCH).
        self.stamp_incidents(&mut out);
        // When standard replies are off (or the ircd module isn't loaded), a
        // FAIL/WARN/NOTE would be dropped — degrade each to a plain notice so the
        // user always hears the outcome.
        if !self.standard_replies {
            self.degrade_standard_replies(&mut out);
        }
        out
    }

    // Rewrite any StandardReply into an equivalent Notice `*** command: text`
    // (or `*** text` when there's no command), sourced from the same service.
    fn degrade_standard_replies(&self, actions: &mut [NetAction]) {
        for a in actions.iter_mut() {
            let slot = a.inner_mut();
            if let NetAction::StandardReply { from, to, command, text, .. } = slot {
                let body = if command.is_empty() || command == "*" {
                    format!("*** {text}")
                } else {
                    format!("*** {command}: {text}")
                };
                *slot = NetAction::Notice { from: std::mem::take(from), to: std::mem::take(to), text: body };
            }
        }
    }

    // Mint an incident id for each kick/kill in `actions`, append `[#id]` to its
    // reason, and record a searchable summary. One choke-point so every removal —
    // from a bot kicker, a fantasy command, a vote, or an operator — is logged.
    fn stamp_incidents(&mut self, actions: &mut [NetAction]) {
        let now = self.now_secs();
        for a in actions.iter_mut() {
            match a {
                NetAction::Kick { channel, uid, reason, .. } => {
                    let target = self.network.nick_of(uid).unwrap_or(uid).to_string();
                    let summary = format!("kicked \x02{target}\x02 from \x02{channel}\x02: {reason}");
                    let id = self.network.record_incident(summary, now);
                    reason.push_str(&format!(" [#{id}]"));
                }
                NetAction::KillUser { uid, reason, .. } => {
                    let target = self.network.nick_of(uid).unwrap_or(uid).to_string();
                    let summary = format!("killed \x02{target}\x02: {reason}");
                    let id = self.network.record_incident(summary, now);
                    reason.push_str(&format!(" [#{id}]"));
                }
                _ => {}
            }
        }
    }

    // Remove kicker bans whose BANEXPIRE has elapsed, sourced from ChanServ.
    fn sweep_unbans(&mut self) -> Vec<NetAction> {
        if self.pending_unbans.is_empty() {
            return Vec::new();
        }
        let now = self.now_secs();
        let mut out = Vec::new();
        self.pending_unbans.retain(|u| {
            if u.at <= now {
                out.push(NetAction::ChannelMode { from: u.from.clone(), channel: u.channel.clone(), modes: format!("-b {}", u.mask) });
                false
            } else {
                true
            }
        });
        out
    }

    // Keep per-user login state in step with the accountname metadata we send:
    // a non-empty value (SASL/IDENTIFY/REGISTER) logs the uid in, an empty one
    // (LOGOUT) logs it out. Server-global metadata ("*") is not a login.
    fn track_accounts(&mut self, actions: &[NetAction]) {
        for action in actions {
            if let NetAction::Metadata { target, key, value } = action {
                if key == "accountname" && target != "*" {
                    if value.is_empty() {
                        self.network.clear_account(target);
                        // Drop the "registered" user mode when logging out.
                        self.emit_irc(NetAction::UserMode { uid: target.clone(), modes: "-r".to_string() });
                    } else {
                        self.network.set_account(target, value);
                        // Set the "registered" user mode (+r) now that they're identified.
                        self.emit_irc(NetAction::UserMode { uid: target.clone(), modes: "+r".to_string() });
                        // Identified now: cancel any pending nick-protection rename.
                        self.pending_enforce.retain(|p| p.uid != *target);
                        // A login is activity: keep the account from expiring.
                        self.db.mark_account_seen(value, self.now_secs());
                        // An operator logging in is shown the staff (oper) news.
                        if self.oper_privs(value).any() {
                            for note in self.news_notices(NewsKind::Oper, "Staff News", target) {
                                self.emit_irc(note);
                            }
                        }
                    }
                }
            }
        }
    }

    // Record the state changes a just-run command made (the events appended since
    // `mark`) to the searchable incident log, and — when an audit channel is
    // configured — announce each to it, sourced from the services server. Private
    // and purely cosmetic events are deliberately not surfaced.
    fn audit_feed(&mut self, mark: usize, nick: &str, account: Option<&str>) -> Vec<NetAction> {
        let tagged: Vec<(&'static str, String)> = self.db.events_since(mark).iter()
            .filter_map(|e| audit_summary(e).map(|s| (event_category(e), s)))
            .collect();
        if tagged.is_empty() {
            return Vec::new();
        }
        // Name the actor by nick, plus the account they are identified to when it
        // differs — the account is the identity that outlives the nick.
        let actor = match account {
            Some(a) if !a.eq_ignore_ascii_case(nick) => format!("\x02{nick}\x02 ({a})"),
            _ => format!("\x02{nick}\x02"),
        };
        let now = self.now_secs();
        let mut out = Vec::new();
        for (cat, summary) in tagged {
            let line = format!("{actor} {summary}");
            self.network.record_incident(line.clone(), now);
            // Prefer DebugServ's voice; fall back to a server notice when it's off.
            match self.feed(cat, line.clone()) {
                Some(action) => out.push(action),
                None => if let (Some(channel), false) = (&self.log_channel, self.sid.is_empty()) {
                    out.push(NetAction::Notice { from: self.sid.clone(), to: channel.clone(), text: line });
                },
            }
        }
        out
    }

    // The greet a channel's bot shows when a member logged into `account` joins:
    // only when greets are enabled for the channel, the member holds channel
    // access, and has set a non-empty personal greet.
    // The uid a channel's own actions are sourced from: its assigned bot if one is
    // live, else ChanServ — so in-channel actions (auto-op, mode lock, entry
    // message) front as the bot when the channel has one, like Anope.
    fn channel_mode_source(&self, channel: &str) -> String {
        self.db.channel(channel)
            .and_then(|c| c.assigned_bot.clone())
            .map(|b| b.to_ascii_lowercase())
            .and_then(|b| self.bot_uids.get(&b).cloned())
            .or_else(|| self.chan_service.clone())
            .unwrap_or_default()
    }

    fn greet_on_join(&self, channel: &str, account: Option<&str>) -> Option<NetAction> {
        let acc = account?;
        let c = self.db.channel(channel)?;
        if !c.settings.bot_greet || c.join_mode(acc).is_none() {
            return None;
        }
        let bot = c.assigned_bot.clone()?;
        let greet = self.db.account(acc)?.greet.clone();
        if greet.is_empty() {
            return None;
        }
        let botuid = self.network.uid_by_nick(&bot)?.to_string();
        Some(NetAction::Privmsg { from: botuid, to: channel.to_string(), text: format!("[{acc}] {greet}") })
    }

    // Ban+kick `uid` from `channel` if their current identity matches its akick
    // list. Parts them locally and returns the +b/KICK; empty when no match.
    fn akick_hit(&mut self, uid: &str, channel: &str) -> Vec<NetAction> {
        let matched = {
            let target = self.network.ban_target(uid);
            target.as_ref().and_then(|t| {
                self.db.channel(channel).and_then(|c| c.akick_match(t)).map(|k| {
                    let reason = if k.reason.is_empty() { "You are banned from this channel.".to_string() } else { k.reason.clone() };
                    (k.mask.clone(), reason)
                })
            })
        };
        match matched {
            Some((mask, reason)) => {
                let from = self.channel_mode_source(channel);
                self.network.channel_part(channel, uid);
                vec![
                    NetAction::ChannelMode { from: from.clone(), channel: channel.to_string(), modes: format!("+b {mask}") },
                    NetAction::Kick { from, channel: channel.to_string(), uid: uid.to_string(), reason },
                ]
            }
            None => Vec::new(),
        }
    }

    // A nick change rewrites the user's n!u@h, so re-run the akick check the join
    // path does — otherwise a user joins clean, switches to a banned nick, and stays.
    // Access holders are exempt, as on join.
    fn enforce_akick_on_nick(&mut self, uid: &str) -> Vec<NetAction> {
        let mut acts = Vec::new();
        let account = self.network.account_of(uid).map(str::to_string);
        for channel in self.network.channels_of(uid) {
            if self.db.is_channel_suspended(&channel) {
                continue;
            }
            if account.as_deref().and_then(|a| self.db.channel_join_mode(&channel, a)).is_some() {
                continue;
            }
            acts.extend(self.akick_hit(uid, &channel));
        }
        acts
    }

    // Fantasy commands: `!op nick`, `!kick nick`, `!topic …` spoken in a channel
    // that has a bot assigned. We reuse ChanServ's real command handlers — the
}

// A human label for a network-ban X-line kind, for the audit feed.
// The audit feed labels the ban kind from the persisted (string) event token; an
// unmodelled/peer kind falls back to the generic label.
fn ban_kind_label(kind: &str) -> &'static str {
    echo_api::XlineKind::from_wire(kind).map(|k| k.label()).unwrap_or("network ban")
}

// A rough human span for an expiry deadline in an email ("7 days", "12 hours").
fn human_duration(secs: u64) -> String {
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    match secs {
        s if s >= 86_400 => plural(s / 86_400, "day"),
        s if s >= 3_600 => plural(s / 3_600, "hour"),
        s if s >= 60 => plural(s / 60, "minute"),
        s => plural(s.max(1), "second"),
    }
}

// A coarse category tag for the DebugServ feed, sorting committed events into
// account, channel, or operator/enforcement lanes (the catch-all). Purely
// cosmetic — a miscategorised line is harmless.
fn event_category(event: &db::Event) -> &'static str {
    use db::Event::*;
    match event {
        AccountRegistered(_) | AccountDropped { .. } | AccountVerified { .. }
        | AccountPasswordSet { .. } | AccountEmailSet { .. } | CertAdded { .. }
        | CertRemoved { .. } | AccountSuspended { .. } | AccountUnsuspended { .. }
        | NickGrouped { .. } | NickUngrouped { .. } | VhostSet { .. } | VhostDeleted { .. }
        | AccountOperNoteSet { .. } => "ACCT",
        ChannelRegistered { .. } | ChannelDropped { .. } | ChannelFounderSet { .. }
        | ChannelSuccessorSet { .. } | ChannelAccessAdd { .. } | ChannelAccessDel { .. }
        | ChannelAkickAdd { .. } | ChannelAkickDel { .. } | ChannelSuspended { .. }
        | ChannelUnsuspended { .. } | ChannelBotAssigned { .. } | ChannelBotUnassigned { .. }
        | ChannelOperNoteSet { .. } => "CHAN",
        _ => "OPER",
    }
}

// echo's ircd module dependencies: (module, critical?, the feature it enables).
const IRCD_DEPS: &[(&str, bool, &str)] = &[
    ("account", true, "account login tracking"),
    ("services", true, "services-server privileges (SVS*, u-line)"),
    ("rline", false, "regex realname bans (SNLINE)"),
    ("chghost", false, "vhosts (HostServ)"),
    ("chgident", false, "vidents (HostServ)"),
    ("cban", false, "channel-name bans (CBAN)"),
    ("ircv3_ctctags", false, "tag messages (GameServ)"),
];

// At CAPAB END, check the modules the ircd advertised against echo's dependencies,
// so a missing one is a clear diagnostic at link rather than a silent malfunction.
fn verify_ircd_dependencies(net: &Network) {
    if net.module_count() == 0 {
        return; // the ircd didn't advertise its modules — nothing to verify against
    }
    let mut missing = 0;
    for &(module, critical, feature) in IRCD_DEPS {
        if !net.has_module(module) {
            missing += 1;
            if critical {
                tracing::error!(module, "REQUIRED ircd module not loaded — {feature} will not work");
            } else {
                tracing::warn!(module, "ircd module not loaded — {feature} is unavailable");
            }
        }
    }
    if missing == 0 {
        tracing::info!(count = net.module_count(), "verified ircd module dependencies");
    }
}

// A one-line, human-readable summary of a logged event for the staff audit
// feed, or None for events that are private (memos), cosmetic self-service
// (greets, auto-join, personal settings), or otherwise not worth surfacing.
// Never include secrets: password/verifier material and memo bodies are elided.
fn audit_summary(event: &db::Event) -> Option<String> {
    use db::Event::*;
    let s = match event {
        AccountRegistered(a) => format!("registered account \x02{}\x02", a.name),
        AccountDropped { account } => format!("dropped account \x02{account}\x02"),
        AccountVerified { account } => format!("verified account \x02{account}\x02"),
        AccountPasswordSet { account, .. } => format!("changed the password on \x02{account}\x02"),
        AccountEmailSet { account, email } => match email {
            Some(_) => format!("set the email on \x02{account}\x02"),
            None => format!("cleared the email on \x02{account}\x02"),
        },
        AccountSwhoisSet { account, text } => match text {
            Some(t) => format!("set the SWHOIS on \x02{account}\x02 to \x02{t}\x02"),
            None => format!("cleared the SWHOIS on \x02{account}\x02"),
        },
        CertAdded { account, fp } => format!("added cert \x02{fp}\x02 to \x02{account}\x02"),
        CertRemoved { account, fp } => format!("removed cert \x02{fp}\x02 from \x02{account}\x02"),
        AccountSuspended { account, reason, .. } => format!("suspended account \x02{account}\x02 ({reason})"),
        AccountUnsuspended { account } => format!("unsuspended account \x02{account}\x02"),
        NickGrouped { nick, account } => format!("grouped nick \x02{nick}\x02 to \x02{account}\x02"),
        NickUngrouped { nick } => format!("ungrouped nick \x02{nick}\x02"),
        VhostSet { account, host, expires, .. } => {
            let kind = if expires.is_some() { " (temporary)" } else { "" };
            format!("set vhost \x02{host}\x02 on \x02{account}\x02{kind}")
        }
        VhostDeleted { account } => format!("removed the vhost on \x02{account}\x02"),
        ChannelRegistered { name, founder, .. } => format!("registered channel \x02{name}\x02 (founder \x02{founder}\x02)"),
        ChannelDropped { name } => format!("dropped channel \x02{name}\x02"),
        ChannelRenamed { old, new } => format!("renamed channel \x02{old}\x02 to \x02{new}\x02"),
        ChannelFounderSet { channel, founder } => format!("set founder of \x02{channel}\x02 to \x02{founder}\x02"),
        ChannelSuccessorSet { channel, successor } => match successor {
            Some(s) => format!("set successor of \x02{channel}\x02 to \x02{s}\x02"),
            None => format!("cleared the successor of \x02{channel}\x02"),
        },
        ChannelAccessAdd { channel, account, level } => format!("set \x02{account}\x02 to {level} on \x02{channel}\x02"),
        ChannelAccessDel { channel, account } => format!("removed \x02{account}\x02 from \x02{channel}\x02 access"),
        ChannelAkickAdd { channel, mask, reason } => format!("added akick \x02{mask}\x02 on \x02{channel}\x02 ({reason})"),
        ChannelAkickDel { channel, mask } => format!("removed akick \x02{mask}\x02 on \x02{channel}\x02"),
        ChannelLevelSet { channel, cap, role } => format!("set level \x02{cap}\x02 to \x02{role}\x02 on \x02{channel}\x02"),
        ChannelLevelReset { channel, cap } => format!("reset level \x02{cap}\x02 on \x02{channel}\x02"),
        ChannelSuspended { channel, reason, .. } => format!("suspended channel \x02{channel}\x02 ({reason})"),
        ChannelUnsuspended { channel } => format!("unsuspended channel \x02{channel}\x02"),
        ChannelBotAssigned { channel, bot } => format!("assigned bot \x02{bot}\x02 to \x02{channel}\x02"),
        ChannelBotUnassigned { channel } => format!("removed the bot from \x02{channel}\x02"),
        BotAdded(b) => format!("added bot \x02{}\x02", b.nick),
        BotRemoved { nick } => format!("removed bot \x02{nick}\x02"),
        DefaultBotSet { bot } => match bot {
            Some(b) => format!("set the auto-assign bot to \x02{b}\x02"),
            None => "cleared the auto-assign bot".to_string(),
        },
        VhostOfferAdded { host } => format!("added vhost offer \x02{host}\x02"),
        VhostOfferRemoved { host } => format!("removed vhost offer \x02{host}\x02"),
        VhostForbidAdded { pattern } => format!("forbade vhost pattern \x02{pattern}\x02"),
        VhostForbidRemoved { pattern } => format!("un-forbade vhost pattern \x02{pattern}\x02"),
        VhostTemplateSet { template } => match template {
            Some(t) => format!("set the vhost template to \x02{t}\x02"),
            None => "cleared the vhost template".to_string(),
        },
        AkillAdded { kind, mask, reason, expires, .. } => {
            let temp = if expires.is_some() { " (temporary)" } else { "" };
            format!("set a {} on \x02{mask}\x02{temp} ({reason})", ban_kind_label(kind))
        }
        AkillRemoved { kind, mask } => format!("lifted the {} on \x02{mask}\x02", ban_kind_label(kind)),
        FilterAdded { pattern, action, reason, .. } => format!("added a \x02{action}\x02 spam filter on \x02{pattern}\x02 ({reason})"),
        FilterRemoved { pattern } => format!("removed the spam filter on \x02{pattern}\x02"),
        ForbidAdded { kind, mask, reason, .. } => format!("forbade {} \x02{mask}\x02 ({reason})", kind.to_ascii_lowercase()),
        ForbidRemoved { kind, mask } => format!("un-forbade {} \x02{mask}\x02", kind.to_ascii_lowercase()),
        NotifyAdded { mask, flags, .. } => format!("added a notify watch on \x02{mask}\x02 [{flags}]"),
        NotifyRemoved { mask } => format!("removed the notify watch on \x02{mask}\x02"),
        JupeAdded { name, reason, .. } => format!("juped server \x02{name}\x02 ({reason})"),
        JupeRemoved { name } => format!("lifted the jupe on \x02{name}\x02"),
        AccountOperNoteSet { account, note } => match note {
            Some(_) => format!("set a staff note on \x02{account}\x02"),
            None => format!("cleared the staff note on \x02{account}\x02"),
        },
        ChannelOperNoteSet { channel, note } => match note {
            Some(_) => format!("set a staff note on \x02{channel}\x02"),
            None => format!("cleared the staff note on \x02{channel}\x02"),
        },
        NewsAdded { kind, .. } => format!("added a \x02{kind}\x02 bulletin"),
        NewsDeleted { .. } => "removed a bulletin".to_string(),
        ReportFiled { reporter, target, reason, .. } => format!("\x02{reporter}\x02 reported \x02{target}\x02: {reason}"),
        ReportClosed { id } => format!("closed report #{id}"),
        ReportDeleted { id } => format!("deleted report #{id}"),
        HelpRequested { requester, message, .. } => format!("\x02{requester}\x02 asked for help: {message}"),
        HelpTaken { id, handler } => format!("\x02{handler}\x02 took help ticket #{id}"),
        HelpClosed { id } => format!("closed help ticket #{id}"),
        GroupRegistered { name, founder, .. } => format!("registered group \x02{name}\x02 (founder \x02{founder}\x02)"),
        GroupDropped { name } => format!("dropped group \x02{name}\x02"),
        GroupFounderSet { name, founder } => format!("set founder of \x02{name}\x02 to \x02{founder}\x02"),
        GroupFlagsSet { name, account, flags } => {
            if flags.is_empty() {
                format!("added \x02{account}\x02 to group \x02{name}\x02")
            } else {
                format!("set \x02{account}\x02 in group \x02{name}\x02 to \x02{flags}\x02")
            }
        }
        GroupMemberDel { name, account } => format!("removed \x02{account}\x02 from group \x02{name}\x02"),
        OperGranted { account, privs, .. } => format!("granted \x02{account}\x02 operator ({})", privs.join(", ")),
        OperRevoked { account } => format!("revoked \x02{account}\x02's operator access"),
        SessionExceptionAdded { mask, limit, .. } => format!("set a session exception \x02{mask}\x02 (limit {limit})"),
        SessionExceptionRemoved { mask } => format!("removed the session exception \x02{mask}\x02"),
        AccountNoExpire { account, on } => {
            let verb = if *on { "pinned" } else { "unpinned" };
            format!("{verb} account \x02{account}\x02 against expiry")
        }
        ChannelNoExpire { channel, on } => {
            let verb = if *on { "pinned" } else { "unpinned" };
            format!("{verb} channel \x02{channel}\x02 against expiry")
        }
        // Private, self-service, or cosmetic — not surfaced.
        AjoinAdded { .. } | AjoinRemoved { .. } | AccountGreetSet { .. } | AccountSignoreSet { .. } | AccountLanguageSet { .. } | AccountProfileSet { .. } | AccountAutoOpSet { .. } | AccountKillSet { .. } | AccountHideStatusSet { .. } | AccountSnoticeSet { .. } | VhostRequested { .. }
        | VhostRequestCleared { .. } | MemoSent { .. } | MemoRead { .. } | MemoDeleted { .. }
        | MemoIgnoreAdd { .. } | MemoIgnoreDel { .. } | MemoPrefsSet { .. }
        | ChannelMlock { .. } | ChannelDescSet { .. } | ChannelEntryMsgSet { .. } | ChannelUrlSet { .. } | ChannelEmailSet { .. } | ChannelSettingsSet { .. }
        | ChannelKickerSet { .. } | ChannelBadwordsSet { .. } | ChannelTriggersSet { .. }
        | ChannelTopicSet { .. } | AccountSeen { .. } | ChannelUsed { .. }
        | AccountExpiryWarned { .. } | ChannelExpiryWarned { .. } | StatsSet { .. } | IncidentsSet { .. } => return None,
    };
    Some(s)
}

// Rewrite the source uid of an action from `old` to `new`, where the variant
// carries a `from`. Used to make fantasy output appear to come from the bot.
// True if an IRC mode string (e.g. "+i-o") removes `letter`.
fn mode_removed(modes: &str, letter: char) -> bool {
    let mut adding = true;
    for c in modes.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            l if l == letter && !adding => return true,
            _ => {}
        }
    }
    false
}

fn resource_action(a: &mut NetAction, old: &str, new: &str) {
    let from = match a.inner_mut() {
        NetAction::Notice { from, .. }
        | NetAction::Privmsg { from, .. }
        | NetAction::ChannelMode { from, .. }
        | NetAction::Kick { from, .. }
        | NetAction::Topic { from, .. }
        | NetAction::Invite { from, .. } => from,
        _ => return,
    };
    if from == old {
        *from = new.to_string();
    }
}

// Decode a SASL PLAIN payload (authzid \0 authcid \0 passwd) and authenticate
// it, returning the canonical account name on success.
// A case-insensitive 64-bit hash of a line, for the REPEAT kicker. Allocation-
// free (folds each byte to lowercase in place) so it stays cheap on the hot
// path; a 64-bit collision causing a spurious kick is astronomically unlikely.
// A hash of a bot's identity (user/host/gecos), so reconcile can tell when a
// BOT CHANGE altered it without changing the nick.
fn ident_hash(user: &str, host: &str, gecos: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    user.hash(&mut h);
    host.hash(&mut h);
    gecos.hash(&mut h);
    h.finish()
}

fn ci_hash(text: &str) -> u64 {
    use std::hash::Hasher;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for b in text.bytes() {
        h.write_u8(b.to_ascii_lowercase());
    }
    h.finish()
}

// Decode a SASL PLAIN response into (authcid, password). The verify itself is
// deferred off the lock, so this no longer touches the store.
fn decode_plain(b64: &str) -> Option<(String, String)> {
    let raw = STANDARD.decode(b64).ok()?;
    let parts: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authcid = std::str::from_utf8(parts[1]).ok()?.to_string();
    let passwd = std::str::from_utf8(parts[2]).ok()?.to_string();
    Some((authcid, passwd))
}

// Report SASL failure to the ircd (drives 904).
// Strip control codes (colour/bold, CR/LF, NUL) and cap the length before a
// string goes into a feed line. An account name on a failed attempt is
// attacker-supplied, so it must never inject into the channel message.
fn safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(48).collect()
}

fn sasl_fail(agent: &str, client: &str) -> Vec<NetAction> {
    vec![NetAction::Sasl { agent: agent.to_string(), client: client.to_string(), mode: "D".to_string(), data: vec!["F".to_string()] }]
}

// The two actions that complete any mechanism: set the account (drives 900),
// then report SASL success (drives 903).
fn sasl_success(agent: &str, client: &str, account: String) -> Vec<NetAction> {
    vec![
        NetAction::Metadata { target: client.to_string(), key: "accountname".to_string(), value: account },
        NetAction::Sasl { agent: agent.to_string(), client: client.to_string(), mode: "D".to_string(), data: vec!["S".to_string()] },
    ]
}

// Outcome of a registration attempt, rendered to the right wire response below.
enum RegOutcome {
    Ok,
    /// Registered, but an emailed code must be confirmed before it's verified.
    VerifyRequired,
    /// The name is on the OperServ FORBID list.
    Forbidden,
    /// The supplied email matches an OperServ FORBID EMAIL pattern.
    ForbiddenEmail,
    Exists,
    RateLimited,
    Frozen,
    External,
    Internal,
}

// Render a registration outcome for whichever origin asked (relay or NickServ),
// so both the pre-check rejection and the post-derivation result share one place.
fn reg_reply(reply: &RegReply, outcome: RegOutcome, account: &str) -> Vec<NetAction> {
    match reply {
        RegReply::Relay { reqid, kind, origin } => {
            let (status, code, message) = match outcome {
                RegOutcome::Ok => ("success", "*", "Account registered."),
                RegOutcome::VerifyRequired => ("verification_required", "VERIFICATION_REQUIRED", "Registered — check your email for a code, then VERIFY."),
                RegOutcome::Forbidden => ("error", "BAD_ACCOUNT_NAME", "That account name is forbidden by network policy."),
                RegOutcome::ForbiddenEmail => ("error", "BAD_EMAIL", "That email address is forbidden by network policy."),
                RegOutcome::Exists => ("error", "ACCOUNT_EXISTS", "That account name is already registered."),
                RegOutcome::RateLimited => ("error", "TEMPORARILY_UNAVAILABLE", "Too many registrations, please wait a moment."),
                RegOutcome::Frozen => ("error", "TEMPORARILY_UNAVAILABLE", "Registrations are temporarily frozen by network staff."),
                RegOutcome::External => ("error", "ACCOUNT_REGISTRATION_DISABLED", "Accounts are managed on the website; register there."),
                RegOutcome::Internal => ("error", "TEMPORARILY_UNAVAILABLE", "Registration is unavailable, try again later."),
            };
            vec![NetAction::AccountResponse {
                reqid: reqid.clone(),
                origin: origin.clone(),
                kind: kind.clone(),
                account: account.to_string(),
                status: status.to_string(),
                code: code.to_string(),
                message: message.to_string(),
            }]
        }
        RegReply::NickServ { agent, uid, nick } => {
            let notice = |text: String| NetAction::Notice { from: agent.clone(), to: uid.clone(), text };
            match outcome {
                // Registering identifies you to the nick right away (drives 900).
                // VerifyRequired still logs you in; the emailed-code notice is
                // appended by complete_register.
                RegOutcome::Ok | RegOutcome::VerifyRequired => vec![
                    NetAction::Metadata { target: uid.clone(), key: "accountname".to_string(), value: nick.clone() },
                    notice(format!("Your nick \x02{nick}\x02 is now registered and you're logged in. Welcome!")),
                ],
                RegOutcome::Forbidden => vec![notice("That nickname is forbidden and can't be registered.".to_string())],
                RegOutcome::ForbiddenEmail => vec![notice("That email address is forbidden by network policy. Use a different one.".to_string())],
                RegOutcome::Exists => vec![notice(format!("\x02{nick}\x02 is already registered. If it's yours, use \x02IDENTIFY <password>\x02."))],
                RegOutcome::RateLimited => vec![notice("Registrations are busy right now. Please try again in a moment.".to_string())],
                RegOutcome::Frozen => vec![notice("Registrations are temporarily frozen by network staff. Please try again later.".to_string())],
                RegOutcome::External => vec![notice("Accounts are managed on the website — register there.".to_string())],
                RegOutcome::Internal => vec![notice("Sorry, that didn't work. Please try again in a moment.".to_string())],
            }
        }
    }
}

// Token bucket bounding how often the expensive registration derivation may run,
// so a REGISTER flood degrades to a trickle instead of pinning a core. Global on
// purpose: it caps total work regardless of which user or server relayed it.
struct RegLimiter {
    tokens: f64,
    last: Instant,
}

const REG_BURST: f64 = 8.0; // registrations allowed back-to-back from a full bucket
const REG_REFILL_PER_SEC: f64 = 0.5; // steady-state: one every two seconds

impl RegLimiter {
    fn new() -> Self {
        Self { tokens: REG_BURST, last: Instant::now() }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * REG_REFILL_PER_SEC).min(REG_BURST);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// A global token bucket bounding how fast echo hits the DICT server, so a channel
// of users spamming !dict can't hammer dict.org (and get echo throttled). Bursts
// of DICT_BURST, then DICT_REFILL_PER_SEC sustained; an over-budget lookup is
// dropped — the bot simply doesn't answer that one.
struct DictLimiter {
    tokens: f64,
    last: Instant,
}

const DICT_BURST: f64 = 6.0;
const DICT_REFILL_PER_SEC: f64 = 1.0;

impl DictLimiter {
    fn new() -> Self {
        Self { tokens: DICT_BURST, last: Instant::now() }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * DICT_REFILL_PER_SEC).min(DICT_BURST);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// Per-host flood control for anonymous service commands. A bot that connects and
// spams `/msg NickServ HELP` in a loop is warned, then silently dropped until it
// slows down — never answered per line, which would just double the flood on
// the wire. A sender may burst up to CMD_BURST commands, then is held to
// CMD_REFILL_PER_SEC sustained (one every two seconds). Keyed by host so a nick
// change or reconnect does not reset the count. Ephemeral; never event-logged.
#[derive(Default)]
struct CmdLimiter {
    buckets: HashMap<String, CmdBucket>,
    last_sweep: Option<Instant>,
}

struct CmdBucket {
    tokens: f64,
    last: Instant,
    last_warn: Option<Instant>, // when we last told this host to slow down
}

const CMD_BURST: f64 = 15.0; // commands allowed back-to-back from a full bucket
const CMD_REFILL_PER_SEC: f64 = 0.5; // steady-state: one every two seconds
const CMD_WARN_EVERY: Duration = Duration::from_secs(30); // at most one "slow down" per host per window
const CMD_SWEEP_EVERY: Duration = Duration::from_secs(60);

enum CmdVerdict {
    Allow, // within budget: run the command
    Warn,  // just went over: send one "slow down" notice, drop the command
    Drop,  // still over and already warned: drop silently
}

impl CmdLimiter {
    fn check(&mut self, key: &str) -> CmdVerdict {
        self.check_at(key, Instant::now())
    }

    fn check_at(&mut self, key: &str, now: Instant) -> CmdVerdict {
        self.sweep(now);
        let b = self.buckets.entry(key.to_string()).or_insert(CmdBucket { tokens: CMD_BURST, last: now, last_warn: None });
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * CMD_REFILL_PER_SEC).min(CMD_BURST);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            return CmdVerdict::Allow;
        }
        // Over budget. Warn at most once per window, then drop silently — a sustained
        // flood that the ircd's fakelag paces to a trickle must not draw a fresh
        // "slow down" on every other line, which would just backscatter the flood.
        if b.last_warn.is_none_or(|w| now.duration_since(w) >= CMD_WARN_EVERY) {
            b.last_warn = Some(now);
            CmdVerdict::Warn
        } else {
            CmdVerdict::Drop
        }
    }

    // Drop buckets that have refilled to full since we last touched them: a full
    // bucket is indistinguishable from a fresh one, so this is lossless and keeps
    // the map bounded to recently-active senders. Runs at most once a minute.
    fn sweep(&mut self, now: Instant) {
        if let Some(last) = self.last_sweep {
            if now.duration_since(last) < CMD_SWEEP_EVERY {
                return;
            }
        }
        self.last_sweep = Some(now);
        self.buckets.retain(|_, b| (b.tokens + now.duration_since(b.last).as_secs_f64() * CMD_REFILL_PER_SEC) < CMD_BURST);
    }
}

#[cfg(test)]
mod tests;
