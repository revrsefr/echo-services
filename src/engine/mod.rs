pub mod db;
pub mod scram;
pub mod service;
pub mod state;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::sync::mpsc;

use crate::proto::{NetAction, NetEvent, RegReply};
use db::{Db, LogEntry, RegError};
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
    reg_limiter: RegLimiter,
    chan_service: Option<String>, // uid to source channel modes from (ChanServ)
    nick_service: Option<String>, // uid of the account service (NickServ), for its notices
    irc_out: Option<mpsc::UnboundedSender<NetAction>>, // services-initiated actions -> the uplink
    opers: HashMap<String, Privs>, // casefolded account -> privileges (from [[oper]] config)
    sid: String, // our services SID, for minting bot uids
    // Nick-protection enforcement. `synced` gates it until the uplink's initial
    // burst is done, so a relink doesn't enforce every already-online user.
    synced: bool,
    guest_nick: String, // base for the Guest#### rename on enforcement
    enforce_seq: u32,   // counter appended to guest_nick
    pending_enforce: Vec<PendingEnforce>, // registered nicks awaiting identify-or-rename
    bot_uids: HashMap<String, String>, // casefolded bot nick -> live uid (per connection)
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
    set: regex::RegexSet,
}

struct CachedTriggers {
    rev: u64,
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
        Self {
            services,
            network,
            db,
            sasl_sessions: HashMap::new(),
            reg_limiter: RegLimiter::new(),
            chan_service,
            nick_service,
            irc_out: None,
            opers: HashMap::new(),
            sid: String::new(),
            synced: false,
            guest_nick: "Guest".to_string(),
            enforce_seq: 0,
            pending_enforce: Vec::new(),
            bot_uids: HashMap::new(),
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
                    out.push(NetAction::ServiceJoin { uid: uid.clone(), channel: chan.clone() });
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
    fn sasl_login(&self, agent: &str, client: &str, account: String) -> Vec<NetAction> {
        if self.db.is_suspended(&account) {
            return sasl_fail(agent, client);
        }
        sasl_success(agent, client, account)
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
    pub fn gossip_digest(&self) -> HashMap<String, u64> {
        self.db.version_vector()
    }

    pub fn gossip_missing(&self, peer: &HashMap<String, u64>) -> Vec<LogEntry> {
        self.db.missing_for(peer)
    }

    // A full read of current directory state, for the gRPC Snapshot RPC.
    pub fn directory_snapshot(&self) -> (Vec<db::Account>, Vec<db::ChannelInfo>) {
        (self.db.accounts().cloned().collect(), self.db.channels().cloned().collect())
    }

    pub fn gossip_ingest(&mut self, entry: LogEntry) -> std::io::Result<()> {
        // If ingesting a peer's entry removed an account a local session relied on
        // (lost a conflict, or dropped elsewhere), clean up after it.
        match self.db.ingest(entry)? {
            Some(db::AccountChange::TakenOver(a)) => self.handle_account_gone(&a, "collided with another network and no longer belongs to you"),
            Some(db::AccountChange::Dropped(a)) => self.handle_account_gone(&a, "was dropped"),
            None => {}
        }
        Ok(())
    }

    // An account a local session was using is gone (lost a conflict, or dropped on
    // another node). Log out those sessions (their credential is gone) and drop the
    // channels it founded locally — their founder identity no longer exists here.
    fn handle_account_gone(&mut self, account: &str, reason: &str) {
        let victims = self.network.uids_logged_into(account);
        // A channel with a valid successor is inherited rather than released.
        let (inherited, orphaned) = self.db.release_founded_channels(account);
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
                self.emit_irc(NetAction::Notice { from: ns.clone(), to: uid, text: format!("You are now the founder of \x02{chan}\x02 (inherited from \x02{account}\x02).") });
            }
        }
        // Log out and inform each local session that held the name.
        for uid in victims {
            self.network.clear_account(&uid);
            self.emit_irc(NetAction::Metadata { target: uid.clone(), key: "accountname".to_string(), value: String::new() });
            if let Some(ns) = &ns {
                self.emit_irc(NetAction::Notice {
                    from: ns.clone(),
                    to: uid.clone(),
                    text: format!("Your account \x02{account}\x02 {reason}. You have been logged out."),
                });
                if !orphaned.is_empty() {
                    self.emit_irc(NetAction::Notice {
                        from: ns.clone(),
                        to: uid,
                        text: format!("Channels you had registered as \x02{account}\x02 were released: {}.", orphaned.join(", ")),
                    });
                }
            }
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
    pub fn expire_sweep(&mut self) {
        let now = self.now_secs();
        // First, warn owners whose account/channel is approaching expiry and for
        // whom we have an email — a chance to keep it before it's dropped.
        if let Some(lead) = self.expire_warn.filter(|_| self.db.email_enabled()) {
            if let Some(ttl) = self.account_ttl {
                for (account, email, left) in self.db.accounts_to_warn(now, ttl, lead) {
                    let mail = echo_api::email::expiry_warning(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), "account", &account, &human_duration(left));
                    self.emit_irc(NetAction::SendEmail { to: email, subject: mail.subject, text: mail.text, html: Some(mail.html) });
                    self.db.mark_account_warned(&account);
                }
            }
            if let Some(ttl) = self.channel_ttl {
                for (channel, email, left) in self.db.channels_to_warn(now, ttl, lead) {
                    let mail = echo_api::email::expiry_warning(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), "channel", &channel, &human_duration(left));
                    self.emit_irc(NetAction::SendEmail { to: email, subject: mail.subject, text: mail.text, html: Some(mail.html) });
                    self.db.mark_channel_warned(&channel);
                }
            }
        }
        if let Some(ttl) = self.account_ttl {
            for account in self.db.expired_accounts(now, ttl) {
                // Never expire an operator's account or one still in use.
                if self.opers.contains_key(&account.to_ascii_lowercase()) || !self.network.uids_logged_into(&account).is_empty() {
                    continue;
                }
                if self.db.drop_account(&account).unwrap_or(false) {
                    self.handle_account_gone(&account, "expired after a long period of inactivity");
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
    }

    // The news items of `kind` as server-sourced notices to `uid`, each tagged
    // with `label` so it reads as an announcement. Empty if we have no SID yet.
    fn news_notices(&self, kind: &str, label: &str, uid: &str) -> Vec<NetAction> {
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
                if still_there && !identified {
                    fire.push(p.uid);
                }
            } else {
                i += 1;
            }
        }
        for uid in fire {
            let guest = format!("{}{}", self.guest_nick, self.enforce_seq);
            self.enforce_seq = self.enforce_seq.wrapping_add(1);
            if let Some(ns) = self.nick_service.clone() {
                self.emit_irc(NetAction::Notice { from: ns, to: uid.clone(), text: "You didn't identify in time; you've been renamed.".to_string() });
            }
            self.emit_irc(NetAction::ForceNick { uid, nick: guest });
        }
    }

    // Record a line to the searchable incident log and, if an audit channel is
    // configured, announce it there. For actions not tied to a command (expiry).
    fn audit(&mut self, text: String) {
        let now = self.now_secs();
        self.network.record_incident(text.clone(), now);
        if let (Some(channel), false) = (&self.log_channel, self.sid.is_empty()) {
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

    // Evict exchanges idle past the TTL. Run before starting a new one so a
    // dropped-mid-auth client the ircd never reported cannot pile up.
    fn sweep_sasl(&mut self) {
        let now = Instant::now();
        self.sasl_sessions.retain(|_, t| now.duration_since(t.touched) < SASL_SESSION_TTL);
    }

    // Sent right after the SERVER line: burst, introduce every service, endburst.
    pub fn startup_actions(&mut self) -> Vec<NetAction> {
        // Fresh link: forget bot uids minted on any previous connection.
        self.bot_uids.clear();
        self.bot_idents.clear();
        self.bot_channels.clear();
        self.network.clear_bots();
        self.next_bot_index = 0;
        let mut out = vec![NetAction::Burst];
        for svc in &self.services {
            out.push(NetAction::IntroduceUser {
                uid: svc.uid().to_string(),
                nick: svc.nick().to_string(),
                ident: "services".to_string(),
                host: svc.host().to_string(),
                gecos: svc.gecos().to_string(),
            });
        }
        // Advertise our SASL mechanisms so the uplink can offer `sasl=PLAIN` to
        // clients in CAP LS (IRCv3 SASL 3.2).
        // Introduce the registered bots too.
        out.extend(self.reconcile_bots());
        // Re-assert the network bans over the fresh link, each with its remaining
        // duration so the ircd expires it at the right time (permanent = 0).
        let now = self.now_secs();
        for a in self.db.akills() {
            let duration = a.expires.map(|e| e.saturating_sub(now)).unwrap_or(0);
            out.push(NetAction::AddLine { kind: a.kind, mask: a.mask, setter: a.setter, duration, reason: a.reason });
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
        let mut out = self.sweep_unbans();
        let evout = match event {
            NetEvent::Ping { token, from } => vec![NetAction::Pong { token, from }],
            NetEvent::UserConnect { uid, nick, host, ip } => {
                let arriving_nick = nick.clone();
                self.network.user_connect(uid.clone(), nick, host, ip.clone());
                // DEFCON 1 is a full lockdown: no new connections are accepted.
                if self.db.defcon() == 1 && !self.sid.is_empty() {
                    return vec![NetAction::KillUser {
                        from: self.sid.clone(),
                        uid,
                        reason: "The network is in lockdown (DEFCON 1). Please try again later.".to_string(),
                    }];
                }
                // Enforce the session limit: kill the connection that puts an IP
                // over its allowance (default limit, raised/lowered by exceptions).
                if let Some(limit) = self.session_limit_for(&ip) {
                    if self.network.session_count(&ip) > limit {
                        return vec![NetAction::KillUser {
                            from: self.sid.clone(),
                            uid,
                            reason: format!("Session limit exceeded ({limit} from {ip})"),
                        }];
                    }
                }
                // Greet with the logon news, and — separately — prompt-then-
                // enforce if they arrived on a registered nick they aren't
                // identified to.
                let mut out = self.news_notices("logon", "News", &uid);
                out.extend(self.enforce_registered_nick(&uid, &arriving_nick));
                out
            }
            NetEvent::NickChange { uid, nick } => {
                let new_nick = nick.clone();
                self.network.user_nick_change(&uid, nick);
                self.pending_enforce.retain(|p| p.uid != uid); // they left the old nick
                self.enforce_registered_nick(&uid, &new_nick)
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
                let from = self.chan_service.clone().unwrap_or_default();
                match self.db.channel(&channel) {
                    Some(info) => {
                        let mut out = vec![NetAction::ChannelMode { from: from.clone(), channel: channel.clone(), modes: info.lock_modes() }];
                        // KEEPTOPIC: restore the remembered topic on a recreated channel.
                        if info.settings.keeptopic && !info.topic.is_empty() {
                            out.push(NetAction::Topic { from, channel, topic: info.topic.clone() });
                        }
                        out
                    }
                    None => Vec::new(),
                }
            }
            // Enforce the mode lock: revert any change that broke it.
            NetEvent::ChannelModeChange { channel, modes } => {
                let from = self.chan_service.clone().unwrap_or_default();
                match self.db.channel(&channel).and_then(|info| info.enforce(&modes)) {
                    Some(revert) => vec![NetAction::ChannelMode { from, channel, modes: revert }],
                    None => Vec::new(),
                }
            }
            // On join: record membership, enforce the auto-kick list, give access
            // members their status mode, and send the entry message.
            NetEvent::Join { uid, channel, op } => {
                self.network.channel_join(&channel, &uid, op);
                // A join to a registered channel is activity: keep it from expiring.
                if self.db.channel(&channel).is_some() {
                    self.db.mark_channel_used(&channel, self.now_secs());
                }
                // A suspended channel is frozen: no auto-op, akick, or entry message.
                if self.db.is_channel_suspended(&channel) {
                    return Vec::new();
                }
                let account = self.network.account_of(&uid).map(str::to_string);
                let from = self.chan_service.clone().unwrap_or_default();
                // Group-aware: a member of a group that holds channel access gets
                // the group's status mode too.
                let mode = account.as_deref().and_then(|a| self.db.channel_join_mode(&channel, a));
                let entrymsg = self.db.channel(&channel).map(|c| c.entrymsg.clone()).filter(|m| !m.is_empty());
                // Computed before the match below moves `channel` into its actions.
                let greet = self.greet_on_join(&channel, account.as_deref());
                let mut out = Vec::new();
                // SECUREOPS: a user who arrives opped (FJOIN prefix) but lacks op-level
                // access loses it, unless we're about to grant it to them anyway.
                if op && mode != Some("+o") && self.db.channel(&channel).is_some_and(|c| c.settings.secureops) {
                    out.push(NetAction::ChannelMode { from: from.clone(), channel: channel.clone(), modes: format!("-o {uid}") });
                }
                // RESTRICTED: only users with access (or opers) may be in the channel.
                if mode.is_none() && self.db.channel(&channel).is_some_and(|c| c.settings.restricted) {
                    let is_oper = account.as_deref().is_some_and(|a| self.oper_privs(a).any());
                    if !is_oper {
                        out.push(NetAction::Kick { from, channel, uid, reason: "This channel is restricted to users with access.".to_string() });
                        return out;
                    }
                }
                match mode {
                    // A user with access gets their status mode, plus the entry message.
                    Some(m) => {
                        if let Some(msg) = entrymsg {
                            out.push(NetAction::Notice { from: from.clone(), to: uid.clone(), text: msg });
                        }
                        out.push(NetAction::ChannelMode { from, channel, modes: format!("{m} {uid}") });
                    }
                    // No access: an auto-kick match is banned and kicked, else greeted.
                    None => {
                        let nick = self.network.nick_of(&uid).unwrap_or("*").to_string();
                        let host = self.network.host_of(&uid).unwrap_or("*").to_string();
                        let hostmask = format!("{nick}!*@{host}");
                        let akick = self.db.channel(&channel).and_then(|c| c.akick_match(&hostmask)).map(|k| {
                            let reason = if k.reason.is_empty() { "You are banned from this channel.".to_string() } else { k.reason.clone() };
                            (k.mask.clone(), reason)
                        });
                        match akick {
                            Some((mask, reason)) => {
                                self.network.channel_part(&channel, &uid);
                                out.push(NetAction::ChannelMode { from: from.clone(), channel: channel.clone(), modes: format!("+b {mask}") });
                                out.push(NetAction::Kick { from, channel, uid, reason });
                            }
                            None => {
                                if let Some(msg) = entrymsg {
                                    out.push(NetAction::Notice { from, to: uid, text: msg });
                                }
                            }
                        }
                    }
                }
                // GREET: if the channel shows greets and this member has channel
                // access + a personal greet, the assigned bot displays it.
                if let Some(g) = greet {
                    out.push(g);
                    self.bump("botserv.greet");
                }
                out
            }
            NetEvent::Part { uid, channel } => {
                self.network.channel_part(&channel, &uid);
                self.forget_chatter(&channel, &uid);
                Vec::new()
            }
            NetEvent::ChannelOp { channel, uid, op } => {
                self.network.set_op(&channel, &uid, op);
                // SECUREOPS: a user who gains +o without op-level access loses it.
                if op {
                    if let Some(c) = self.db.channel(&channel) {
                        if c.settings.secureops && !self.network.account_of(&uid).is_some_and(|a| c.join_mode(a) == Some("+o")) {
                            let from = self.chan_service.clone().unwrap_or_default();
                            return vec![NetAction::ChannelMode { from, channel, modes: format!("-o {uid}") }];
                        }
                    }
                }
                Vec::new()
            }
            NetEvent::ChannelVoice { channel, uid, voice } => {
                self.network.set_voice(&channel, &uid, voice);
                Vec::new()
            }
            NetEvent::ChannelKey { channel, key } => {
                self.network.set_channel_key(&channel, key);
                Vec::new()
            }
            NetEvent::TopicChange { channel, setter, topic } => {
                let info = self.db.channel(&channel).map(|c| (c.settings.keeptopic, c.settings.topiclock, c.topic.clone()));
                // The setter may change a locked topic only with op-level access.
                let authorized = self.network.account_of(&setter).and_then(|a| self.db.channel(&channel).map(|c| c.join_mode(a) == Some("+o"))).unwrap_or(false);
                match info {
                    // TOPICLOCK + unauthorised: put the kept topic back.
                    Some((_, true, stored)) if !authorized => {
                        let from = self.chan_service.clone().unwrap_or_default();
                        vec![NetAction::Topic { from, channel, topic: stored }]
                    }
                    // Otherwise remember the new topic if the channel keeps it.
                    Some((keep, lock, _)) if keep || lock => {
                        let _ = self.db.set_channel_topic(&channel, &topic);
                        Vec::new()
                    }
                    _ => Vec::new(),
                }
            }
            NetEvent::Quit { uid } => {
                self.network.user_quit(&uid);
                self.sasl_sessions.remove(&uid); // drop any half-finished exchange
                self.pending_enforce.retain(|p| p.uid != uid);
                self.forget_chatter_everywhere(&uid);
                Vec::new()
            }
            NetEvent::Privmsg { from, to, text } => self.dispatch(&from, &to, &text),
            NetEvent::AccountRequest { reqid, origin, kind, account, p2, p3 } => {
                self.account_request(reqid, origin, kind, account, p2, p3)
            }
            NetEvent::Sasl { client, mode, data, .. } => self.sasl(client, mode, data),
            _ => Vec::new(),
        };
        self.track_accounts(&evout);
        out.extend(evout);
        // Give every user-removal a traceable incident id, stamped into its reason
        // and recorded in the searchable log (OperServ LOGSEARCH).
        self.stamp_incidents(&mut out);
        out
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
                    } else {
                        self.network.set_account(target, value);
                        // Identified now: cancel any pending nick-protection rename.
                        self.pending_enforce.retain(|p| p.uid != *target);
                        // A login is activity: keep the account from expiring.
                        self.db.mark_account_seen(value, self.now_secs());
                        // An operator logging in is shown the staff (oper) news.
                        if self.oper_privs(value).any() {
                            for note in self.news_notices("oper", "Staff News", target) {
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
        let summaries: Vec<String> = self.db.events_since(mark).iter().filter_map(audit_summary).collect();
        if summaries.is_empty() {
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
        for summary in summaries {
            let line = format!("{actor} {summary}");
            self.network.record_incident(line.clone(), now);
            if let (Some(channel), false) = (&self.log_channel, self.sid.is_empty()) {
                out.push(NetAction::Notice { from: self.sid.clone(), to: channel.clone(), text: line });
            }
        }
        out
    }

    // The greet a channel's bot shows when a member logged into `account` joins:
    // only when greets are enabled for the channel, the member holds channel
    // access, and has set a non-empty personal greet.
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

    // Fantasy commands: `!op nick`, `!kick nick`, `!topic …` spoken in a channel
    // that has a bot assigned. We reuse ChanServ's real command handlers — the
}

// A human label for a network-ban X-line kind, for the audit feed.
fn ban_kind_label(kind: &str) -> &'static str {
    match kind {
        "Q" => "nick ban",
        "R" => "realname ban",
        "SHUN" => "shun",
        "CBAN" => "channel ban",
        _ => "network ban",
    }
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
        ChannelFounderSet { channel, founder } => format!("set founder of \x02{channel}\x02 to \x02{founder}\x02"),
        ChannelSuccessorSet { channel, successor } => match successor {
            Some(s) => format!("set successor of \x02{channel}\x02 to \x02{s}\x02"),
            None => format!("cleared the successor of \x02{channel}\x02"),
        },
        ChannelAccessAdd { channel, account, level } => format!("set \x02{account}\x02 to {level} on \x02{channel}\x02"),
        ChannelAccessDel { channel, account } => format!("removed \x02{account}\x02 from \x02{channel}\x02 access"),
        ChannelAkickAdd { channel, mask, reason } => format!("added akick \x02{mask}\x02 on \x02{channel}\x02 ({reason})"),
        ChannelAkickDel { channel, mask } => format!("removed akick \x02{mask}\x02 on \x02{channel}\x02"),
        ChannelSuspended { channel, reason, .. } => format!("suspended channel \x02{channel}\x02 ({reason})"),
        ChannelUnsuspended { channel } => format!("unsuspended channel \x02{channel}\x02"),
        ChannelBotAssigned { channel, bot } => format!("assigned bot \x02{bot}\x02 to \x02{channel}\x02"),
        ChannelBotUnassigned { channel } => format!("removed the bot from \x02{channel}\x02"),
        BotAdded(b) => format!("added bot \x02{}\x02", b.nick),
        BotRemoved { nick } => format!("removed bot \x02{nick}\x02"),
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
        ForbidAdded { kind, mask, reason, .. } => format!("forbade {} \x02{mask}\x02 ({reason})", kind.to_ascii_lowercase()),
        ForbidRemoved { kind, mask } => format!("un-forbade {} \x02{mask}\x02", kind.to_ascii_lowercase()),
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
        AjoinAdded { .. } | AjoinRemoved { .. } | AccountGreetSet { .. } | VhostRequested { .. }
        | VhostRequestCleared { .. } | MemoSent { .. } | MemoRead { .. } | MemoDeleted { .. }
        | MemoIgnoreAdd { .. } | MemoIgnoreDel { .. }
        | ChannelMlock { .. } | ChannelDescSet { .. } | ChannelEntryMsgSet { .. } | ChannelSettingsSet { .. }
        | ChannelKickerSet { .. } | ChannelBadwordsSet { .. } | ChannelTriggersSet { .. }
        | ChannelTopicSet { .. } | AccountSeen { .. } | ChannelUsed { .. }
        | AccountExpiryWarned { .. } | ChannelExpiryWarned { .. } => return None,
    };
    Some(s)
}

// Rewrite the source uid of an action from `old` to `new`, where the variant
// carries a `from`. Used to make fantasy output appear to come from the bot.
fn resource_action(a: &mut NetAction, old: &str, new: &str) {
    let from = match a {
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

fn login_plain(b64: &str, db: &Db) -> Option<String> {
    let raw = STANDARD.decode(b64).ok()?;
    let parts: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authcid = std::str::from_utf8(parts[1]).ok()?;
    let passwd = std::str::from_utf8(parts[2]).ok()?;
    db.authenticate(authcid, passwd).map(str::to_string)
}

// Report SASL failure to the ircd (drives 904).
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

#[cfg(test)]
mod tests;
