use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

// Ceiling on a single compiled badword regex, so one pattern can't consume huge
// memory. Shared by add-time validation and the engine's match-time build.
pub const BADWORD_SIZE_LIMIT: usize = 1 << 20;

/// Compile a channel's badword patterns into one RegexSet. Case-insensitive by
/// default (a pattern can opt out with `(?-i)`), size-limited, and tolerant of a
/// bad entry so one pattern can't disable the whole set.
pub fn build_badword_set(patterns: &[String]) -> regex::RegexSet {
    regex::RegexSetBuilder::new(patterns)
        .case_insensitive(true)
        .size_limit(BADWORD_SIZE_LIMIT)
        .build()
        .unwrap_or_else(|_| regex::RegexSet::empty())
}
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::scram::{self, Hash};

// The store is one type, `Db`, whose operations are grouped by domain into
// sibling files; the type definitions, log plumbing, and shared helpers live
// here. Each domain file adds its own `impl Db` block.
mod account;
mod channel;
mod event;
mod network;
mod store;

pub use event::Event;
pub(crate) use event::{apply, Scope};

// Error kinds, the emailed-code purpose, and the module-facing views live in the
// echo-api SDK crate; re-exported so the engine keeps naming them locally and
// modules importing `crate::engine::db::{ChanError, ...}` are unaffected.
pub use echo_api::{
    AccountView, AjoinView, AkillView, BotView, Caps, ForbidView, GroupView, HelpView, IgnoreView, MemoView, NewsView, Privs, ReportView, SuspensionView, ChanAccessView, ChanAkickView, ChanError, ChanSetting, ChannelView, CertError, CodeKind, Kicker, RegError, Store, TriggerView, VhostView,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub email: Option<String>,
    pub ts: u64,
    // The node that first registered this account (its "home"). With `ts` it
    // deterministically resolves a concurrent registration of the same name across
    // the federation. Named `home` not `origin` so it can't collide with the log
    // envelope's `origin` when this struct is flattened into a LogEntry. Defaulted
    // for records written before this existed.
    #[serde(default)]
    pub home: String,
    // SCRAM verifiers (`v=1,i=,s=,sk=,sv=`), computed from the password at
    // registration. Absent on accounts registered before SCRAM support.
    #[serde(default)]
    pub scram256: Option<String>,
    #[serde(default)]
    pub scram512: Option<String>,
    // TLS client-certificate fingerprints (lowercase hex) that may log in to
    // this account via SASL EXTERNAL. Each fingerprint maps to one account.
    #[serde(default)]
    pub certfps: Vec<String>,
    // Whether the email on file has been confirmed. Defaults true so accounts
    // predating email confirmation (and those registered without email) count
    // as verified.
    #[serde(default = "verified_default")]
    pub verified: bool,
    // Channels this account is auto-joined to on identify (AJOIN).
    #[serde(default)]
    pub ajoin: Vec<AjoinEntry>,
    // Services suspension, if any (login blocked while set and unexpired).
    #[serde(default)]
    pub suspension: Option<Suspension>,
    // Memos left for this account (MemoServ), oldest first.
    #[serde(default)]
    pub memos: Vec<Memo>,
    // Accounts this user won't receive memos from (MemoServ IGNORE).
    #[serde(default)]
    pub memo_ignore: Vec<String>,
    // MemoServ SET NOTIFY: be told about new memos on login (default on).
    #[serde(default = "verified_default")]
    pub memo_notify: bool,
    // MemoServ SET LIMIT: mailbox cap (None = the network default).
    #[serde(default)]
    pub memo_limit: Option<u32>,
    // Personal greet a bot shows when this account joins a greet-enabled channel.
    #[serde(default)]
    pub greet: String,
    // NickServ SET AUTOOP: when off, this user is never auto-opped on join even
    // where they hold access (they op themselves). Stored inverted so the default
    // (auto-op enabled) is the zero value.
    #[serde(default)]
    pub no_autoop: bool,
    // NickServ SET KILL: when off, this account's nicks are not protected — an
    // unidentified user keeping the nick is never renamed to a guest. Stored
    // inverted so the default (protection enabled) is the zero value.
    #[serde(default)]
    pub no_protect: bool,
    // NickServ SET HIDE STATUS: when set, the last-seen / online line in INFO is
    // shown only to the account's owner and to opers, not to other users. Default
    // (visible) is the zero value.
    #[serde(default)]
    pub hide_status: bool,
    // Assigned vhost (HostServ), applied to the displayed host on identify.
    #[serde(default)]
    pub vhost: Option<Vhost>,
    // A vhost the user has requested, pending operator approval.
    #[serde(default)]
    pub vhost_request: Option<PendingVhost>,
    // Unix time this account was last active (identified). 0 = never stamped
    // since expiry tracking existed, in which case `ts` (registration) stands in.
    #[serde(default)]
    pub last_seen: u64,
    // Pinned by an operator so inactivity-expiry never drops it.
    #[serde(default)]
    pub noexpire: bool,
    // Whether an impending-expiry warning email has already been sent (reset on
    // the next activity, so each idle spell warns at most once).
    #[serde(default)]
    pub expiry_warned: bool,
    // A staff note (OperServ INFO), shown only to operators.
    #[serde(default)]
    pub oper_note: Option<String>,
}

// A requested vhost awaiting approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingVhost {
    pub host: String,
    pub ts: u64,
}

// A HostServ virtual host: the displayed host, who assigned it, and when.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vhost {
    pub host: String,
    pub setter: String,
    pub ts: u64,
    // Absolute unix-seconds expiry, or None for a permanent vhost.
    #[serde(default)]
    pub expires: Option<u64>,
}

fn verified_default() -> bool {
    true
}

// An access-list entry: an account and its level ("op" or "voice").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChanAccess {
    pub account: String,
    pub level: String,
}

// An auto-kick entry: a nick!user@host mask and why it was added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChanAkick {
    pub mask: String,
    pub reason: String,
}

// A services suspension on an account: who set it, why, when, and an optional
// absolute-unix-seconds expiry (None = until manually lifted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suspension {
    pub by: String,
    pub reason: String,
    pub ts: u64,
    #[serde(default)]
    pub expires: Option<u64>,
}

// A network ban: the ircd X-line `kind` (e.g. "G" for a user@host G-line, "Q"
// for a nick Q-line), a mask, who set it, why, when, and an optional
// absolute-unix-seconds expiry (None = permanent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Akill {
    #[serde(default = "gline_kind")]
    pub kind: String,
    pub mask: String,
    pub setter: String,
    pub reason: String,
    pub ts: u64,
    #[serde(default)]
    pub expires: Option<u64>,
}

// A registration ban: an account name, channel, or email pattern that may not be
// registered. `kind` is "NICK", "CHAN", or "EMAIL". Network-wide policy like an
// AKILL, so it gossips and every node enforces it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forbid {
    pub kind: String,
    pub mask: String,
    pub setter: String,
    pub reason: String,
    pub ts: u64,
}

// The default ban kind for records written before bans carried one: a G-line.
fn gline_kind() -> String {
    "G".to_string()
}

// A valid 3-char server id for a juped server from a counter: a leading digit
// (kept high to avoid colliding with typical real SIDs) then two base-36 chars.
fn jupe_sid(seq: u32) -> String {
    const C: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let b = C[(seq / 36 % 36) as usize];
    let c = C[(seq % 36) as usize];
    String::from_utf8(vec![b'9', b, c]).unwrap()
}

// A services ignore: services silently drop commands from a matching user. Node-
// local and in-memory (like the auth throttle) — a fast, transient moderation
// tool, not persisted or federated.
#[derive(Debug, Clone)]
pub struct Ignore {
    pub mask: String,
    pub reason: String,
    pub expires: Option<u64>,
}

// A news item (InfoServ bulletin): a `kind` ("logon" shown to everyone on
// connect, "oper" shown to operators on login), the text, who set it, and when.
// Carries a stable id (assigned at add time, embedded in the log) so deletion is
// order-independent under replay.
#[derive(Debug, Clone)]
pub struct News {
    pub id: u64,
    pub kind: String,
    pub text: String,
    pub setter: String,
    pub ts: u64,
}

// A help-desk ticket (HelpServ): who asked, their message, when, the staff member
// handling it (if taken), and whether it's still open.
#[derive(Debug, Clone)]
pub struct HelpTicket {
    pub id: u64,
    pub requester: String,
    pub message: String,
    pub ts: u64,
    pub handler: Option<String>,
    pub open: bool,
}

// A user group (GroupServ): a `!name`, its founder account, and member accounts
// each with group-access flags. Groups can be granted channel access.
#[derive(Debug, Clone)]
pub struct Group {
    pub name: String, // "!name", casefolded
    pub founder: String,
    pub ts: u64,
    pub members: Vec<GroupMember>,
}

#[derive(Debug, Clone)]
pub struct GroupMember {
    pub account: String,
    pub flags: String,
}

// An abuse report (ReportServ): who filed it, the nick/channel it's about, why,
// when, and whether it's still open. Stable id like News.
#[derive(Debug, Clone)]
pub struct Report {
    pub id: u64,
    pub reporter: String,
    pub target: String,
    pub reason: String,
    pub ts: u64,
    pub open: bool,
}

// The network-wide lists that aren't accounts/channels/grouped/bots: the network
// bans and the news items. Bundled so `apply` threads one parameter for them
// (and stays within its argument budget as more are added).
#[derive(Debug, Clone, Default)]
pub struct NetData {
    pub akills: Vec<Akill>,
    pub forbids: Vec<Forbid>,
    pub news: Vec<News>,
    pub news_seq: u64,
    // Abuse reports (ReportServ), oldest first.
    pub reports: Vec<Report>,
    pub report_seq: u64,
    // User groups (GroupServ).
    pub groups: Vec<Group>,
    // Help-desk tickets (HelpServ), oldest first.
    pub help: Vec<HelpTicket>,
    pub help_seq: u64,
    // Runtime services operators (OperServ OPER), casefolded account -> grant.
    // Merged with the declarative [[oper]] config at the engine.
    pub opers: HashMap<String, OperGrant>,
    // Session-limit exceptions (OperServ SESSION): per-IP-mask allowances.
    pub sess_exceptions: Vec<SessionException>,
    // The bot auto-assigned to newly registered channels (BotServ AUTOASSIGN),
    // if any. Casefolded nick; None disables auto-assignment.
    pub default_bot: Option<String>,
}

// A session-limit exception: an IP-mask glob and the session allowance for IPs
// that match it (0 = unlimited).
#[derive(Debug, Clone)]
pub struct SessionException {
    pub mask: String,
    pub limit: u32,
    pub reason: String,
}

// A runtime operator grant: the privilege names and an optional absolute-unix
// expiry (None = permanent), evaluated lazily like suspensions/vhosts.
#[derive(Debug, Clone)]
pub struct OperGrant {
    pub privs: Vec<String>,
    pub expires: Option<u64>,
}

// A memo left for an account (MemoServ).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memo {
    pub from: String,
    pub text: String,
    pub ts: u64,
    #[serde(default)]
    pub read: bool,
    // The sender asked to be told when it's read (MemoServ RSEND).
    #[serde(default)]
    pub receipt: bool,
}

// A service bot: a pseudo-client BotServ can assign to sit in channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bot {
    pub nick: String,
    pub user: String,
    pub host: String,
    pub gecos: String,
    // Oper-only to assign, and hidden from BOT LIST for non-admins.
    #[serde(default)]
    pub private: bool,
}

// An auto-join entry: a channel this account is joined to on identify, with an
// optional key for keyed channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AjoinEntry {
    pub channel: String,
    #[serde(default)]
    pub key: String,
}

// A channel's on/off options (ChanServ SET). Typed, not a bag of string flags,
// so a new option is one field and the compiler proves every place handles it.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ChanSettings {
    // Append "(requested by <nick>)" to ChanServ KICK reasons.
    #[serde(default)]
    pub signkick: bool,
    // Hide the channel from ChanServ LIST.
    #[serde(default)]
    pub private: bool,
    // Forbid using ChanServ to act against someone with equal-or-higher access.
    #[serde(default)]
    pub peace: bool,
    // Strip channel-operator status from anyone without op-level access.
    #[serde(default)]
    pub secureops: bool,
    // Kick anyone without channel access when they join.
    #[serde(default)]
    pub restricted: bool,
    // Stored inverted so it defaults to auto-op ON: when set, access members are
    // NOT auto-opped on join (they must UP). SET AUTOOP toggles it.
    #[serde(default)]
    pub noautoop: bool,
    // Remember the topic and restore it when the channel is recreated.
    #[serde(default)]
    pub keeptopic: bool,
    // Revert topic changes made by users without op-level access.
    #[serde(default)]
    pub topiclock: bool,
    // BotServ: show members' personal greets when they join.
    #[serde(default)]
    pub bot_greet: bool,
    // BotServ: forbid the founder from (un)assigning a bot (admin override only).
    #[serde(default)]
    pub nobot: bool,
}

// A registered channel and who owns it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub name: String,
    pub founder: String,
    pub ts: u64,
    // Mode-lock: chars services keep set / unset (besides the implicit +r).
    #[serde(default)]
    pub lock_on: String,
    #[serde(default)]
    pub lock_off: String,
    #[serde(default)]
    pub access: Vec<ChanAccess>,
    #[serde(default)]
    pub akick: Vec<ChanAkick>,
    // Account that inherits the channel if the founder's account is dropped or
    // expires; None means the channel is released instead.
    #[serde(default)]
    pub successor: Option<String>,
    // Free-text description, shown in INFO.
    #[serde(default)]
    pub desc: String,
    // Message noticed to users as they join.
    #[serde(default)]
    pub entrymsg: String,
    // Channel homepage URL, shown in INFO (empty = none).
    #[serde(default)]
    pub url: String,
    // Channel contact email, shown in INFO (empty = none).
    #[serde(default)]
    pub email: String,
    // On/off options set via ChanServ SET.
    #[serde(default)]
    pub settings: ChanSettings,
    // Last known topic, kept for KEEPTOPIC / TOPICLOCK.
    #[serde(default)]
    pub topic: String,
    // Services suspension, if any (channel frozen while set and unexpired).
    #[serde(default)]
    pub suspension: Option<Suspension>,
    // BotServ bot assigned to sit in this channel, if any (its nick).
    #[serde(default)]
    pub assigned_bot: Option<String>,
    // BotServ kicker configuration (the bot kicks on caps/formatting/etc.).
    #[serde(default)]
    pub kickers: KickerSettings,
    // BADWORDS: user-configured regex patterns the badwords kicker matches.
    #[serde(default)]
    pub badwords: Vec<String>,
    // Bumped whenever `badwords` changes, so the engine's compiled-RegexSet
    // cache knows to rebuild. Session-local; never serialized.
    #[serde(skip)]
    pub badwords_rev: u64,
    // TRIGGERs: regex -> response the bot speaks when a line matches.
    #[serde(default)]
    pub triggers: Vec<Trigger>,
    #[serde(skip)]
    pub triggers_rev: u64,
    // Unix time this channel was last used (a member joined). 0 = never stamped
    // since expiry tracking existed, in which case `ts` (registration) stands in.
    #[serde(default)]
    pub last_used: u64,
    // Pinned by an operator so inactivity-expiry never drops it.
    #[serde(default)]
    pub noexpire: bool,
    // Whether an impending-expiry warning email has already been sent.
    #[serde(default)]
    pub expiry_warned: bool,
    // A staff note (OperServ INFO), shown only to operators.
    #[serde(default)]
    pub oper_note: Option<String>,
}

// A bot auto-response: when a channel line matches `pattern`, the assigned bot
// says `response` (with $nick replaced by the speaker's nick).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    pub pattern: String,
    pub response: String,
    // Minimum seconds between firings of this trigger (0 = no limit).
    #[serde(default)]
    pub cooldown: u32,
}

// BotServ's per-channel "kickers": the assigned bot kicks a message that trips
// an enabled rule. Typed, like ChanSettings — a new kicker is one field.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KickerSettings {
    #[serde(default)]
    pub caps: bool,
    // Only messages at least this long are caps-checked (0 = the default, 10).
    #[serde(default)]
    pub caps_min: u16,
    // Percentage of letters that must be uppercase to trip (0 = default, 25).
    #[serde(default)]
    pub caps_percent: u16,
    #[serde(default)]
    pub bolds: bool,
    #[serde(default)]
    pub colors: bool,
    #[serde(default)]
    pub underlines: bool,
    #[serde(default)]
    pub reverses: bool,
    #[serde(default)]
    pub italics: bool,
    // Kick users who send too many lines too fast.
    #[serde(default)]
    pub flood: bool,
    // Lines within `flood_secs` that trip the flood kicker (0 = default, 6).
    #[serde(default)]
    pub flood_lines: u16,
    #[serde(default)]
    pub flood_secs: u16,
    // Kick users who repeat the same line.
    #[serde(default)]
    pub repeat: bool,
    // Consecutive repeats that trip the repeat kicker (0 = default, 3).
    #[serde(default)]
    pub repeat_times: u16,
    // Kick lines matching one of the channel's badword regexes.
    #[serde(default)]
    pub badwords: bool,
    // Times a user may be kicked (by any kicker) before the bot bans them
    // instead. 0 = never ban, only kick.
    #[serde(default)]
    pub ttb: u16,
    // How long such a ban lasts, in seconds. 0 = until manually removed.
    #[serde(default)]
    pub ban_expire: u32,
    // Warn a user (once) before kicking them the first time.
    #[serde(default)]
    pub warn: bool,
    // Community !votekick/!voteban: votes needed to act (0 = disabled).
    #[serde(default)]
    pub votekick: u16,
    // Don't kick channel operators, whatever they send.
    #[serde(default)]
    pub dontkickops: bool,
    // Don't kick voiced (+v) users.
    #[serde(default)]
    pub dontkickvoices: bool,
}

impl KickerSettings {
    // Any kicker enabled? (dontkickops alone doesn't count.)
    pub fn any(&self) -> bool {
        self.caps || self.bolds || self.colors || self.underlines || self.reverses || self.italics || self.flood || self.repeat || self.badwords
    }

    // Resolved thresholds, applying the defaults for a 0 (unset) value.
    pub fn flood_thresholds(&self) -> (u16, u16) {
        (if self.flood_lines < 2 { 6 } else { self.flood_lines }, if self.flood_secs == 0 { 10 } else { self.flood_secs })
    }

    pub fn repeat_threshold(&self) -> u16 {
        if self.repeat_times == 0 { 3 } else { self.repeat_times }
    }

    // The reason to kick `text` for, or None if it trips no enabled kicker.
    pub fn violation(&self, text: &str) -> Option<&'static str> {
        if self.bolds && text.contains('\x02') {
            return Some("Don't use bold formatting on this channel.");
        }
        if self.colors && text.contains('\x03') {
            return Some("Don't use colour codes on this channel.");
        }
        if self.underlines && text.contains('\x1f') {
            return Some("Don't use underline formatting on this channel.");
        }
        if self.reverses && text.contains('\x16') {
            return Some("Don't use reverse formatting on this channel.");
        }
        if self.italics && text.contains('\x1d') {
            return Some("Don't use italic formatting on this channel.");
        }
        if self.caps {
            let min = if self.caps_min == 0 { 10 } else { self.caps_min } as usize;
            let percent = if self.caps_percent == 0 { 25 } else { self.caps_percent } as u32;
            if text.chars().count() >= min {
                let upper = text.chars().filter(|c| c.is_ascii_uppercase()).count() as u32;
                let lower = text.chars().filter(|c| c.is_ascii_lowercase()).count() as u32;
                if upper as usize >= min && upper + lower > 0 && upper * 100 / (upper + lower) >= percent {
                    return Some("Turn caps lock off!");
                }
            }
        }
        None
    }
}

impl ChannelInfo {
    /// The status mode to give `account` on join, if any: +o for the founder and
    /// access-list ops, +v for voices.
    pub fn join_mode(&self, account: &str) -> Option<&'static str> {
        if self.founder.eq_ignore_ascii_case(account) {
            return Some("+o");
        }
        self.access
            .iter()
            .find(|a| a.account.eq_ignore_ascii_case(account))
            .and_then(|a| echo_api::level_caps(&a.level).auto)
    }

    /// The matching auto-kick entry for `hostmask` (nick!user@host), if any.
    pub fn akick_match(&self, hostmask: &str) -> Option<&ChanAkick> {
        self.akick.iter().find(|k| glob_match(&k.mask, hostmask))
    }

    /// The mode string services keep applied: +r plus the lock.
    pub fn lock_modes(&self) -> String {
        let mut s = format!("+r{}", self.lock_on);
        if !self.lock_off.is_empty() {
            s.push('-');
            s.push_str(&self.lock_off);
        }
        s
    }

    /// Given a mode change, the modes to send back to restore the lock, if it was
    /// violated. +r is always locked on. Only simple (paramless) modes are checked.
    pub fn enforce(&self, change: &str) -> Option<String> {
        let (mut readd, mut reremove) = (String::new(), String::new());
        let mut adding = true;
        for ch in change.chars() {
            match ch {
                '+' => adding = true,
                '-' => adding = false,
                m if m.is_ascii_alphabetic() => {
                    if (m == 'r' || self.lock_on.contains(m)) && !adding && !readd.contains(m) {
                        readd.push(m);
                    } else if self.lock_off.contains(m) && adding && !reremove.contains(m) {
                        reremove.push(m);
                    }
                }
                _ => {}
            }
        }
        if readd.is_empty() && reremove.is_empty() {
            return None;
        }
        let mut s = String::new();
        if !readd.is_empty() {
            s.push('+');
            s.push_str(&readd);
        }
        if !reremove.is_empty() {
            s.push('-');
            s.push_str(&reremove);
        }
        Some(s)
    }
}

// A durable record: the event plus the metadata a gossip layer needs to address
// and order it — the origin node, its per-node sequence (`origin:seq` is the
// cluster-unique id), and a Lamport clock for causal ordering across nodes.
// Lines written before these existed default them in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(default)]
    origin: String,
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    lamport: u64,
    #[serde(flatten)]
    event: Event,
}

#[cfg(test)]
impl LogEntry {
    pub(crate) fn for_test(origin: &str, seq: u64, lamport: u64, event: Event) -> Self {
        LogEntry { origin: origin.to_string(), seq, lamport, event }
    }
}

// Read-only accessors for consumers outside this module (the gRPC replication
// layer subscribes to the same broadcast channel gossip does, and translates
// each entry to a wire message).
impl LogEntry {
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn lamport(&self) -> u64 {
        self.lamport
    }
    pub fn event(&self) -> &Event {
        &self.event
    }
}

// Append-only log, the sole persistent source of truth: `open` replays it,
// `append` stamps and writes a locally-authored entry, and `ingest` folds in an
// entry authored by another node. The version vector (highest seq applied per
// origin) plus the Lamport clock are the seam a future gossip layer ships entries
// over — de-duplicating and ordering them — without the services knowing.
pub struct EventLog {
    path: PathBuf,
    origin: String,
    lamport: u64,                   // logical clock, ticked on every event
    versions: HashMap<String, u64>, // per-origin highest seq applied (version vector)
    entries: Vec<LogEntry>,         // full log, kept so peers can pull what they lack
    outbound: Option<broadcast::Sender<LogEntry>>, // push newly committed entries to peers
    // Operator lockdown (OperServ SET READONLY): while set, locally-authored
    // writes are refused. Ephemeral — it resets on restart and never persists,
    // and gossip ingestion is unaffected so a read-only node stays in sync.
    readonly: bool,
}

impl EventLog {
    fn open(path: PathBuf, origin: String) -> (Self, Vec<Event>) {
        let mut log = Self { path, origin, lamport: 0, versions: HashMap::new(), entries: Vec::new(), outbound: None, readonly: false };
        if let Ok(data) = std::fs::read_to_string(&log.path) {
            for line in data.lines().filter(|l| !l.trim().is_empty()) {
                match serde_json::from_str::<LogEntry>(line) {
                    Ok(entry) => {
                        log.absorb(&entry);
                        log.entries.push(entry);
                    }
                    Err(e) => tracing::warn!(%e, "skipping malformed event log line"),
                }
            }
        }
        let events = log.entries.iter().map(|e| e.event.clone()).collect();
        (log, events)
    }

    // Roll the clock and version vector forward over an entry. Local (channel)
    // entries carry no gossip identity, so they never touch the vector or clock.
    fn absorb(&mut self, entry: &LogEntry) {
        if entry.event.scope() != Scope::Global {
            return;
        }
        self.lamport = self.lamport.max(entry.lamport);
        self.versions.entry(entry.origin.clone()).and_modify(|s| *s = (*s).max(entry.seq)).or_insert(entry.seq);
    }

    // Seq the next locally-authored event will carry (0-based, per our origin).
    fn next_seq(&self) -> u64 {
        self.versions.get(&self.origin).map_or(0, |s| s + 1)
    }

    // Persist a locally-authored event. Global events get the next seq + a ticked
    // Lamport clock and are pushed to peers; local (channel) events are written
    // for restart but never gossiped and carry no version-vector identity.
    fn append(&mut self, event: Event) -> std::io::Result<()> {
        // Operator lockdown refuses every locally-authored write at this one seam.
        if self.readonly {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "services are read-only"));
        }
        let global = event.scope() == Scope::Global;
        let entry = if global {
            self.lamport += 1;
            LogEntry { origin: self.origin.clone(), seq: self.next_seq(), lamport: self.lamport, event }
        } else {
            LogEntry { origin: self.origin.clone(), seq: 0, lamport: 0, event }
        };
        if let Err(e) = self.persist(&entry) {
            // Surface the real cause (disk full, permissions, ...) here at the
            // source; callers only see a generic Internal error further up.
            tracing::error!(%e, path = %self.path.display(), "failed to write event to the log");
            return Err(e);
        }
        if global {
            self.versions.insert(entry.origin.clone(), entry.seq);
            self.notify(&entry);
        }
        self.entries.push(entry);
        Ok(())
    }

    // Ingest an entry authored by another node — the gossip seam. Returns the
    // event to fold into state, or None if already applied (idempotent, so
    // re-delivery converges). Assumes per-origin in-order delivery.
    fn ingest(&mut self, entry: LogEntry) -> std::io::Result<Option<Event>> {
        // A node never accepts another node's channel state — only global (account)
        // identity replicates. This is the guarantee: you can't be handed ownership
        // of a channel that was registered on a network you're not part of.
        if entry.event.scope() != Scope::Global {
            return Ok(None);
        }
        if self.versions.get(&entry.origin).is_some_and(|&s| entry.seq <= s) {
            return Ok(None); // already have it
        }
        self.persist(&entry)?;
        self.lamport = self.lamport.max(entry.lamport) + 1; // Lamport receive rule
        self.versions.insert(entry.origin.clone(), entry.seq);
        let event = entry.event.clone();
        self.notify(&entry);
        self.entries.push(entry);
        Ok(Some(event))
    }

    // Push a freshly committed entry to connected peers, if any are wired up.
    // Best effort: a lagging subscriber just relies on the periodic digest.
    fn notify(&self, entry: &LogEntry) {
        if let Some(tx) = &self.outbound {
            let _ = tx.send(entry.clone());
        }
    }

    fn set_outbound(&mut self, tx: broadcast::Sender<LogEntry>) {
        self.outbound = Some(tx);
    }

    // The events appended at or after `mark`, cloned. Used by the audit feed to
    // see exactly what a just-run command changed (the log only ever grows during
    // a command, so `[mark..]` is that command's footprint).
    fn events_from(&self, mark: usize) -> Vec<Event> {
        self.entries.get(mark..).into_iter().flatten().map(|e| e.event.clone()).collect()
    }

    // Our version vector: highest seq applied per origin.
    fn version_vector(&self) -> HashMap<String, u64> {
        self.versions.clone()
    }

    // Global entries a peer is missing, given the version vector it advertised.
    // Local (channel) entries are never offered — they don't leave the node.
    fn missing_for(&self, peer: &HashMap<String, u64>) -> Vec<LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.scope() == Scope::Global)
            .filter(|e| peer.get(&e.origin).is_none_or(|&s| e.seq > s))
            .cloned()
            .collect()
    }

    fn persist(&self, entry: &LogEntry) -> std::io::Result<()> {
        // Serialise first, and treat a failure as an error rather than writing a
        // blank line, which would silently drop a committed change.
        let line = serde_json::to_string(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{line}")?;
        // fsync: a committed account/channel change is on disk before we report
        // success, so a crash or power loss can't lose it.
        f.sync_all()
    }

    // How many entries the log currently holds.
    fn len(&self) -> usize {
        self.entries.len()
    }

    // Rewrite the log to a minimal snapshot: one event per live account and
    // channel, authored under our origin at fresh sequence numbers. Peers
    // re-converge because the register events overwrite and cert replay is
    // idempotent. The version vector resets to our origin; peers re-advertise
    // theirs on the next sync. Written to a temp file and renamed, so a crash
    // leaves the old log.
    fn compact(&mut self, events: Vec<Event>) -> std::io::Result<()> {
        let mut seq = self.next_seq();
        let mut last_global = None;
        let mut snapshot = Vec::with_capacity(events.len());
        for event in events {
            let entry = if event.scope() == Scope::Global {
                self.lamport += 1;
                let e = LogEntry { origin: self.origin.clone(), seq, lamport: self.lamport, event };
                last_global = Some(seq);
                seq += 1;
                e
            } else {
                LogEntry { origin: self.origin.clone(), seq: 0, lamport: 0, event }
            };
            snapshot.push(entry);
        }
        let tmp = self.path.with_extension("compact");
        {
            let mut f = std::fs::File::create(&tmp)?;
            for entry in &snapshot {
                writeln!(f, "{}", serde_json::to_string(entry).unwrap_or_default())?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        self.versions = HashMap::new();
        if let Some(last) = last_global {
            self.versions.insert(self.origin.clone(), last);
        }
        self.entries = snapshot;
        Ok(())
    }
}

// What an ingested entry did to a locally-known account, so the engine can log
// out sessions that were relying on it.
pub enum AccountChange {
    TakenOver(String),
    Dropped(String),
    // A gossiped suspension that is now in force: local sessions must be logged
    // out, but the account (and its channels) stay put.
    Suspended(String),
}

// A fingerprint is hex (hash digest), optionally colon-separated. Bound the
// length so a junk value can't bloat an account.
fn valid_fp(fp: &str) -> bool {
    let hex = fp.chars().filter(|c| *c != ':').count();
    (32..=128).contains(&hex) && fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

// The expensive, password-derived half of an account, computed once at
// registration. Split out from `register` so the derivation (two SCRAM
// verifiers, ~1s at the default cost) can run off the reactor via spawn_blocking.
// The SCRAM verifier is the sole password credential: SCRAM logins use it
// directly, and PLAIN/IDENTIFY verify the plaintext against it (see
// `scram::verify_plain`), so there is no separate password hash to keep in step.
pub struct Credentials {
    pub(crate) scram256: String,
    pub(crate) scram512: String,
}

pub struct Db {
    accounts: HashMap<String, Account>, // keyed by casefolded name
    channels: HashMap<String, ChannelInfo>, // keyed by casefolded name
    grouped: HashMap<String, String>, // casefolded alias nick -> canonical account name
    log: EventLog,
    // PBKDF2 cost baked into new SCRAM verifiers; lowered by tests.
    pub(crate) scram_iterations: u32,
    // Whether outbound email is configured, so email features can gate themselves.
    email_enabled: bool,
    // Display name, accent colour, and optional logo URL for email templates.
    email_brand: String,
    email_accent: String,
    email_logo: String,
    // Node-local, non-persisted email codes, keyed by account.
    codes: HashMap<String, PendingCode>,
    // Node-local, non-persisted brute-force throttle for password authentication.
    auth_fails: HashMap<String, AuthThrottle>,
    // Last vhost REQUEST time per account (in-memory, anti-spam), unix secs.
    vhost_req_times: HashMap<String, u64>,
    // Last ReportServ REPORT time per reporter (in-memory, anti-spam), unix secs.
    report_times: HashMap<String, u64>,
    // Registered service bots (BotServ), keyed by casefolded nick.
    bots: HashMap<String, Bot>,
    // HostServ node config: the self-serve offer menu, the forbidden-pattern
    // blocklist, and the auto-vhost template.
    host_cfg: HostConfig,
    // Network-wide replicated lists: bans (AKILL/SQLINE) and news.
    net: NetData,
    // Services ignores (OperServ IGNORE), node-local and in-memory.
    ignores: Vec<Ignore>,
    // Juped servers (OperServ JUPE), node-local: the introducing node owns them,
    // so they aren't federated (that would collide SIDs across nodes).
    jupes: Vec<Jupe>,
    jupe_seq: u32,
    // Network defence level (OperServ DEFCON), 5 = normal down to 1 = lockdown.
    // Node-local; the derived restrictions are read by the engine and services.
    defcon: u8,
    // When set, account identity is owned by an external authority (e.g. the
    // website): IRC can't register or change credentials, only authenticate
    // against accounts pushed in (via the gRPC Accounts API). Node-local config.
    external_accounts: bool,
}

// A juped server: the held name, the fake server id we allocated for it, and why.
#[derive(Debug, Clone)]
pub struct Jupe {
    pub name: String,
    pub sid: String,
    pub reason: String,
}

// Network-wide HostServ configuration, rebuilt from the event log.
#[derive(Debug, Clone, Default)]
pub struct HostConfig {
    // Specs users may self-assign with TAKE.
    pub offers: Vec<String>,
    // Regex patterns a user-requested/taken vhost may not match (anti-impersonation).
    pub forbidden: Vec<String>,
    // Auto-vhost template, e.g. "$account.users.example" (DEFAULT substitutes).
    pub template: Option<String>,
}

// A pending emailed code and how many wrong guesses remain before it is burned.
struct PendingCode {
    kind: CodeKind,
    code: String,
    deadline: Instant,
    tries_left: u8,
}

// Failed-authentication state for one account (in memory only, reset on restart).
struct AuthThrottle {
    fails: u32,
    locked_until: Option<Instant>,
}

// Wrong-code guesses tolerated before a code is invalidated (defence in depth on
// top of the code's own entropy).
const CODE_TRIES: u8 = 5;
// Free password attempts before the exponential backoff kicks in, and its cap.
const AUTH_FREE_TRIES: u32 = 3;
const AUTH_MAX_BACKOFF_SECS: u64 = 300;

fn key(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Db {
    pub fn open(path: impl Into<PathBuf>, origin: impl Into<String>) -> Self {
        let (log, events) = EventLog::open(path.into(), origin.into());
        let mut accounts = HashMap::new();
        let mut channels = HashMap::new();
        let mut grouped = HashMap::new();
        let mut bots = HashMap::new();
        let mut host_cfg = HostConfig::default();
        let mut net = NetData::default();
        for event in events {
            apply(&mut accounts, &mut channels, &mut grouped, &mut bots, &mut host_cfg, &mut net, event);
        }
        tracing::info!(accounts = accounts.len(), channels = channels.len(), "account store loaded");
        Self { accounts, channels, grouped, log, scram_iterations: scram::DEFAULT_ITERATIONS, email_enabled: false, email_brand: "Network Services".to_string(), email_accent: "#4f46e5".to_string(), email_logo: String::new(), codes: HashMap::new(), auth_fails: HashMap::new(), vhost_req_times: HashMap::new(), report_times: HashMap::new(), bots, host_cfg, net, ignores: Vec::new(), jupes: Vec::new(), jupe_seq: 0, defcon: 5, external_accounts: false }
    }

    /// Fold an entry authored by another node into the store — the services-side
    /// of the gossip seam. Idempotent (re-delivered entries are dropped). Returns
    /// the account name if this ingest changed its owner (a registration conflict
    /// resolved against the local claim), so the caller can log out stale sessions.
    pub fn ingest(&mut self, entry: LogEntry) -> std::io::Result<Option<AccountChange>> {
        // Snapshot the incoming account's local owner before applying, to detect a
        // takeover (home changed) or a remote drop (it disappears).
        let watched: Option<(String, Option<String>)> = match &entry.event {
            Event::AccountRegistered(a) => Some((a.name.clone(), self.account(&a.name).map(|c| c.home.clone()))),
            Event::AccountDropped { account } => Some((account.clone(), self.account(account).map(|c| c.home.clone()))),
            _ => None,
        };
        let applied = self.log.ingest(entry)?;
        // A freshly applied suspension may need to terminate local sessions.
        let suspended = applied.as_ref().and_then(|e| match e {
            Event::AccountSuspended { account, .. } => Some(account.clone()),
            _ => None,
        });
        if let Some(event) = applied {
            apply(&mut self.accounts, &mut self.channels, &mut self.grouped, &mut self.bots, &mut self.host_cfg, &mut self.net, event);
        }
        if let Some((name, prev_home)) = watched {
            match (prev_home, self.account(&name).map(|c| c.home.clone())) {
                (Some(prev), Some(cur)) if cur != prev => return Ok(Some(AccountChange::TakenOver(name))),
                (Some(_), None) => return Ok(Some(AccountChange::Dropped(name))),
                _ => {}
            }
        }
        if let Some(account) = suspended {
            // Only if the suspension is actually in force (not an already-expired one).
            if self.is_suspended(&account) {
                return Ok(Some(AccountChange::Suspended(account)));
            }
        }
        Ok(None)
    }

    /// Rewrite the log to one entry per account and channel, reclaiming churn.
    pub fn compact(&mut self) -> std::io::Result<()> {
        let before = self.log.len();
        let mut snapshot: Vec<Event> = self.accounts.values().cloned().map(|a| Event::AccountRegistered(Box::new(a))).collect();
        for c in self.channels.values() {
            snapshot.push(Event::ChannelRegistered { name: c.name.clone(), founder: c.founder.clone(), ts: c.ts });
            if !c.lock_on.is_empty() || !c.lock_off.is_empty() {
                snapshot.push(Event::ChannelMlock { name: c.name.clone(), on: c.lock_on.clone(), off: c.lock_off.clone() });
            }
            for a in &c.access {
                snapshot.push(Event::ChannelAccessAdd { channel: c.name.clone(), account: a.account.clone(), level: a.level.clone() });
            }
            for k in &c.akick {
                snapshot.push(Event::ChannelAkickAdd { channel: c.name.clone(), mask: k.mask.clone(), reason: k.reason.clone() });
            }
            if !c.desc.is_empty() {
                snapshot.push(Event::ChannelDescSet { channel: c.name.clone(), desc: c.desc.clone() });
            }
            if !c.entrymsg.is_empty() {
                snapshot.push(Event::ChannelEntryMsgSet { channel: c.name.clone(), msg: c.entrymsg.clone() });
            }
            if c.settings.signkick || c.settings.private || c.settings.peace || c.settings.secureops || c.settings.keeptopic || c.settings.topiclock {
                snapshot.push(Event::ChannelSettingsSet { channel: c.name.clone(), settings: c.settings });
            }
            if !c.topic.is_empty() {
                snapshot.push(Event::ChannelTopicSet { channel: c.name.clone(), topic: c.topic.clone() });
            }
            if let Some(s) = &c.suspension {
                snapshot.push(Event::ChannelSuspended { channel: c.name.clone(), by: s.by.clone(), reason: s.reason.clone(), ts: s.ts, expires: s.expires });
            }
            if let Some(bot) = &c.assigned_bot {
                snapshot.push(Event::ChannelBotAssigned { channel: c.name.clone(), bot: bot.clone() });
            }
            if c.kickers.any() || c.kickers.dontkickops || c.kickers.ttb > 0 || c.kickers.ban_expire > 0 || c.kickers.votekick > 0 {
                snapshot.push(Event::ChannelKickerSet { channel: c.name.clone(), kickers: c.kickers.clone() });
            }
            if !c.badwords.is_empty() {
                snapshot.push(Event::ChannelBadwordsSet { channel: c.name.clone(), badwords: c.badwords.clone() });
            }
            if !c.triggers.is_empty() {
                snapshot.push(Event::ChannelTriggersSet { channel: c.name.clone(), triggers: c.triggers.clone() });
            }
            if let Some(note) = &c.oper_note {
                snapshot.push(Event::ChannelOperNoteSet { channel: c.name.clone(), note: Some(note.clone()) });
            }
        }
        for (nick, account) in &self.grouped {
            snapshot.push(Event::NickGrouped { nick: nick.clone(), account: account.clone() });
        }
        for b in self.bots.values() {
            snapshot.push(Event::BotAdded(b.clone()));
        }
        if self.net.default_bot.is_some() {
            snapshot.push(Event::DefaultBotSet { bot: self.net.default_bot.clone() });
        }
        for host in &self.host_cfg.offers {
            snapshot.push(Event::VhostOfferAdded { host: host.clone() });
        }
        for pattern in &self.host_cfg.forbidden {
            snapshot.push(Event::VhostForbidAdded { pattern: pattern.clone() });
        }
        if self.host_cfg.template.is_some() {
            snapshot.push(Event::VhostTemplateSet { template: self.host_cfg.template.clone() });
        }
        // Compaction is a good moment to forget akills that have already expired.
        let now = now();
        for f in &self.net.forbids {
            snapshot.push(Event::ForbidAdded { kind: f.kind.clone(), mask: f.mask.clone(), setter: f.setter.clone(), reason: f.reason.clone(), ts: f.ts });
        }
        for a in self.net.akills.iter().filter(|a| a.expires.is_none_or(|e| e > now)) {
            snapshot.push(Event::AkillAdded { kind: a.kind.clone(), mask: a.mask.clone(), setter: a.setter.clone(), reason: a.reason.clone(), ts: a.ts, expires: a.expires });
        }
        for n in &self.net.news {
            snapshot.push(Event::NewsAdded { id: n.id, kind: n.kind.clone(), text: n.text.clone(), setter: n.setter.clone(), ts: n.ts });
        }
        for r in &self.net.reports {
            snapshot.push(Event::ReportFiled { id: r.id, reporter: r.reporter.clone(), target: r.target.clone(), reason: r.reason.clone(), ts: r.ts });
            if !r.open {
                snapshot.push(Event::ReportClosed { id: r.id });
            }
        }
        for g in &self.net.groups {
            snapshot.push(Event::GroupRegistered { name: g.name.clone(), founder: g.founder.clone(), ts: g.ts });
            for m in &g.members {
                snapshot.push(Event::GroupFlagsSet { name: g.name.clone(), account: m.account.clone(), flags: m.flags.clone() });
            }
        }
        for t in &self.net.help {
            snapshot.push(Event::HelpRequested { id: t.id, requester: t.requester.clone(), message: t.message.clone(), ts: t.ts });
            if let Some(h) = &t.handler {
                snapshot.push(Event::HelpTaken { id: t.id, handler: h.clone() });
            }
            if !t.open {
                snapshot.push(Event::HelpClosed { id: t.id });
            }
        }
        for (account, grant) in &self.net.opers {
            snapshot.push(Event::OperGranted { account: account.clone(), privs: grant.privs.clone(), expires: grant.expires });
        }
        for e in &self.net.sess_exceptions {
            snapshot.push(Event::SessionExceptionAdded { mask: e.mask.clone(), limit: e.limit, reason: e.reason.clone() });
        }
        self.log.compact(snapshot)?;
        tracing::info!(before, after = self.log.len(), "compacted event log");
        Ok(())
    }

    /// Whether the log has grown enough past the live state to be worth compacting.
    pub fn should_compact(&self) -> bool {
        self.log.len() > (self.accounts.len() + self.channels.len()) * 3 + 64
    }

    /// Wire the log to a broadcast channel; each new entry is pushed to peers.
    pub fn set_outbound(&mut self, tx: broadcast::Sender<LogEntry>) {
        self.log.set_outbound(tx);
    }

    /// The number of entries in the log, a mark to later diff against.
    pub fn log_len(&self) -> usize {
        self.log.len()
    }

    /// The events appended since `mark` (a value from an earlier [`log_len`]).
    pub fn events_since(&self, mark: usize) -> Vec<Event> {
        self.log.events_from(mark)
    }

    /// Our version vector, advertised to peers so they can send what we lack.
    pub fn version_vector(&self) -> HashMap<String, u64> {
        self.log.version_vector()
    }

    /// The log entries a peer is missing, given the version vector it sent.
    pub fn missing_for(&self, peer: &HashMap<String, u64>) -> Vec<LogEntry> {
        self.log.missing_for(peer)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.resolved_key(name).is_some()
    }

    // Resolve a name (a registered account, or a nick grouped to one) to the
    // owning account's storage key.
    fn resolved_key(&self, name: &str) -> Option<String> {
        let k = key(name);
        if self.accounts.contains_key(&k) {
            return Some(k);
        }
        self.grouped.get(&k).map(|acct| key(acct))
    }

    /// The canonical account name for `name`, whether it is the account itself or
    /// a nick grouped to it.
    pub fn resolve_account(&self, name: &str) -> Option<&str> {
        let k = self.resolved_key(name)?;
        self.accounts.get(&k).map(|a| a.name.as_str())
    }

    /// Group alias `nick` to an existing `account`.
    pub fn group_nick(&mut self, nick: &str, account: &str) -> Result<(), RegError> {
        if !self.accounts.contains_key(&key(account)) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::NickGrouped { nick: nick.to_string(), account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.grouped.insert(key(nick), account.to_string());
        Ok(())
    }

    /// Remove grouped alias `nick`. Ok(false) if it wasn't grouped.
    pub fn ungroup_nick(&mut self, nick: &str) -> Result<bool, RegError> {
        if !self.grouped.contains_key(&key(nick)) {
            return Ok(false);
        }
        self.log.append(Event::NickUngrouped { nick: nick.to_string() }).map_err(|_| RegError::Internal)?;
        self.grouped.remove(&key(nick));
        Ok(true)
    }

    /// The alias nicks grouped to `account` (not the account name itself).
    pub fn grouped_nicks(&self, account: &str) -> Vec<String> {
        self.grouped.iter().filter(|(_, a)| a.eq_ignore_ascii_case(account)).map(|(nick, _)| nick.clone()).collect()
    }

    /// Derive the password-bound half of an account. Pure and CPU-heavy (no
    /// `&self`), so a caller can run it on a blocking thread; the cheap
    /// `register_prepared` then commits the result.
    pub fn derive_credentials(password: &str, iterations: u32) -> Option<Credentials> {
        Some(Credentials {
            scram256: scram::make_verifier(Hash::Sha256, password, iterations),
            scram512: scram::make_verifier(Hash::Sha512, password, iterations),
        })
    }

}

fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (
        pattern.chars().flat_map(char::to_lowercase).collect(),
        text.chars().flat_map(char::to_lowercase).collect(),
    );
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// A random 6-digit code for email verification / password reset.
// An unguessable emailed code: 8 characters from a 32-symbol unambiguous
// alphabet (~40 bits). 256 is an exact multiple of 32, so the byte->symbol map
// is bias-free. Long enough that it can't be brute-forced inside its 15-minute
// window even without the per-code attempt limit.
fn gen_code() -> String {
    const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // no 0/O/1/I
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| ALPHABET[(*x % 32) as usize] as char).collect()
}


// The module-facing account/channel store. Every method forwards to Db's own
// (fully-qualified so it is the inherent method, never this trait method), with
// reads projected into credential-free views. Internal callers keep using the
// richer inherent methods directly.


#[cfg(test)]
mod tests;
