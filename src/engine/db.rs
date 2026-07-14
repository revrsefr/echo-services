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

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::scram::{self, Hash};

// Error kinds, the emailed-code purpose, and the module-facing views live in the
// fedserv-api SDK crate; re-exported so the engine keeps naming them locally and
// modules importing `crate::engine::db::{ChanError, ...}` are unaffected.
pub use fedserv_api::{
    AccountView, AjoinView, AkillView, BotView, Caps, GroupView, IgnoreView, MemoView, NewsView, Privs, ReportView, SuspensionView, ChanAccessView, ChanAkickView, ChanError, ChanSetting, ChannelView, CertError, CodeKind, Kicker, RegError, Store, TriggerView, VhostView,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub password_hash: String,
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
    // Personal greet a bot shows when this account joins a greet-enabled channel.
    #[serde(default)]
    pub greet: String,
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

// Event-sourced persistence: every change is an Event appended to a JSONL log,
// and account state is the fold of that log. Replicating this log across nodes
// is what turns the store federated later, without changing the services.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum Event {
    // Boxed: Account is far larger than any other variant, so this keeps every
    // small event in the log from being sized to it.
    AccountRegistered(Box<Account>),
    CertAdded { account: String, fp: String },
    CertRemoved { account: String, fp: String },
    AccountEmailSet { account: String, email: Option<String> },
    AccountGreetSet { account: String, greet: String },
    AccountPasswordSet { account: String, password_hash: String, scram256: String, scram512: String },
    AccountDropped { account: String },
    AccountVerified { account: String },
    AjoinAdded { account: String, channel: String, key: String },
    AjoinRemoved { account: String, channel: String },
    VhostSet { account: String, host: String, setter: String, ts: u64, expires: Option<u64> },
    VhostDeleted { account: String },
    VhostRequested { account: String, host: String, ts: u64 },
    VhostRequestCleared { account: String },
    AccountSuspended { account: String, by: String, reason: String, ts: u64, expires: Option<u64> },
    AccountUnsuspended { account: String },
    MemoSent { account: String, from: String, text: String, ts: u64 },
    MemoRead { account: String, index: usize },
    MemoDeleted { account: String, index: usize },
    NickGrouped { nick: String, account: String },
    NickUngrouped { nick: String },
    ChannelRegistered { name: String, founder: String, ts: u64 },
    ChannelDropped { name: String },
    ChannelMlock { name: String, on: String, off: String },
    ChannelAccessAdd { channel: String, account: String, level: String },
    ChannelAccessDel { channel: String, account: String },
    ChannelAkickAdd { channel: String, mask: String, reason: String },
    ChannelAkickDel { channel: String, mask: String },
    ChannelFounderSet { channel: String, founder: String },
    ChannelDescSet { channel: String, desc: String },
    ChannelEntryMsgSet { channel: String, msg: String },
    ChannelSettingsSet { channel: String, settings: ChanSettings },
    ChannelKickerSet { channel: String, kickers: KickerSettings },
    ChannelBadwordsSet { channel: String, badwords: Vec<String> },
    ChannelTriggersSet { channel: String, triggers: Vec<Trigger> },
    ChannelTopicSet { channel: String, topic: String },
    ChannelSuspended { channel: String, by: String, reason: String, ts: u64, expires: Option<u64> },
    ChannelUnsuspended { channel: String },
    ChannelBotAssigned { channel: String, bot: String },
    ChannelBotUnassigned { channel: String },
    BotAdded(Bot),
    BotRemoved { nick: String },
    VhostOfferAdded { host: String },
    VhostOfferRemoved { host: String },
    VhostForbidAdded { pattern: String },
    VhostForbidRemoved { pattern: String },
    VhostTemplateSet { template: Option<String> },
    // Inactivity-expiry bookkeeping. Seen/Used stamp last activity (coalesced, so
    // at most one per account/channel per day); NoExpire pins a record so the
    // sweep never expires it.
    AccountSeen { account: String, ts: u64 },
    ChannelUsed { channel: String, ts: u64 },
    AccountNoExpire { account: String, on: bool },
    ChannelNoExpire { channel: String, on: bool },
    // An impending-expiry warning email was sent; cleared by the next Seen/Used.
    AccountExpiryWarned { account: String },
    ChannelExpiryWarned { channel: String },
    // A staff note set or cleared (OperServ INFO).
    AccountOperNoteSet { account: String, note: Option<String> },
    ChannelOperNoteSet { channel: String, note: Option<String> },
    // News items (OperServ NEWS). The stable `id` makes deletion order-independent.
    NewsAdded { id: u64, kind: String, text: String, setter: String, ts: u64 },
    NewsDeleted { id: u64 },
    // Abuse reports (ReportServ). Global so any node's operators see the queue.
    ReportFiled { id: u64, reporter: String, target: String, reason: String, ts: u64 },
    ReportClosed { id: u64 },
    ReportDeleted { id: u64 },
    // User groups (GroupServ). Global — groups are account identity.
    GroupRegistered { name: String, founder: String, ts: u64 },
    GroupDropped { name: String },
    GroupFounderSet { name: String, founder: String },
    // Upsert a member (empty flags = a plain member, still present).
    GroupFlagsSet { name: String, account: String, flags: String },
    // Remove a member from a group entirely.
    GroupMemberDel { name: String, account: String },
    // Runtime operator grants (OperServ OPER).
    OperGranted {
        account: String,
        privs: Vec<String>,
        #[serde(default)]
        expires: Option<u64>,
    },
    OperRevoked { account: String },
    // Session-limit exceptions (OperServ SESSION).
    SessionExceptionAdded { mask: String, limit: u32, reason: String },
    SessionExceptionRemoved { mask: String },
    // Network bans (OperServ AKILL / SQLINE). Global: a ban covers the whole
    // network, so every node holds the list and re-applies it at burst. `kind`
    // is the ircd X-line type and defaults to "G" for records predating it.
    AkillAdded {
        #[serde(default = "gline_kind")]
        kind: String,
        mask: String,
        setter: String,
        reason: String,
        ts: u64,
        expires: Option<u64>,
    },
    AkillRemoved {
        #[serde(default = "gline_kind")]
        kind: String,
        mask: String,
    },
}

// Whether an event replicates across the federation. Account identity is Global
// (one owner, gossiped everywhere); channel state is Local (scoped to the one
// network that authored it, so a node can't be handed ownership of a channel it
// never saw registered). Exhaustive on purpose: a new event must pick a side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Global,
    Local,
}

impl Event {
    fn scope(&self) -> Scope {
        match self {
            Event::AccountRegistered(_)
            | Event::CertAdded { .. }
            | Event::CertRemoved { .. }
            | Event::AccountEmailSet { .. }
            | Event::AccountGreetSet { .. }
            | Event::AccountPasswordSet { .. }
            | Event::AccountDropped { .. }
            | Event::AccountVerified { .. }
            | Event::AjoinAdded { .. }
            | Event::AjoinRemoved { .. }
            | Event::VhostSet { .. }
            | Event::VhostDeleted { .. }
            | Event::VhostRequested { .. }
            | Event::VhostRequestCleared { .. }
            | Event::AccountSuspended { .. }
            | Event::AccountUnsuspended { .. }
            | Event::MemoSent { .. }
            | Event::MemoRead { .. }
            | Event::MemoDeleted { .. }
            | Event::NickGrouped { .. }
            | Event::NickUngrouped { .. }
            | Event::AccountSeen { .. }
            | Event::AccountNoExpire { .. }
            | Event::AccountExpiryWarned { .. }
            | Event::AccountOperNoteSet { .. }
            | Event::AkillAdded { .. }
            | Event::AkillRemoved { .. }
            | Event::NewsAdded { .. }
            | Event::NewsDeleted { .. }
            | Event::ReportFiled { .. }
            | Event::ReportClosed { .. }
            | Event::ReportDeleted { .. }
            | Event::GroupRegistered { .. }
            | Event::GroupDropped { .. }
            | Event::GroupFounderSet { .. }
            | Event::GroupFlagsSet { .. }
            | Event::GroupMemberDel { .. }
            | Event::OperGranted { .. }
            | Event::OperRevoked { .. }
            | Event::SessionExceptionAdded { .. }
            | Event::SessionExceptionRemoved { .. } => Scope::Global,
            Event::ChannelRegistered { .. }
            | Event::ChannelDropped { .. }
            | Event::ChannelMlock { .. }
            | Event::ChannelAccessAdd { .. }
            | Event::ChannelAccessDel { .. }
            | Event::ChannelAkickAdd { .. }
            | Event::ChannelAkickDel { .. }
            | Event::ChannelFounderSet { .. }
            | Event::ChannelDescSet { .. }
            | Event::ChannelEntryMsgSet { .. }
            | Event::ChannelSettingsSet { .. }
            | Event::ChannelKickerSet { .. }
            | Event::ChannelBadwordsSet { .. }
            | Event::ChannelTriggersSet { .. }
            | Event::ChannelTopicSet { .. }
            | Event::ChannelSuspended { .. }
            | Event::ChannelUnsuspended { .. }
            | Event::ChannelBotAssigned { .. }
            | Event::ChannelBotUnassigned { .. }
            | Event::BotAdded(_)
            | Event::BotRemoved { .. }
            | Event::VhostOfferAdded { .. }
            | Event::VhostOfferRemoved { .. }
            | Event::VhostForbidAdded { .. }
            | Event::VhostForbidRemoved { .. }
            | Event::VhostTemplateSet { .. }
            | Event::ChannelUsed { .. }
            | Event::ChannelNoExpire { .. }
            | Event::ChannelExpiryWarned { .. }
            | Event::ChannelOperNoteSet { .. } => Scope::Local,
        }
    }
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
    pub news: Vec<News>,
    pub news_seq: u64,
    // Abuse reports (ReportServ), oldest first.
    pub reports: Vec<Report>,
    pub report_seq: u64,
    // User groups (GroupServ).
    pub groups: Vec<Group>,
    // Runtime services operators (OperServ OPER), casefolded account -> grant.
    // Merged with the declarative [[oper]] config at the engine.
    pub opers: HashMap<String, OperGrant>,
    // Session-limit exceptions (OperServ SESSION): per-IP-mask allowances.
    pub sess_exceptions: Vec<SessionException>,
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
    // Free-text description, shown in INFO.
    #[serde(default)]
    pub desc: String,
    // Message noticed to users as they join.
    #[serde(default)]
    pub entrymsg: String,
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
            .and_then(|a| fedserv_api::level_caps(&a.level).auto)
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
}

impl EventLog {
    fn open(path: PathBuf, origin: String) -> (Self, Vec<Event>) {
        let mut log = Self { path, origin, lamport: 0, versions: HashMap::new(), entries: Vec::new(), outbound: None };
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
        let global = event.scope() == Scope::Global;
        let entry = if global {
            self.lamport += 1;
            LogEntry { origin: self.origin.clone(), seq: self.next_seq(), lamport: self.lamport, event }
        } else {
            LogEntry { origin: self.origin.clone(), seq: 0, lamport: 0, event }
        };
        self.persist(&entry)?;
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
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(entry).unwrap_or_default())
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
}

// A fingerprint is hex (hash digest), optionally colon-separated. Bound the
// length so a junk value can't bloat an account.
fn valid_fp(fp: &str) -> bool {
    let hex = fp.chars().filter(|c| *c != ':').count();
    (32..=128).contains(&hex) && fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

// The expensive, password-derived half of an account, computed once at
// registration. Split out from `register` so the derivation (argon2 + two SCRAM
// verifiers, ~1s at the default cost) can run off the reactor via spawn_blocking.
pub struct Credentials {
    pub(crate) password_hash: String,
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
        if let Some(event) = self.log.ingest(entry)? {
            apply(&mut self.accounts, &mut self.channels, &mut self.grouped, &mut self.bots, &mut self.host_cfg, &mut self.net, event);
        }
        if let Some((name, prev_home)) = watched {
            match (prev_home, self.account(&name).map(|c| c.home.clone())) {
                (Some(prev), Some(cur)) if cur != prev => return Ok(Some(AccountChange::TakenOver(name))),
                (Some(_), None) => return Ok(Some(AccountChange::Dropped(name))),
                _ => {}
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
            password_hash: hash_password(password)?,
            scram256: scram::make_verifier(Hash::Sha256, password, iterations),
            scram512: scram::make_verifier(Hash::Sha512, password, iterations),
        })
    }

    /// Commit pre-derived credentials as a new account. Cheap: no key stretching.
    pub fn register_prepared(&mut self, name: &str, creds: Credentials, email: Option<String>) -> Result<(), RegError> {
        if self.exists(name) {
            return Err(RegError::Exists);
        }
        // Unverified only when email confirmation actually applies (email is
        // configured and an address was given); otherwise verified immediately.
        let verified = !(self.email_enabled && email.is_some());
        let account = Account {
            name: name.to_string(),
            password_hash: creds.password_hash,
            email,
            ts: now(),
            home: self.log.origin.clone(),
            scram256: Some(creds.scram256),
            scram512: Some(creds.scram512),
            certfps: Vec::new(),
            verified,
            ajoin: Vec::new(),
            suspension: None,
            memos: Vec::new(),
            greet: String::new(),
            vhost: None,
            vhost_request: None,
            last_seen: now(),
            noexpire: false,
            expiry_warned: false,
            oper_note: None,
        };
        self.log.append(Event::AccountRegistered(Box::new(account.clone()))).map_err(|_| RegError::Internal)?;
        self.accounts.insert(key(name), account);
        Ok(())
    }

    /// Provision a new account directly from pre-derived SCRAM verifiers (no
    /// plaintext), for bulk backfill from an external authority that stores
    /// verifiers rather than passwords. `password_hash` is left empty — typed-
    /// password login stays disabled until a real password is set — but SCRAM and
    /// keycard login work at once. Refuses if the account already exists (so a
    /// backfill can't clobber a fully-credentialed account). `scram512` empty =
    /// SCRAM-SHA-512 unavailable for this account (it falls back to 256).
    pub fn provision_account(&mut self, name: &str, scram256: &str, scram512: &str, email: Option<String>) -> Result<(), RegError> {
        if self.exists(name) {
            return Err(RegError::Exists);
        }
        if name.is_empty() || scram256.is_empty() {
            return Err(RegError::Internal);
        }
        let account = Account {
            name: name.to_string(),
            password_hash: String::new(),
            email,
            ts: now(),
            home: self.log.origin.clone(),
            scram256: Some(scram256.to_string()),
            scram512: (!scram512.is_empty()).then(|| scram512.to_string()),
            certfps: Vec::new(),
            verified: true, // the external authority vouches for it
            ajoin: Vec::new(),
            suspension: None,
            memos: Vec::new(),
            greet: String::new(),
            vhost: None,
            vhost_request: None,
            last_seen: now(),
            noexpire: false,
            expiry_warned: false,
            oper_note: None,
        };
        self.log.append(Event::AccountRegistered(Box::new(account.clone()))).map_err(|_| RegError::Internal)?;
        self.accounts.insert(key(name), account);
        Ok(())
    }

    /// Register synchronously, deriving and committing in one call. A test helper;
    /// the live paths derive off-thread via `derive_credentials` + `register_prepared`.
    #[cfg(test)]
    pub fn register(&mut self, name: &str, password: &str, email: Option<String>) -> Result<(), RegError> {
        let creds = Self::derive_credentials(password, self.scram_iterations).ok_or(RegError::Internal)?;
        self.register_prepared(name, creds, email)
    }

    #[cfg(test)]
    pub(crate) fn test_hash(&self, name: &str) -> Option<String> {
        self.accounts.get(&key(name)).map(|a| a.password_hash.clone())
    }

    /// Check credentials; on success return the account's canonical name (its
    /// stored casing), else None.
    pub fn authenticate(&self, name: &str, password: &str) -> Option<&str> {
        let account = self.accounts.get(&self.resolved_key(name)?)?;
        verify_password(password, &account.password_hash).then_some(account.name.as_str())
    }

    /// The account's canonical name and its SCRAM verifier for `mech`, if any.
    pub fn scram_lookup(&self, name: &str, mech: &str) -> Option<(&str, &str)> {
        let account = self.accounts.get(&self.resolved_key(name)?)?;
        let verifier = match mech {
            "SCRAM-SHA-256" => account.scram256.as_deref(),
            "SCRAM-SHA-512" => account.scram512.as_deref(),
            _ => None,
        }?;
        Some((account.name.as_str(), verifier))
    }

    /// The canonical name of the account owning `fp`, if any. Fingerprints are
    /// globally unique, so this is unambiguous.
    pub fn certfp_owner(&self, fp: &str) -> Option<&str> {
        let fp = fp.to_ascii_lowercase();
        self.accounts.values().find(|a| a.certfps.contains(&fp)).map(|a| a.name.as_str())
    }

    /// The fingerprints registered to an account (empty if unknown/none).
    pub fn certfps(&self, account: &str) -> &[String] {
        self.accounts.get(&key(account)).map_or(&[], |a| a.certfps.as_slice())
    }

    /// Whether outbound email is configured.
    pub fn email_enabled(&self) -> bool {
        self.email_enabled
    }

    /// Whether `account`'s email is confirmed (true for unknown/legacy accounts).
    pub fn is_verified(&self, account: &str) -> bool {
        self.account(account).is_none_or(|a| a.verified)
    }

    /// Mark `account`'s email confirmed.
    pub fn verify_account(&mut self, account: &str) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountVerified { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().verified = true;
        Ok(())
    }

    pub fn set_email_enabled(&mut self, on: bool) {
        self.email_enabled = on;
    }

    /// Display name used in email templates.
    pub fn email_brand(&self) -> &str {
        &self.email_brand
    }

    /// Accent colour used in email templates.
    pub fn email_accent(&self) -> &str {
        &self.email_accent
    }

    /// Logo image URL for email templates (empty = show the brand name as text).
    pub fn email_logo(&self) -> &str {
        &self.email_logo
    }

    pub fn set_email_brand(&mut self, brand: &str) {
        self.email_brand = brand.to_string();
    }

    pub fn set_email_accent(&mut self, accent: &str) {
        self.email_accent = accent.to_string();
    }

    pub fn set_email_logo(&mut self, logo: &str) {
        self.email_logo = logo.to_string();
    }

    /// Issue a fresh emailed code for `account` and purpose, valid for 15 minutes.
    pub fn issue_code(&mut self, account: &str, kind: CodeKind) -> String {
        let code = gen_code();
        self.codes.insert(
            key(account),
            PendingCode { kind, code: code.clone(), deadline: Instant::now() + Duration::from_secs(900), tries_left: CODE_TRIES },
        );
        code
    }

    /// Consume a code for `account`: true if the purpose and code match and it
    /// hasn't expired. A wrong guess burns a try and the code is dropped once
    /// they run out, so it can't be ground down online.
    pub fn take_code(&mut self, account: &str, kind: CodeKind, code: &str) -> bool {
        let k = key(account);
        let Some(pc) = self.codes.get_mut(&k) else { return false };
        if pc.deadline <= Instant::now() {
            self.codes.remove(&k);
            return false;
        }
        if pc.kind == kind && pc.code == code {
            self.codes.remove(&k);
            return true;
        }
        pc.tries_left = pc.tries_left.saturating_sub(1);
        if pc.tries_left == 0 {
            self.codes.remove(&k);
        }
        false
    }

    /// Seconds the caller must wait before another password attempt on `account`,
    /// or None if it is not currently throttled.
    pub fn auth_lockout(&self, account: &str) -> Option<u64> {
        let until = self.auth_fails.get(&key(account))?.locked_until?;
        let now = Instant::now();
        (until > now).then(|| (until - now).as_secs() + 1)
    }

    /// Record the outcome of a password attempt against `account`. Success clears
    /// the counter; each failure past a few free tries grows an exponential
    /// backoff, throttling guessing without a hard lockout a griefer could abuse.
    pub fn note_auth(&mut self, account: &str, success: bool) {
        let k = key(account);
        if success {
            self.auth_fails.remove(&k);
            return;
        }
        let t = self.auth_fails.entry(k).or_insert(AuthThrottle { fails: 0, locked_until: None });
        t.fails += 1;
        if t.fails > AUTH_FREE_TRIES {
            let shift = (t.fails - AUTH_FREE_TRIES - 1).min(9);
            let secs = (1u64 << shift).min(AUTH_MAX_BACKOFF_SECS);
            t.locked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    /// Set (or clear) `account`'s email.
    pub fn set_email(&mut self, account: &str, email: Option<String>) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountEmailSet { account: account.to_string(), email: email.clone() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().email = email;
        Ok(())
    }

    /// Assign a vhost to `account`. `setter` is who did it; `ttl` is seconds until
    /// it expires, or None for a permanent vhost.
    pub fn set_vhost(&mut self, account: &str, host: &str, setter: &str, ttl: Option<u64>) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        let ts = now();
        let expires = ttl.map(|t| ts + t);
        self.log.append(Event::VhostSet { account: account.to_string(), host: host.to_string(), setter: setter.to_string(), ts, expires }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().vhost = Some(Vhost { host: host.to_string(), setter: setter.to_string(), ts, expires });
        Ok(())
    }

    /// Remove `account`'s vhost. Returns whether one was set.
    pub fn del_vhost(&mut self, account: &str) -> Result<bool, RegError> {
        let k = key(account);
        match self.accounts.get(&k) {
            Some(a) if a.vhost.is_some() => {}
            Some(_) => return Ok(false),
            None => return Err(RegError::Internal),
        }
        self.log.append(Event::VhostDeleted { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().vhost = None;
        Ok(true)
    }


    /// Record a pending vhost request for `account` (awaiting approval).
    pub fn request_vhost(&mut self, account: &str, host: &str) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        let ts = now();
        self.log.append(Event::VhostRequested { account: account.to_string(), host: host.to_string(), ts }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().vhost_request = Some(PendingVhost { host: host.to_string(), ts });
        self.vhost_req_times.insert(k, ts);
        Ok(())
    }

    /// Seconds a member must wait before requesting another vhost (0 = allowed).
    pub fn vhost_request_wait(&self, account: &str) -> u64 {
        const COOLDOWN: u64 = 60;
        match self.vhost_req_times.get(&key(account)) {
            Some(&last) => COOLDOWN.saturating_sub(now().saturating_sub(last)),
            None => 0,
        }
    }

    /// Clear a pending vhost request (on approval or rejection). Returns the
    /// requested host, if there was one.
    pub fn take_vhost_request(&mut self, account: &str) -> Result<Option<String>, RegError> {
        let k = key(account);
        let host = match self.accounts.get(&k) {
            Some(a) => a.vhost_request.as_ref().map(|r| r.host.clone()),
            None => return Err(RegError::Internal),
        };
        if host.is_some() {
            self.log.append(Event::VhostRequestCleared { account: account.to_string() }).map_err(|_| RegError::Internal)?;
            self.accounts.get_mut(&k).unwrap().vhost_request = None;
        }
        Ok(host)
    }

    /// Every account with a pending vhost request, as (account, host).
    pub fn vhost_requests(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .accounts
            .values()
            .filter_map(|a| a.vhost_request.as_ref().map(|r| (a.name.clone(), r.host.clone())))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Add a vhost offer to the self-serve menu. Ok(false) if already offered.
    pub fn vhost_offer_add(&mut self, host: &str) -> Result<bool, RegError> {
        if self.host_cfg.offers.iter().any(|o| o == host) {
            return Ok(false);
        }
        self.log.append(Event::VhostOfferAdded { host: host.to_string() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.offers.push(host.to_string());
        Ok(true)
    }

    /// Remove the offer at 1-based `index`. Returns the removed spec, if valid.
    pub fn vhost_offer_del(&mut self, index: usize) -> Result<Option<String>, RegError> {
        if index == 0 || index > self.host_cfg.offers.len() {
            return Ok(None);
        }
        let host = self.host_cfg.offers[index - 1].clone();
        self.log.append(Event::VhostOfferRemoved { host: host.clone() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.offers.retain(|o| o != &host);
        Ok(Some(host))
    }

    /// The self-serve vhost offer menu.
    pub fn vhost_offers(&self) -> &[String] {
        &self.host_cfg.offers
    }

    /// Add a forbidden vhost regex (anti-impersonation). Validates it compiles;
    /// Ok(false) if already present.
    pub fn vhost_forbid_add(&mut self, pattern: &str) -> Result<bool, RegError> {
        if regex::RegexBuilder::new(pattern).size_limit(BADWORD_SIZE_LIMIT).build().is_err() {
            return Err(RegError::Internal);
        }
        if self.host_cfg.forbidden.iter().any(|p| p == pattern) {
            return Ok(false);
        }
        self.log.append(Event::VhostForbidAdded { pattern: pattern.to_string() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.forbidden.push(pattern.to_string());
        Ok(true)
    }

    /// Remove the forbidden pattern at 1-based `index`; returns it if valid.
    pub fn vhost_forbid_del(&mut self, index: usize) -> Result<Option<String>, RegError> {
        if index == 0 || index > self.host_cfg.forbidden.len() {
            return Ok(None);
        }
        let pattern = self.host_cfg.forbidden[index - 1].clone();
        self.log.append(Event::VhostForbidRemoved { pattern: pattern.clone() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.forbidden.retain(|p| p != &pattern);
        Ok(Some(pattern))
    }

    pub fn vhost_forbidden(&self) -> &[String] {
        &self.host_cfg.forbidden
    }

    /// Whether `host` matches a forbidden pattern (case-insensitive).
    pub fn vhost_is_forbidden(&self, host: &str) -> bool {
        !self.host_cfg.forbidden.is_empty() && build_badword_set(&self.host_cfg.forbidden).is_match(host)
    }

    /// Set (or clear) the auto-vhost template, e.g. "$account.users.example".
    pub fn set_vhost_template(&mut self, template: Option<String>) -> Result<(), RegError> {
        self.log.append(Event::VhostTemplateSet { template: template.clone() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.template = template;
        Ok(())
    }

    pub fn vhost_template(&self) -> Option<&str> {
        self.host_cfg.template.as_deref()
    }

    /// The account whose current (non-expired) vhost is `host`, if any — so a
    /// vhost can't be assigned to two accounts and collide on the network.
    pub fn vhost_owner(&self, host: &str) -> Option<String> {
        self.accounts
            .values()
            .find(|a| a.vhost.as_ref().is_some_and(|v| v.host.eq_ignore_ascii_case(host) && v.expires.is_none_or(|e| e > now())))
            .map(|a| a.name.clone())
    }

    /// Every account that has a vhost, as (account, host, setter, expires).
    pub fn vhosts(&self) -> Vec<(String, String, String, Option<u64>)> {
        let mut out: Vec<(String, String, String, Option<u64>)> = self
            .accounts
            .values()
            .filter_map(|a| a.vhost.as_ref().map(|v| (a.name.clone(), v.host.clone(), v.setter.clone(), v.expires)))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Set (or clear, when empty) `account`'s personal greet.
    pub fn set_greet(&mut self, account: &str, greet: &str) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountGreetSet { account: account.to_string(), greet: greet.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().greet = greet.to_string();
        Ok(())
    }

    /// Replace `account`'s password with freshly derived credentials.
    pub fn set_credentials(&mut self, account: &str, creds: Credentials) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log
            .append(Event::AccountPasswordSet {
                account: account.to_string(),
                password_hash: creds.password_hash.clone(),
                scram256: creds.scram256.clone(),
                scram512: creds.scram512.clone(),
            })
            .map_err(|_| RegError::Internal)?;
        let a = self.accounts.get_mut(&k).unwrap();
        a.password_hash = creds.password_hash;
        a.scram256 = Some(creds.scram256);
        a.scram512 = Some(creds.scram512);
        Ok(())
    }

    /// Delete `account`. Ok(false) if it wasn't registered.
    pub fn drop_account(&mut self, account: &str) -> Result<bool, RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Ok(false);
        }
        self.log.append(Event::AccountDropped { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.remove(&k);
        Ok(true)
    }

    /// Register `fp` to `account`. Fingerprints are one-to-one with accounts.
    pub fn certfp_add(&mut self, account: &str, fp: &str) -> Result<(), CertError> {
        let fp = fp.to_ascii_lowercase();
        if !valid_fp(&fp) {
            return Err(CertError::Invalid);
        }
        if self.certfp_owner(&fp).is_some() {
            return Err(CertError::InUse);
        }
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(CertError::NoAccount);
        }
        self.log.append(Event::CertAdded { account: account.to_string(), fp: fp.clone() }).map_err(|_| CertError::Internal)?;
        self.accounts.get_mut(&k).unwrap().certfps.push(fp);
        Ok(())
    }

    /// Remove `fp` from `account`. Ok(false) if the account had no such fingerprint.
    pub fn certfp_del(&mut self, account: &str, fp: &str) -> Result<bool, CertError> {
        let fp = fp.to_ascii_lowercase();
        let k = key(account);
        match self.accounts.get(&k) {
            None => return Err(CertError::NoAccount),
            Some(a) if !a.certfps.contains(&fp) => return Ok(false),
            Some(_) => {}
        }
        self.log.append(Event::CertRemoved { account: account.to_string(), fp: fp.clone() }).map_err(|_| CertError::Internal)?;
        self.accounts.get_mut(&k).unwrap().certfps.retain(|c| *c != fp);
        Ok(true)
    }

    /// The account's auto-join list.
    pub fn ajoin_list(&self, account: &str) -> &[AjoinEntry] {
        self.accounts.get(&key(account)).map_or(&[], |a| a.ajoin.as_slice())
    }

    /// Add a channel to the account's auto-join list (updating the key if it was
    /// already listed). Returns whether it was newly added.
    pub fn ajoin_add(&mut self, account: &str, channel: &str, join_key: &str) -> Result<bool, RegError> {
        let k = key(account);
        let Some(a) = self.accounts.get(&k) else { return Err(RegError::Internal) };
        let existed = a.ajoin.iter().any(|e| e.channel.eq_ignore_ascii_case(channel));
        self.log
            .append(Event::AjoinAdded { account: account.to_string(), channel: channel.to_string(), key: join_key.to_string() })
            .map_err(|_| RegError::Internal)?;
        let a = self.accounts.get_mut(&k).unwrap();
        a.ajoin.retain(|e| !e.channel.eq_ignore_ascii_case(channel));
        a.ajoin.push(AjoinEntry { channel: channel.to_string(), key: join_key.to_string() });
        Ok(!existed)
    }

    /// Remove a channel from the account's auto-join list. Returns whether it was present.
    pub fn ajoin_del(&mut self, account: &str, channel: &str) -> Result<bool, RegError> {
        let k = key(account);
        let Some(a) = self.accounts.get(&k) else { return Err(RegError::Internal) };
        if !a.ajoin.iter().any(|e| e.channel.eq_ignore_ascii_case(channel)) {
            return Ok(false);
        }
        self.log
            .append(Event::AjoinRemoved { account: account.to_string(), channel: channel.to_string() })
            .map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().ajoin.retain(|e| !e.channel.eq_ignore_ascii_case(channel));
        Ok(true)
    }

    /// Suspend an account. `expires` is an absolute unix time (None = permanent).
    pub fn suspend_account(&mut self, account: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        let ts = now();
        self.log
            .append(Event::AccountSuspended { account: account.to_string(), by: by.to_string(), reason: reason.to_string(), ts, expires })
            .map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().suspension = Some(Suspension { by: by.to_string(), reason: reason.to_string(), ts, expires });
        Ok(())
    }

    /// Lift a suspension. Returns whether one was set.
    pub fn unsuspend_account(&mut self, account: &str) -> Result<bool, RegError> {
        let k = key(account);
        match self.accounts.get(&k) {
            None => return Err(RegError::Internal),
            Some(a) if a.suspension.is_none() => return Ok(false),
            Some(_) => {}
        }
        self.log.append(Event::AccountUnsuspended { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().suspension = None;
        Ok(true)
    }

    /// Whether an account has a set, unexpired suspension (evaluated lazily — no timer).
    pub fn is_suspended(&self, account: &str) -> bool {
        self.accounts
            .get(&key(account))
            .and_then(|a| a.suspension.as_ref())
            .is_some_and(|s| s.expires.is_none_or(|e| e > now()))
    }

    /// Stamp an account as active at `now`, coalesced: a fresh stamp is logged
    /// only once its last one is a day old, so routine logins don't flood the
    /// log. No-op for an account that doesn't exist.
    pub fn mark_account_seen(&mut self, account: &str, now: u64) {
        const COALESCE: u64 = 86_400;
        let k = key(account);
        let stale = self.accounts.get(&k).is_some_and(|a| now.saturating_sub(a.last_seen.max(a.ts)) >= COALESCE);
        if stale {
            let _ = self.log.append(Event::AccountSeen { account: account.to_string(), ts: now });
            if let Some(a) = self.accounts.get_mut(&k) {
                a.last_seen = a.last_seen.max(now);
            }
        }
    }

    /// Stamp a channel as used at `now`, coalesced like [`mark_account_seen`].
    pub fn mark_channel_used(&mut self, channel: &str, now: u64) {
        const COALESCE: u64 = 86_400;
        let k = key(channel);
        let stale = self.channels.get(&k).is_some_and(|c| now.saturating_sub(c.last_used.max(c.ts)) >= COALESCE);
        if stale {
            let _ = self.log.append(Event::ChannelUsed { channel: channel.to_string(), ts: now });
            if let Some(c) = self.channels.get_mut(&k) {
                c.last_used = c.last_used.max(now);
            }
        }
    }

    /// Pin or unpin an account against inactivity-expiry. Returns whether the
    /// flag actually changed.
    pub fn set_account_noexpire(&mut self, account: &str, on: bool) -> Result<bool, RegError> {
        let k = key(account);
        match self.accounts.get(&k) {
            None => Err(RegError::Internal),
            Some(a) if a.noexpire == on => Ok(false),
            Some(_) => {
                self.log.append(Event::AccountNoExpire { account: account.to_string(), on }).map_err(|_| RegError::Internal)?;
                self.accounts.get_mut(&k).unwrap().noexpire = on;
                Ok(true)
            }
        }
    }

    /// Pin or unpin a channel against inactivity-expiry.
    pub fn set_channel_noexpire(&mut self, channel: &str, on: bool) -> Result<bool, ChanError> {
        let k = key(channel);
        match self.channels.get(&k) {
            None => Err(ChanError::NoChannel),
            Some(c) if c.noexpire == on => Ok(false),
            Some(_) => {
                self.log.append(Event::ChannelNoExpire { channel: channel.to_string(), on }).map_err(|_| ChanError::Internal)?;
                self.channels.get_mut(&k).unwrap().noexpire = on;
                Ok(true)
            }
        }
    }

    /// Accounts inactive longer than `ttl` seconds as of `now` and eligible to be
    /// expired: not pinned (NOEXPIRE) and not currently suspended. Callers apply
    /// their own further guards (skip opers and live sessions) before dropping.
    pub fn expired_accounts(&self, now: u64, ttl: u64) -> Vec<String> {
        self.accounts
            .values()
            .filter(|a| !a.noexpire && a.suspension.is_none() && now.saturating_sub(a.last_seen.max(a.ts)) > ttl)
            .map(|a| a.name.clone())
            .collect()
    }

    /// Channels unused longer than `ttl` seconds as of `now` and eligible to be
    /// expired: not pinned and not suspended.
    pub fn expired_channels(&self, now: u64, ttl: u64) -> Vec<String> {
        self.channels
            .values()
            .filter(|c| !c.noexpire && c.suspension.is_none() && now.saturating_sub(c.last_used.max(c.ts)) > ttl)
            .map(|c| c.name.clone())
            .collect()
    }

    /// Accounts entering the warning window — inactive past `ttl - lead` but not
    /// yet past `ttl` — that have an email, aren't pinned or suspended, and
    /// haven't already been warned this idle spell. Returns (account, email,
    /// seconds until expiry).
    pub fn accounts_to_warn(&self, now: u64, ttl: u64, lead: u64) -> Vec<(String, String, u64)> {
        let floor = ttl.saturating_sub(lead);
        self.accounts
            .values()
            .filter(|a| !a.noexpire && !a.expiry_warned && a.suspension.is_none() && a.email.is_some())
            .filter_map(|a| {
                let idle = now.saturating_sub(a.last_seen.max(a.ts));
                (idle > floor && idle <= ttl).then(|| (a.name.clone(), a.email.clone().unwrap_or_default(), ttl - idle))
            })
            .collect()
    }

    /// Channels entering the warning window, paired with their founder's email
    /// (skipped when the founder has none). Returns (channel, email, seconds left).
    pub fn channels_to_warn(&self, now: u64, ttl: u64, lead: u64) -> Vec<(String, String, u64)> {
        let floor = ttl.saturating_sub(lead);
        self.channels
            .values()
            .filter(|c| !c.noexpire && !c.expiry_warned && c.suspension.is_none())
            .filter_map(|c| {
                let idle = now.saturating_sub(c.last_used.max(c.ts));
                if idle <= floor || idle > ttl {
                    return None;
                }
                let email = self.accounts.get(&key(&c.founder)).and_then(|a| a.email.clone())?;
                Some((c.name.clone(), email, ttl - idle))
            })
            .collect()
    }

    /// Record that an account has been warned about impending expiry.
    pub fn mark_account_warned(&mut self, account: &str) {
        let k = key(account);
        if self.accounts.contains_key(&k) {
            let _ = self.log.append(Event::AccountExpiryWarned { account: account.to_string() });
            if let Some(a) = self.accounts.get_mut(&k) {
                a.expiry_warned = true;
            }
        }
    }

    /// Record that a channel has been warned about impending expiry.
    pub fn mark_channel_warned(&mut self, channel: &str) {
        let k = key(channel);
        if self.channels.contains_key(&k) {
            let _ = self.log.append(Event::ChannelExpiryWarned { channel: channel.to_string() });
            if let Some(c) = self.channels.get_mut(&k) {
                c.expiry_warned = true;
            }
        }
    }

    /// Set or clear an account's staff note. Returns whether the account exists.
    pub fn set_account_note(&mut self, account: &str, note: Option<String>) -> bool {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return false;
        }
        let _ = self.log.append(Event::AccountOperNoteSet { account: account.to_string(), note: note.clone() });
        self.accounts.get_mut(&k).unwrap().oper_note = note;
        true
    }

    /// An account's staff note, if any.
    pub fn account_note(&self, account: &str) -> Option<String> {
        self.accounts.get(&key(account)).and_then(|a| a.oper_note.clone())
    }

    /// Set or clear a channel's staff note. Returns whether the channel exists.
    pub fn set_channel_note(&mut self, channel: &str, note: Option<String>) -> bool {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return false;
        }
        let _ = self.log.append(Event::ChannelOperNoteSet { channel: channel.to_string(), note: note.clone() });
        self.channels.get_mut(&k).unwrap().oper_note = note;
        true
    }

    /// A channel's staff note, if any.
    pub fn channel_note(&self, channel: &str) -> Option<String> {
        self.channels.get(&key(channel)).and_then(|c| c.oper_note.clone())
    }

    /// Add (or refresh) a `kind` network ban. Returns whether it was newly added.
    pub fn akill_add(&mut self, kind: &str, mask: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError> {
        let same = |a: &Akill| a.kind == kind && a.mask.eq_ignore_ascii_case(mask);
        let fresh = !self.net.akills.iter().any(|a| same(a) && a.expires.is_none_or(|e| e > now()));
        self.log
            .append(Event::AkillAdded { kind: kind.to_string(), mask: mask.to_string(), setter: setter.to_string(), reason: reason.to_string(), ts: now(), expires })
            .map_err(|_| RegError::Internal)?;
        self.net.akills.retain(|a| !same(a));
        self.net.akills.push(Akill { kind: kind.to_string(), mask: mask.to_string(), setter: setter.to_string(), reason: reason.to_string(), ts: now(), expires });
        Ok(fresh)
    }

    /// Lift a `kind` network ban. Returns whether a live one was removed.
    pub fn akill_del(&mut self, kind: &str, mask: &str) -> Result<bool, RegError> {
        let same = |a: &Akill| a.kind == kind && a.mask.eq_ignore_ascii_case(mask);
        let existed = self.net.akills.iter().any(|a| same(a) && a.expires.is_none_or(|e| e > now()));
        if !existed {
            return Ok(false);
        }
        self.log.append(Event::AkillRemoved { kind: kind.to_string(), mask: mask.to_string() }).map_err(|_| RegError::Internal)?;
        self.net.akills.retain(|a| !same(a));
        Ok(true)
    }

    /// The live network bans (expired ones hidden lazily), oldest first.
    pub fn akills(&self) -> Vec<AkillView> {
        let now = now();
        self.net.akills
            .iter()
            .filter(|a| a.expires.is_none_or(|e| e > now))
            .map(|a| AkillView { kind: a.kind.clone(), mask: a.mask.clone(), setter: a.setter.clone(), reason: a.reason.clone(), ts: a.ts, expires: a.expires })
            .collect()
    }

    /// Add (or replace) a session-limit exception for an IP-mask.
    pub fn session_except_add(&mut self, mask: &str, limit: u32, reason: &str) {
        let _ = self.log.append(Event::SessionExceptionAdded { mask: mask.to_string(), limit, reason: reason.to_string() });
        self.net.sess_exceptions.retain(|e| !e.mask.eq_ignore_ascii_case(mask));
        self.net.sess_exceptions.push(SessionException { mask: mask.to_string(), limit, reason: reason.to_string() });
    }

    /// Remove a session-limit exception. Returns whether one existed.
    pub fn session_except_del(&mut self, mask: &str) -> bool {
        let existed = self.net.sess_exceptions.iter().any(|e| e.mask.eq_ignore_ascii_case(mask));
        if existed {
            let _ = self.log.append(Event::SessionExceptionRemoved { mask: mask.to_string() });
            self.net.sess_exceptions.retain(|e| !e.mask.eq_ignore_ascii_case(mask));
        }
        existed
    }

    /// The session-limit exceptions, as (mask, limit, reason).
    pub fn session_exceptions(&self) -> Vec<(String, u32, String)> {
        self.net.sess_exceptions.iter().map(|e| (e.mask.clone(), e.limit, e.reason.clone())).collect()
    }

    /// The session allowance for `ip` from any matching exception (the most
    /// permissive wins), or None if none matches. A limit of 0 means unlimited.
    pub fn session_exception_for(&self, ip: &str) -> Option<u32> {
        self.net
            .sess_exceptions
            .iter()
            .filter(|e| glob_match(&e.mask.to_ascii_lowercase(), &ip.to_ascii_lowercase()))
            .map(|e| e.limit)
            .max_by_key(|&l| if l == 0 { u32::MAX } else { l })
    }

    /// Grant runtime operator privileges to an account (replaces any existing),
    /// optionally expiring at an absolute unix time.
    pub fn oper_grant(&mut self, account: &str, privs: Vec<String>, expires: Option<u64>) {
        let _ = self.log.append(Event::OperGranted { account: account.to_string(), privs: privs.clone(), expires });
        self.net.opers.insert(key(account), OperGrant { privs, expires });
    }

    /// Revoke a runtime operator grant. Returns whether one existed.
    pub fn oper_revoke(&mut self, account: &str) -> bool {
        if !self.net.opers.contains_key(&key(account)) {
            return false;
        }
        let _ = self.log.append(Event::OperRevoked { account: account.to_string() });
        self.net.opers.remove(&key(account));
        true
    }

    /// The live runtime operator grants, as (account, privilege-names, expiry);
    /// expired ones are hidden.
    pub fn opers_list(&self) -> Vec<(String, Vec<String>, Option<u64>)> {
        let now = now();
        self.net
            .opers
            .iter()
            .filter(|(_, g)| g.expires.is_none_or(|e| e > now))
            .map(|(a, g)| (a.clone(), g.privs.clone(), g.expires))
            .collect()
    }

    /// The runtime privileges granted to an account as of `now`, if the grant is
    /// present and unexpired (config opers are merged in separately by the engine).
    pub fn oper_privs_of(&self, account: &str, now: u64) -> Option<Privs> {
        self.net
            .opers
            .get(&key(account))
            .filter(|g| g.expires.is_none_or(|e| e > now))
            .map(|g| Privs::from_names(&g.privs))
    }

    /// Add a news item of `kind` ("logon"/"oper"). Returns its stable id.
    pub fn news_add(&mut self, kind: &str, text: &str, setter: &str) -> u64 {
        let id = self.net.news_seq;
        let ts = now();
        let _ = self.log.append(Event::NewsAdded { id, kind: kind.to_string(), text: text.to_string(), setter: setter.to_string(), ts });
        self.net.news_seq = id + 1;
        self.net.news.push(News { id, kind: kind.to_string(), text: text.to_string(), setter: setter.to_string(), ts });
        id
    }

    /// Delete a news item by id. Returns whether one existed.
    pub fn news_del(&mut self, id: u64) -> bool {
        let existed = self.net.news.iter().any(|n| n.id == id);
        if existed {
            let _ = self.log.append(Event::NewsDeleted { id });
            self.net.news.retain(|n| n.id != id);
        }
        existed
    }

    /// The news items of `kind`, oldest first.
    pub fn news(&self, kind: &str) -> Vec<NewsView> {
        self.net
            .news
            .iter()
            .filter(|n| n.kind == kind)
            .map(|n| NewsView { id: n.id, text: n.text.clone(), setter: n.setter.clone(), ts: n.ts })
            .collect()
    }

    /// Whether account identity is owned by an external authority.
    pub fn external_accounts(&self) -> bool {
        self.external_accounts
    }

    /// Set external-account mode (from config, at startup).
    pub fn set_external_accounts(&mut self, on: bool) {
        self.external_accounts = on;
    }

    /// The network defence level (5 = normal, 1 = full lockdown).
    pub fn defcon(&self) -> u8 {
        self.defcon
    }

    /// Set the defence level, clamped to 1..=5.
    pub fn set_defcon(&mut self, level: u8) {
        self.defcon = level.clamp(1, 5);
    }

    /// Whether new nick/account registrations are frozen (defcon 3 or lower).
    pub fn registrations_frozen(&self) -> bool {
        self.defcon <= 3
    }

    /// Whether new channel registrations are frozen (defcon 4 or lower).
    pub fn channel_regs_frozen(&self) -> bool {
        self.defcon <= 4
    }

    /// Jupe a server name: allocate a fake sid, store it, return the sid to
    /// introduce (or the existing sid if the name is already juped).
    pub fn jupe_add(&mut self, name: &str, reason: &str) -> String {
        if let Some(j) = self.jupes.iter().find(|j| j.name.eq_ignore_ascii_case(name)) {
            return j.sid.clone();
        }
        let sid = jupe_sid(self.jupe_seq);
        self.jupe_seq += 1;
        self.jupes.push(Jupe { name: name.to_string(), sid: sid.clone(), reason: reason.to_string() });
        sid
    }

    /// Lift a jupe. Returns the sid to squit if it existed.
    pub fn jupe_del(&mut self, name: &str) -> Option<String> {
        let sid = self.jupes.iter().find(|j| j.name.eq_ignore_ascii_case(name)).map(|j| j.sid.clone())?;
        self.jupes.retain(|j| !j.name.eq_ignore_ascii_case(name));
        Some(sid)
    }

    /// The juped servers, as (name, sid, reason).
    pub fn jupes(&self) -> Vec<(String, String, String)> {
        self.jupes.iter().map(|j| (j.name.clone(), j.sid.clone(), j.reason.clone())).collect()
    }

    /// File an abuse report, rate-limited per reporter. Returns the new report's
    /// id, or None if the reporter filed one too recently.
    pub fn report_file(&mut self, reporter: &str, target: &str, reason: &str) -> Option<u64> {
        const COOLDOWN: u64 = 30;
        let now = now();
        let key = reporter.to_ascii_lowercase();
        if self.report_times.get(&key).is_some_and(|&t| now.saturating_sub(t) < COOLDOWN) {
            return None;
        }
        self.report_times.insert(key, now);
        let id = self.net.report_seq;
        let _ = self.log.append(Event::ReportFiled { id, reporter: reporter.to_string(), target: target.to_string(), reason: reason.to_string(), ts: now });
        self.net.report_seq = id + 1;
        self.net.reports.push(Report { id, reporter: reporter.to_string(), target: target.to_string(), reason: reason.to_string(), ts: now, open: true });
        Some(id)
    }

    /// Close (resolve) a report. Returns whether an open one was closed.
    pub fn report_close(&mut self, id: u64) -> bool {
        let closed = self.net.reports.iter().any(|r| r.id == id && r.open);
        if closed {
            let _ = self.log.append(Event::ReportClosed { id });
            if let Some(r) = self.net.reports.iter_mut().find(|r| r.id == id) {
                r.open = false;
            }
        }
        closed
    }

    /// Delete a report entirely. Returns whether one existed.
    pub fn report_del(&mut self, id: u64) -> bool {
        let existed = self.net.reports.iter().any(|r| r.id == id);
        if existed {
            let _ = self.log.append(Event::ReportDeleted { id });
            self.net.reports.retain(|r| r.id != id);
        }
        existed
    }

    /// The reports, newest first. `open_only` hides closed ones.
    pub fn reports(&self, open_only: bool) -> Vec<ReportView> {
        self.net
            .reports
            .iter()
            .rev()
            .filter(|r| !open_only || r.open)
            .map(|r| ReportView { id: r.id, reporter: r.reporter.clone(), target: r.target.clone(), reason: r.reason.clone(), ts: r.ts, open: r.open })
            .collect()
    }

    /// A single report by id, if present.
    pub fn report(&self, id: u64) -> Option<ReportView> {
        self.net.reports.iter().find(|r| r.id == id).map(|r| ReportView { id: r.id, reporter: r.reporter.clone(), target: r.target.clone(), reason: r.reason.clone(), ts: r.ts, open: r.open })
    }

    /// Register a new group (name must start with `!`). Founder is an account.
    pub fn group_register(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        if !name.starts_with('!') || name.len() < 2 {
            return Err(ChanError::InvalidPattern);
        }
        if self.group(name).is_some() {
            return Err(ChanError::Exists);
        }
        let ts = now();
        self.log.append(Event::GroupRegistered { name: name.to_string(), founder: founder.to_string(), ts }).map_err(|_| ChanError::Internal)?;
        self.net.groups.push(Group { name: name.to_string(), founder: founder.to_string(), ts, members: Vec::new() });
        Ok(())
    }

    /// Drop a group.
    pub fn group_drop(&mut self, name: &str) -> Result<(), ChanError> {
        if self.group(name).is_none() {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::GroupDropped { name: name.to_string() }).map_err(|_| ChanError::Internal)?;
        let k = key(name);
        self.net.groups.retain(|g| key(&g.name) != k);
        Ok(())
    }

    /// Upsert a group member with `flags` (empty = a plain member).
    pub fn group_set_flags(&mut self, name: &str, account: &str, flags: &str) -> Result<(), ChanError> {
        let k = key(name);
        let Some(g) = self.net.groups.iter_mut().find(|g| key(&g.name) == k) else {
            return Err(ChanError::NoChannel);
        };
        self.log.append(Event::GroupFlagsSet { name: name.to_string(), account: account.to_string(), flags: flags.to_string() }).map_err(|_| ChanError::Internal)?;
        g.members.retain(|m| !m.account.eq_ignore_ascii_case(account));
        g.members.push(GroupMember { account: account.to_string(), flags: flags.to_string() });
        Ok(())
    }

    /// Remove a member from a group. Returns whether one was present.
    pub fn group_del_member(&mut self, name: &str, account: &str) -> Result<bool, ChanError> {
        let k = key(name);
        let Some(g) = self.net.groups.iter_mut().find(|g| key(&g.name) == k) else {
            return Err(ChanError::NoChannel);
        };
        if !g.members.iter().any(|m| m.account.eq_ignore_ascii_case(account)) {
            return Ok(false);
        }
        self.log.append(Event::GroupMemberDel { name: name.to_string(), account: account.to_string() }).map_err(|_| ChanError::Internal)?;
        g.members.retain(|m| !m.account.eq_ignore_ascii_case(account));
        Ok(true)
    }

    /// Transfer a group's founder to another account.
    pub fn group_set_founder(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        let k = key(name);
        let Some(g) = self.net.groups.iter_mut().find(|g| key(&g.name) == k) else {
            return Err(ChanError::NoChannel);
        };
        self.log.append(Event::GroupFounderSet { name: name.to_string(), founder: founder.to_string() }).map_err(|_| ChanError::Internal)?;
        g.founder = founder.to_string();
        Ok(())
    }

    /// A group view (founder + members), if it exists.
    pub fn group(&self, name: &str) -> Option<GroupView> {
        let k = key(name);
        self.net.groups.iter().find(|g| key(&g.name) == k).map(|g| GroupView {
            name: g.name.clone(),
            founder: g.founder.clone(),
            members: g.members.iter().map(|m| fedserv_api::GroupMemberView { account: m.account.clone(), flags: m.flags.clone() }).collect(),
        })
    }

    /// Every group's name, sorted.
    pub fn groups(&self) -> Vec<String> {
        let mut names: Vec<String> = self.net.groups.iter().map(|g| g.name.clone()).collect();
        names.sort();
        names
    }

    /// The groups an account belongs to (founder or member).
    pub fn groups_of(&self, account: &str) -> Vec<String> {
        self.net
            .groups
            .iter()
            .filter(|g| g.founder.eq_ignore_ascii_case(account) || g.members.iter().any(|m| m.account.eq_ignore_ascii_case(account)))
            .map(|g| g.name.clone())
            .collect()
    }

    /// Whether an account is in a group (its founder or a member).
    pub fn is_group_member(&self, name: &str, account: &str) -> bool {
        let k = key(name);
        self.net.groups.iter().find(|g| key(&g.name) == k).is_some_and(|g| g.founder.eq_ignore_ascii_case(account) || g.members.iter().any(|m| m.account.eq_ignore_ascii_case(account)))
    }

    /// An account's effective channel capabilities, combining its direct access
    /// entry with any `!group` access entry it belongs to (the interconnection
    /// that lets a channel grant access to a whole group).
    pub fn channel_caps(&self, channel: &str, account: &str) -> Caps {
        let Some(c) = self.channels.get(&key(channel)) else { return Caps::default() };
        if c.founder.eq_ignore_ascii_case(account) {
            return fedserv_api::level_caps("founder");
        }
        let mut caps = Caps::default();
        for a in &c.access {
            let applies = match a.account.strip_prefix('!') {
                Some(g) => self.is_group_member(&format!("!{g}"), account),
                None => a.account.eq_ignore_ascii_case(account),
            };
            if applies {
                caps = caps.union(fedserv_api::level_caps(&a.level));
            }
        }
        caps
    }

    /// A user's join status mode for a channel, group-aware.
    pub fn channel_join_mode(&self, channel: &str, account: &str) -> Option<&'static str> {
        self.channel_caps(channel, account).auto
    }

    /// Add a services ignore, replacing any existing entry for the same mask.
    pub fn ignore_add(&mut self, mask: &str, reason: &str, expires: Option<u64>) {
        self.ignores.retain(|i| !i.mask.eq_ignore_ascii_case(mask));
        self.ignores.push(Ignore { mask: mask.to_string(), reason: reason.to_string(), expires });
    }

    /// Remove a services ignore. Returns whether a live one was removed.
    pub fn ignore_del(&mut self, mask: &str) -> bool {
        let now = now();
        let existed = self.ignores.iter().any(|i| i.mask.eq_ignore_ascii_case(mask) && i.expires.is_none_or(|e| e > now));
        self.ignores.retain(|i| !i.mask.eq_ignore_ascii_case(mask));
        existed
    }

    /// The live services ignores (expired hidden lazily), oldest first.
    pub fn ignores(&self) -> Vec<IgnoreView> {
        let now = now();
        self.ignores
            .iter()
            .filter(|i| i.expires.is_none_or(|e| e > now))
            .map(|i| IgnoreView { mask: i.mask.clone(), reason: i.reason.clone(), expires: i.expires })
            .collect()
    }

    /// Whether a user is currently ignored by services. A mask with an `@` is
    /// matched against `nick!*@host` (we don't track ident); a bare mask against
    /// the nick. Expired entries are swept as they're encountered.
    pub fn is_ignored(&mut self, nick: &str, host: &str) -> bool {
        let now = now();
        self.ignores.retain(|i| i.expires.is_none_or(|e| e > now));
        let full = format!("{}!*@{}", nick.to_ascii_lowercase(), host.to_ascii_lowercase());
        let nick_lc = nick.to_ascii_lowercase();
        self.ignores.iter().any(|i| {
            let m = i.mask.to_ascii_lowercase();
            if m.contains('@') {
                glob_match(&m, &full)
            } else {
                glob_match(&m, &nick_lc)
            }
        })
    }

    /// The account's suspension record, if any (shown in INFO even once expired).
    pub fn suspension(&self, account: &str) -> Option<SuspensionView> {
        self.accounts
            .get(&key(account))
            .and_then(|a| a.suspension.as_ref())
            .map(|s| SuspensionView { by: s.by.clone(), reason: s.reason.clone(), ts: s.ts, expires: s.expires })
    }

    /// Register `name` to `founder` (an account name).
    pub fn register_channel(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        let k = key(name);
        if self.channels.contains_key(&k) {
            return Err(ChanError::Exists);
        }
        let ts = now();
        self.log
            .append(Event::ChannelRegistered { name: name.to_string(), founder: founder.to_string(), ts })
            .map_err(|_| ChanError::Internal)?;
        self.channels.insert(k, ChannelInfo { name: name.to_string(), founder: founder.to_string(), ts, lock_on: String::new(), lock_off: String::new(), access: Vec::new(), akick: Vec::new(), desc: String::new(), entrymsg: String::new(), settings: ChanSettings::default(), topic: String::new(), suspension: None, assigned_bot: None , kickers: KickerSettings::default() , badwords: Vec::new(), badwords_rev: 0 , triggers: Vec::new(), triggers_rev: 0, last_used: ts, noexpire: false, expiry_warned: false, oper_note: None });
        Ok(())
    }

    /// The registration for `name`, if any.
    pub fn channel(&self, name: &str) -> Option<&ChannelInfo> {
        self.channels.get(&key(name))
    }

    /// The account record for `name` (its canonical casing), if registered.
    pub fn account(&self, name: &str) -> Option<&Account> {
        self.accounts.get(&key(name))
    }

    /// All registered channels, for listing.
    pub fn channels(&self) -> impl Iterator<Item = &ChannelInfo> {
        self.channels.values()
    }

    /// All registered accounts, for a directory snapshot (see the gRPC layer).
    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    /// Names of channels founded by `account` (case-insensitive).
    pub fn channels_owned_by(&self, account: &str) -> Vec<String> {
        self.channels
            .values()
            .filter(|c| c.founder.eq_ignore_ascii_case(account))
            .map(|c| c.name.clone())
            .collect()
    }

    /// Set the mode-lock (chars to keep set / unset) for a registered channel.
    pub fn set_mlock(&mut self, name: &str, on: &str, off: &str) -> Result<(), ChanError> {
        let k = key(name);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelMlock { name: name.to_string(), on: on.to_string(), off: off.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.lock_on = on.to_string();
        c.lock_off = off.to_string();
        Ok(())
    }

    /// Grant `account` a level ("op"/"voice") on `channel`.
    pub fn access_add(&mut self, channel: &str, account: &str, level: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelAccessAdd { channel: channel.to_string(), account: account.to_string(), level: level.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.access.retain(|a| !a.account.eq_ignore_ascii_case(account));
        c.access.push(ChanAccess { account: account.to_string(), level: level.to_string() });
        Ok(())
    }

    /// Remove `account` from `channel`'s access list. Ok(false) if not present.
    pub fn access_del(&mut self, channel: &str, account: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else {
            return Err(ChanError::NoChannel);
        };
        if !c.access.iter().any(|a| a.account.eq_ignore_ascii_case(account)) {
            return Ok(false);
        }
        self.log
            .append(Event::ChannelAccessDel { channel: channel.to_string(), account: account.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().access.retain(|a| !a.account.eq_ignore_ascii_case(account));
        Ok(true)
    }

    /// Add an auto-kick `mask` (with `reason`) to `channel`.
    pub fn akick_add(&mut self, channel: &str, mask: &str, reason: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelAkickAdd { channel: channel.to_string(), mask: mask.to_string(), reason: reason.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.akick.retain(|a| !a.mask.eq_ignore_ascii_case(mask));
        c.akick.push(ChanAkick { mask: mask.to_string(), reason: reason.to_string() });
        Ok(())
    }

    /// Remove auto-kick `mask` from `channel`. Ok(false) if not present.
    pub fn akick_del(&mut self, channel: &str, mask: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else {
            return Err(ChanError::NoChannel);
        };
        if !c.akick.iter().any(|a| a.mask.eq_ignore_ascii_case(mask)) {
            return Ok(false);
        }
        self.log
            .append(Event::ChannelAkickDel { channel: channel.to_string(), mask: mask.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().akick.retain(|a| !a.mask.eq_ignore_ascii_case(mask));
        Ok(true)
    }

    /// Transfer `channel`'s founder to `account`.
    pub fn set_founder(&mut self, channel: &str, account: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelFounderSet { channel: channel.to_string(), founder: account.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().founder = account.to_string();
        Ok(())
    }

    /// Set `channel`'s description (empty clears it).
    pub fn set_desc(&mut self, channel: &str, desc: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelDescSet { channel: channel.to_string(), desc: desc.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().desc = desc.to_string();
        Ok(())
    }

    /// Turn one ChanServ SET option on or off for a channel.
    pub fn set_channel_setting(&mut self, channel: &str, setting: ChanSetting, on: bool) -> Result<(), ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        let mut settings = c.settings;
        match setting {
            ChanSetting::SignKick => settings.signkick = on,
            ChanSetting::Private => settings.private = on,
            ChanSetting::Peace => settings.peace = on,
            ChanSetting::SecureOps => settings.secureops = on,
            ChanSetting::KeepTopic => settings.keeptopic = on,
            ChanSetting::TopicLock => settings.topiclock = on,
            ChanSetting::BotGreet => settings.bot_greet = on,
            ChanSetting::NoBot => settings.nobot = on,
        }
        self.log
            .append(Event::ChannelSettingsSet { channel: channel.to_string(), settings })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().settings = settings;
        Ok(())
    }

    /// Turn one BotServ kicker on or off. Caps thresholds are set via
    /// `set_caps_kicker`; passing `Kicker::Caps` here only toggles it off.
    pub fn set_kicker(&mut self, channel: &str, kicker: Kicker, on: bool) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| match kicker {
            Kicker::Caps => k.caps = on,
            Kicker::Bolds => k.bolds = on,
            Kicker::Colors => k.colors = on,
            Kicker::Underlines => k.underlines = on,
            Kicker::Reverses => k.reverses = on,
            Kicker::Italics => k.italics = on,
            Kicker::Flood => k.flood = on,
            Kicker::Repeat => k.repeat = on,
            Kicker::Badwords => k.badwords = on,
            Kicker::Warn => k.warn = on,
            Kicker::DontKickOps => k.dontkickops = on,
            Kicker::DontKickVoices => k.dontkickvoices = on,
        })
    }

    /// Enable the caps kicker with its length/percentage thresholds (0 = default).
    pub fn set_caps_kicker(&mut self, channel: &str, caps_min: u16, caps_percent: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| {
            k.caps = true;
            k.caps_min = caps_min;
            k.caps_percent = caps_percent;
        })
    }

    /// Enable the flood kicker with its lines/seconds thresholds (0 = default).
    pub fn set_flood_kicker(&mut self, channel: &str, lines: u16, secs: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| {
            k.flood = true;
            k.flood_lines = lines;
            k.flood_secs = secs;
        })
    }

    /// Enable the repeat kicker with its repeat-count threshold (0 = default).
    pub fn set_repeat_kicker(&mut self, channel: &str, times: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| {
            k.repeat = true;
            k.repeat_times = times;
        })
    }

    /// Kicks-before-ban threshold (0 = never ban, only kick).
    pub fn set_ttb(&mut self, channel: &str, ttb: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| k.ttb = ttb)
    }

    /// How long a kicker ban lasts, in seconds (0 = until removed).
    pub fn set_ban_expire(&mut self, channel: &str, secs: u32) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| k.ban_expire = secs)
    }

    /// Votes needed for a community !votekick/!voteban (0 = disabled).
    pub fn set_votekick(&mut self, channel: &str, votes: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| k.votekick = votes)
    }

    /// Add a badword regex. Validates it compiles within the size limit; returns
    /// Ok(false) if the exact pattern is already present.
    pub fn badword_add(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError> {
        if regex::RegexBuilder::new(pattern).size_limit(BADWORD_SIZE_LIMIT).build().is_err() {
            return Err(ChanError::InvalidPattern);
        }
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        if c.badwords.iter().any(|w| w == pattern) {
            return Ok(false);
        }
        let mut list = c.badwords.clone();
        list.push(pattern.to_string());
        self.write_badwords(channel, &k, list)?;
        Ok(true)
    }

    /// Remove a badword by exact pattern. Ok(false) if it wasn't listed.
    pub fn badword_del(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        if !c.badwords.iter().any(|w| w == pattern) {
            return Ok(false);
        }
        let list: Vec<String> = c.badwords.iter().filter(|w| *w != pattern).cloned().collect();
        self.write_badwords(channel, &k, list)?;
        Ok(true)
    }

    /// Clear all badwords; returns how many were removed.
    pub fn badword_clear(&mut self, channel: &str) -> Result<usize, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        let n = c.badwords.len();
        if n > 0 {
            self.write_badwords(channel, &k, Vec::new())?;
        }
        Ok(n)
    }

    pub fn badwords(&self, channel: &str) -> &[String] {
        self.channels.get(&key(channel)).map_or(&[], |c| c.badwords.as_slice())
    }

    /// Add an auto-response trigger. Validates the pattern; Ok(false) if the same
    /// pattern is already present.
    pub fn trigger_add(&mut self, channel: &str, pattern: &str, response: &str, cooldown: u32) -> Result<bool, ChanError> {
        if regex::RegexBuilder::new(pattern).size_limit(BADWORD_SIZE_LIMIT).build().is_err() {
            return Err(ChanError::InvalidPattern);
        }
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        if c.triggers.iter().any(|t| t.pattern == pattern) {
            return Ok(false);
        }
        let mut list = c.triggers.clone();
        list.push(Trigger { pattern: pattern.to_string(), response: response.to_string(), cooldown });
        self.write_triggers(channel, &k, list)?;
        Ok(true)
    }

    /// Remove the trigger at 1-based `index`. Ok(false) if out of range.
    pub fn trigger_del(&mut self, channel: &str, index: usize) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        if index == 0 || index > c.triggers.len() {
            return Ok(false);
        }
        let mut list = c.triggers.clone();
        list.remove(index - 1);
        self.write_triggers(channel, &k, list)?;
        Ok(true)
    }

    /// Clear all triggers; returns how many were removed.
    pub fn trigger_clear(&mut self, channel: &str) -> Result<usize, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        let n = c.triggers.len();
        if n > 0 {
            self.write_triggers(channel, &k, Vec::new())?;
        }
        Ok(n)
    }

    pub fn triggers(&self, channel: &str) -> &[Trigger] {
        self.channels.get(&key(channel)).map_or(&[], |c| c.triggers.as_slice())
    }

    fn write_triggers(&mut self, channel: &str, k: &str, list: Vec<Trigger>) -> Result<(), ChanError> {
        self.log
            .append(Event::ChannelTriggersSet { channel: channel.to_string(), triggers: list.clone() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(k).unwrap();
        c.triggers = list;
        c.triggers_rev = c.triggers_rev.wrapping_add(1);
        Ok(())
    }

    /// Dry-run the content kickers against a line: the reason it would be kicked,
    /// or None. Flood/repeat are stateful/time-based and are not simulated here.
    pub fn kicker_test(&self, channel: &str, text: &str) -> Option<String> {
        let c = self.channels.get(&key(channel))?;
        if let Some(reason) = c.kickers.violation(text) {
            return Some(reason.to_string());
        }
        if c.kickers.badwords && !c.badwords.is_empty() && build_badword_set(&c.badwords).is_match(text) {
            return Some("matches a badword".to_string());
        }
        None
    }

    /// Copy one channel's BotServ configuration — kickers, badwords, greet and
    /// nobot — onto another. Both channels must be registered.
    pub fn copy_bot_config(&mut self, src: &str, dst: &str) -> Result<(), ChanError> {
        let (kickers, badwords, bot_greet, nobot) = {
            let s = self.channels.get(&key(src)).ok_or(ChanError::NoChannel)?;
            (s.kickers.clone(), s.badwords.clone(), s.settings.bot_greet, s.settings.nobot)
        };
        let dk = key(dst);
        if !self.channels.contains_key(&dk) {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::ChannelKickerSet { channel: dst.to_string(), kickers: kickers.clone() }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&dk).unwrap().kickers = kickers;
        self.write_badwords(dst, &dk, badwords)?;
        self.set_channel_setting(dst, ChanSetting::BotGreet, bot_greet)?;
        self.set_channel_setting(dst, ChanSetting::NoBot, nobot)?;
        Ok(())
    }

    // Persist a new badword list (whole-list event) and apply it.
    fn write_badwords(&mut self, channel: &str, k: &str, list: Vec<String>) -> Result<(), ChanError> {
        self.log
            .append(Event::ChannelBadwordsSet { channel: channel.to_string(), badwords: list.clone() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(k).unwrap();
        c.badwords = list;
        c.badwords_rev = c.badwords_rev.wrapping_add(1);
        Ok(())
    }

    // Read-modify-write the whole kicker struct through one event.
    fn update_kickers(&mut self, channel: &str, f: impl FnOnce(&mut KickerSettings)) -> Result<(), ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        let mut kickers = c.kickers.clone();
        f(&mut kickers);
        self.log
            .append(Event::ChannelKickerSet { channel: channel.to_string(), kickers: kickers.clone() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().kickers = kickers;
        Ok(())
    }

    /// Remember a channel's topic (KEEPTOPIC / TOPICLOCK).
    pub fn set_channel_topic(&mut self, channel: &str, topic: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelTopicSet { channel: channel.to_string(), topic: topic.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().topic = topic.to_string();
        Ok(())
    }

    /// Suspend a channel. `expires` is absolute unix time (None = permanent).
    pub fn suspend_channel(&mut self, channel: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        let ts = now();
        self.log.append(Event::ChannelSuspended { channel: channel.to_string(), by: by.to_string(), reason: reason.to_string(), ts, expires }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().suspension = Some(Suspension { by: by.to_string(), reason: reason.to_string(), ts, expires });
        Ok(())
    }

    /// Lift a channel suspension. Returns whether one was set.
    pub fn unsuspend_channel(&mut self, channel: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        match self.channels.get(&k) {
            None => return Err(ChanError::NoChannel),
            Some(c) if c.suspension.is_none() => return Ok(false),
            Some(_) => {}
        }
        self.log.append(Event::ChannelUnsuspended { channel: channel.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().suspension = None;
        Ok(true)
    }

    /// Whether a channel has a set, unexpired suspension (lazy — no timer).
    pub fn is_channel_suspended(&self, channel: &str) -> bool {
        self.channels.get(&key(channel)).and_then(|c| c.suspension.as_ref()).is_some_and(|s| s.expires.is_none_or(|e| e > now()))
    }

    /// The channel's suspension record, if any.
    pub fn channel_suspension(&self, channel: &str) -> Option<SuspensionView> {
        self.channels.get(&key(channel)).and_then(|c| c.suspension.as_ref()).map(|s| SuspensionView { by: s.by.clone(), reason: s.reason.clone(), ts: s.ts, expires: s.expires })
    }

    /// Register a service bot.
    pub fn bot_add(&mut self, nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError> {
        let k = key(nick);
        if self.bots.contains_key(&k) {
            return Err(ChanError::Exists);
        }
        let bot = Bot { nick: nick.to_string(), user: user.to_string(), host: host.to_string(), gecos: gecos.to_string(), private: false };
        self.log.append(Event::BotAdded(bot.clone())).map_err(|_| ChanError::Internal)?;
        self.bots.insert(k, bot);
        Ok(())
    }

    /// Mark a bot private (oper-only assign) or public. Returns Ok(false) if
    /// there is no such bot.
    pub fn bot_set_private(&mut self, nick: &str, private: bool) -> Result<bool, ChanError> {
        let k = key(nick);
        let Some(mut bot) = self.bots.get(&k).cloned() else { return Ok(false) };
        bot.private = private;
        self.log.append(Event::BotAdded(bot.clone())).map_err(|_| ChanError::Internal)?;
        self.bots.insert(k, bot);
        Ok(true)
    }

    /// Delete every service bot at once (BOT DEL *). Returns how many went.
    pub fn bot_del_all(&mut self) -> Result<usize, ChanError> {
        let nicks: Vec<String> = self.bots.values().map(|b| b.nick.clone()).collect();
        for n in &nicks {
            self.log.append(Event::BotRemoved { nick: n.clone() }).map_err(|_| ChanError::Internal)?;
        }
        self.bots.clear();
        Ok(nicks.len())
    }

    /// Delete a service bot. Returns whether it existed.
    pub fn bot_del(&mut self, nick: &str) -> Result<bool, ChanError> {
        let k = key(nick);
        if !self.bots.contains_key(&k) {
            return Ok(false);
        }
        self.log.append(Event::BotRemoved { nick: nick.to_string() }).map_err(|_| ChanError::Internal)?;
        self.bots.remove(&k);
        Ok(true)
    }

    /// Change a bot's nick and/or identity. `NoChannel` = no such bot,
    /// `Exists` = the new nick belongs to a different bot. On a rename, every
    /// channel the old bot was assigned to is moved to the new nick.
    pub fn bot_change(&mut self, old: &str, new_nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError> {
        let ok = key(old);
        if !self.bots.contains_key(&ok) {
            return Err(ChanError::NoChannel);
        }
        let nk = key(new_nick);
        let renaming = ok != nk;
        if renaming && self.bots.contains_key(&nk) {
            return Err(ChanError::Exists);
        }
        // Keep the private flag across a change.
        let private = self.bots.get(&ok).map(|b| b.private).unwrap_or(false);
        let bot = Bot { nick: new_nick.to_string(), user: user.to_string(), host: host.to_string(), gecos: gecos.to_string(), private };
        if renaming {
            let chans: Vec<String> = self
                .channels
                .values()
                .filter(|c| c.assigned_bot.as_deref().is_some_and(|b| key(b) == ok))
                .map(|c| c.name.clone())
                .collect();
            self.log.append(Event::BotRemoved { nick: old.to_string() }).map_err(|_| ChanError::Internal)?;
            self.bots.remove(&ok);
            self.log.append(Event::BotAdded(bot.clone())).map_err(|_| ChanError::Internal)?;
            self.bots.insert(nk, bot);
            for chan in chans {
                self.log.append(Event::ChannelBotAssigned { channel: chan.clone(), bot: new_nick.to_string() }).map_err(|_| ChanError::Internal)?;
                self.channels.get_mut(&key(&chan)).unwrap().assigned_bot = Some(new_nick.to_string());
            }
        } else {
            // Same nick, new identity: re-emit BotAdded to overwrite the fields.
            self.log.append(Event::BotAdded(bot.clone())).map_err(|_| ChanError::Internal)?;
            self.bots.insert(nk, bot);
        }
        Ok(())
    }

    /// All registered bots.
    pub fn bots(&self) -> impl Iterator<Item = &Bot> {
        self.bots.values()
    }

    /// Assign a bot to a channel.
    pub fn assign_bot(&mut self, channel: &str, bot: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::ChannelBotAssigned { channel: channel.to_string(), bot: bot.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().assigned_bot = Some(bot.to_string());
        Ok(())
    }

    /// Unassign a channel's bot. Returns whether one was assigned.
    pub fn unassign_bot(&mut self, channel: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        match self.channels.get(&k) {
            None => return Err(ChanError::NoChannel),
            Some(c) if c.assigned_bot.is_none() => return Ok(false),
            Some(_) => {}
        }
        self.log.append(Event::ChannelBotUnassigned { channel: channel.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().assigned_bot = None;
        Ok(true)
    }

    /// Append a memo to an account's mailbox.
    pub fn memo_send(&mut self, account: &str, from: &str, text: &str) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        let ts = now();
        self.log.append(Event::MemoSent { account: account.to_string(), from: from.to_string(), text: text.to_string(), ts }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().memos.push(Memo { from: from.to_string(), text: text.to_string(), ts, read: false });
        Ok(())
    }

    /// An account's memos, oldest first.
    pub fn memo_list(&self, account: &str) -> Vec<MemoView> {
        self.accounts.get(&key(account)).map_or(Vec::new(), |a| {
            a.memos.iter().map(|m| MemoView { from: m.from.clone(), text: m.text.clone(), ts: m.ts, read: m.read }).collect()
        })
    }

    /// Read one memo by index (marks it read), returning its contents.
    pub fn memo_read(&mut self, account: &str, index: usize) -> Option<MemoView> {
        let k = key(account);
        let view = self.accounts.get(&k).and_then(|a| a.memos.get(index)).map(|m| MemoView { from: m.from.clone(), text: m.text.clone(), ts: m.ts, read: m.read })?;
        if !view.read {
            let _ = self.log.append(Event::MemoRead { account: account.to_string(), index });
            if let Some(m) = self.accounts.get_mut(&k).and_then(|a| a.memos.get_mut(index)) {
                m.read = true;
            }
        }
        Some(view)
    }

    /// Delete one memo by index. Returns whether it existed.
    pub fn memo_del(&mut self, account: &str, index: usize) -> bool {
        let k = key(account);
        if !self.accounts.get(&k).is_some_and(|a| index < a.memos.len()) {
            return false;
        }
        let _ = self.log.append(Event::MemoDeleted { account: account.to_string(), index });
        if let Some(a) = self.accounts.get_mut(&k) {
            if index < a.memos.len() {
                a.memos.remove(index);
            }
        }
        true
    }

    /// How many unread memos an account has.
    pub fn unread_memos(&self, account: &str) -> usize {
        self.accounts.get(&key(account)).map_or(0, |a| a.memos.iter().filter(|m| !m.read).count())
    }

    /// Set `channel`'s entry message (empty clears it).
    pub fn set_entrymsg(&mut self, channel: &str, msg: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelEntryMsgSet { channel: channel.to_string(), msg: msg.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().entrymsg = msg.to_string();
        Ok(())
    }

    /// Unregister `name`.
    pub fn drop_channel(&mut self, name: &str) -> Result<(), ChanError> {
        let k = key(name);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::ChannelDropped { name: name.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.remove(&k);
        Ok(())
    }
}

// Whether `held` is the rightful owner over a rival `claim` to the same name:
// the earlier registration wins (lower ts), ties broken by the lower origin. A
// total order over the fields carried in the account, so it survives compaction
// (which re-authors the log envelope but keeps account content) and is identical
// on every node. Strictly less-than, so an equal (idempotent) re-delivery still
// overwrites with identical content.
fn owns_over(held: &Account, claim: &Account) -> bool {
    (held.ts, held.home.as_str()) < (claim.ts, claim.home.as_str())
}

// Fold one event into the store. Shared by log replay (`open`) and gossip
// ingest, so both routes reconstruct identical state.
fn apply(accounts: &mut HashMap<String, Account>, channels: &mut HashMap<String, ChannelInfo>, grouped: &mut HashMap<String, String>, bots: &mut HashMap<String, Bot>, host_cfg: &mut HostConfig, net: &mut NetData, event: Event) {
    match event {
        Event::AccountRegistered(a) => {
            // Resolve a concurrent registration of the same name deterministically:
            // keep whichever claim is earlier (lower ts, then lower origin), so every
            // node converges on the same owner regardless of gossip delivery order.
            let k = key(&a.name);
            let keep_existing = accounts.get(&k).is_some_and(|cur| owns_over(cur, &a));
            if !keep_existing {
                accounts.insert(k, *a);
            }
        }
        Event::CertAdded { account, fp } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                if !a.certfps.contains(&fp) {
                    a.certfps.push(fp); // idempotent: safe to replay over a snapshot
                }
            }
        }
        Event::CertRemoved { account, fp } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.certfps.retain(|c| *c != fp);
            }
        }
        Event::AccountEmailSet { account, email } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.email = email;
            }
        }
        Event::AccountGreetSet { account, greet } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.greet = greet;
            }
        }
        Event::AccountPasswordSet { account, password_hash, scram256, scram512 } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.password_hash = password_hash;
                a.scram256 = Some(scram256);
                a.scram512 = Some(scram512);
            }
        }
        Event::AccountDropped { account } => {
            accounts.remove(&key(&account));
            grouped.retain(|_, a| !a.eq_ignore_ascii_case(&account)); // its aliases go too
        }
        Event::AccountVerified { account } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.verified = true;
            }
        }
        Event::AjoinAdded { account, channel, key: join_key } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                // Idempotent (safe to replay over a snapshot): last write wins per channel.
                a.ajoin.retain(|e| !e.channel.eq_ignore_ascii_case(&channel));
                a.ajoin.push(AjoinEntry { channel, key: join_key });
            }
        }
        Event::AjoinRemoved { account, channel } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.ajoin.retain(|e| !e.channel.eq_ignore_ascii_case(&channel));
            }
        }
        Event::VhostSet { account, host, setter, ts, expires } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.vhost = Some(Vhost { host, setter, ts, expires });
            }
        }
        Event::VhostDeleted { account } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.vhost = None;
            }
        }
        Event::VhostRequested { account, host, ts } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.vhost_request = Some(PendingVhost { host, ts });
            }
        }
        Event::VhostRequestCleared { account } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.vhost_request = None;
            }
        }
        Event::AccountSuspended { account, by, reason, ts, expires } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.suspension = Some(Suspension { by, reason, ts, expires });
            }
        }
        Event::AccountUnsuspended { account } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.suspension = None;
            }
        }
        Event::MemoSent { account, from, text, ts } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.memos.push(Memo { from, text, ts, read: false });
            }
        }
        Event::MemoRead { account, index } => {
            if let Some(m) = accounts.get_mut(&key(&account)).and_then(|a| a.memos.get_mut(index)) {
                m.read = true;
            }
        }
        Event::MemoDeleted { account, index } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                if index < a.memos.len() {
                    a.memos.remove(index);
                }
            }
        }
        Event::NickGrouped { nick, account } => {
            grouped.insert(key(&nick), account);
        }
        Event::NickUngrouped { nick } => {
            grouped.remove(&key(&nick));
        }
        Event::ChannelRegistered { name, founder, ts } => {
            channels.insert(key(&name), ChannelInfo { name, founder, ts, lock_on: String::new(), lock_off: String::new(), access: Vec::new(), akick: Vec::new(), desc: String::new(), entrymsg: String::new(), settings: ChanSettings::default(), topic: String::new(), suspension: None, assigned_bot: None , kickers: KickerSettings::default() , badwords: Vec::new(), badwords_rev: 0 , triggers: Vec::new(), triggers_rev: 0, last_used: ts, noexpire: false, expiry_warned: false, oper_note: None });
        }
        Event::ChannelDropped { name } => {
            channels.remove(&key(&name));
        }
        Event::ChannelMlock { name, on, off } => {
            if let Some(c) = channels.get_mut(&key(&name)) {
                c.lock_on = on;
                c.lock_off = off;
            }
        }
        Event::ChannelAccessAdd { channel, account, level } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.access.retain(|a| !a.account.eq_ignore_ascii_case(&account));
                c.access.push(ChanAccess { account, level });
            }
        }
        Event::ChannelAccessDel { channel, account } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.access.retain(|a| !a.account.eq_ignore_ascii_case(&account));
            }
        }
        Event::ChannelAkickAdd { channel, mask, reason } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.akick.retain(|k| !k.mask.eq_ignore_ascii_case(&mask));
                c.akick.push(ChanAkick { mask, reason });
            }
        }
        Event::ChannelAkickDel { channel, mask } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.akick.retain(|k| !k.mask.eq_ignore_ascii_case(&mask));
            }
        }
        Event::ChannelFounderSet { channel, founder } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.founder = founder;
            }
        }
        Event::ChannelDescSet { channel, desc } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.desc = desc;
            }
        }
        Event::ChannelSettingsSet { channel, settings } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.settings = settings;
            }
        }
        Event::ChannelKickerSet { channel, kickers } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.kickers = kickers;
            }
        }
        Event::ChannelBadwordsSet { channel, badwords } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.badwords = badwords;
                c.badwords_rev = c.badwords_rev.wrapping_add(1);
            }
        }
        Event::ChannelTriggersSet { channel, triggers } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.triggers = triggers;
                c.triggers_rev = c.triggers_rev.wrapping_add(1);
            }
        }
        Event::ChannelTopicSet { channel, topic } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.topic = topic;
            }
        }
        Event::ChannelSuspended { channel, by, reason, ts, expires } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.suspension = Some(Suspension { by, reason, ts, expires });
            }
        }
        Event::ChannelUnsuspended { channel } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.suspension = None;
            }
        }
        Event::ChannelBotAssigned { channel, bot } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.assigned_bot = Some(bot);
            }
        }
        Event::ChannelBotUnassigned { channel } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.assigned_bot = None;
            }
        }
        Event::BotAdded(b) => {
            bots.insert(key(&b.nick), b);
        }
        Event::BotRemoved { nick } => {
            bots.remove(&key(&nick));
        }
        Event::VhostOfferAdded { host } => {
            if !host_cfg.offers.iter().any(|o| o == &host) {
                host_cfg.offers.push(host);
            }
        }
        Event::VhostOfferRemoved { host } => {
            host_cfg.offers.retain(|o| o != &host);
        }
        Event::VhostForbidAdded { pattern } => {
            if !host_cfg.forbidden.iter().any(|p| p == &pattern) {
                host_cfg.forbidden.push(pattern);
            }
        }
        Event::VhostForbidRemoved { pattern } => {
            host_cfg.forbidden.retain(|p| p != &pattern);
        }
        Event::VhostTemplateSet { template } => {
            host_cfg.template = template;
        }
        Event::ChannelEntryMsgSet { channel, msg } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.entrymsg = msg;
            }
        }
        Event::AccountSeen { account, ts } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.last_seen = a.last_seen.max(ts); // monotonic: never move activity backwards
                a.expiry_warned = false; // activity clears the warning so a later idle spell warns afresh
            }
        }
        Event::ChannelUsed { channel, ts } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.last_used = c.last_used.max(ts);
                c.expiry_warned = false;
            }
        }
        Event::AccountNoExpire { account, on } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.noexpire = on;
            }
        }
        Event::ChannelNoExpire { channel, on } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.noexpire = on;
            }
        }
        Event::AkillAdded { kind, mask, setter, reason, ts, expires } => {
            // Keyed by (kind, mask), case-insensitive: a re-add refreshes in
            // place, so replaying over a snapshot stays idempotent.
            net.akills.retain(|a| !(a.kind == kind && a.mask.eq_ignore_ascii_case(&mask)));
            net.akills.push(Akill { kind, mask, setter, reason, ts, expires });
        }
        Event::AkillRemoved { kind, mask } => {
            net.akills.retain(|a| !(a.kind == kind && a.mask.eq_ignore_ascii_case(&mask)));
        }
        Event::AccountExpiryWarned { account } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.expiry_warned = true;
            }
        }
        Event::ChannelExpiryWarned { channel } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.expiry_warned = true;
            }
        }
        Event::AccountOperNoteSet { account, note } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.oper_note = note;
            }
        }
        Event::ChannelOperNoteSet { channel, note } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.oper_note = note;
            }
        }
        Event::NewsAdded { id, kind, text, setter, ts } => {
            net.news_seq = net.news_seq.max(id + 1);
            if !net.news.iter().any(|n| n.id == id) {
                net.news.push(News { id, kind, text, setter, ts });
            }
        }
        Event::NewsDeleted { id } => {
            net.news.retain(|n| n.id != id);
        }
        Event::ReportFiled { id, reporter, target, reason, ts } => {
            net.report_seq = net.report_seq.max(id + 1);
            if !net.reports.iter().any(|r| r.id == id) {
                net.reports.push(Report { id, reporter, target, reason, ts, open: true });
            }
        }
        Event::ReportClosed { id } => {
            if let Some(r) = net.reports.iter_mut().find(|r| r.id == id) {
                r.open = false;
            }
        }
        Event::ReportDeleted { id } => {
            net.reports.retain(|r| r.id != id);
        }
        Event::GroupRegistered { name, founder, ts } => {
            let k = key(&name);
            if !net.groups.iter().any(|g| key(&g.name) == k) {
                net.groups.push(Group { name, founder, ts, members: Vec::new() });
            }
        }
        Event::GroupDropped { name } => {
            let k = key(&name);
            net.groups.retain(|g| key(&g.name) != k);
        }
        Event::GroupFounderSet { name, founder } => {
            let k = key(&name);
            if let Some(g) = net.groups.iter_mut().find(|g| key(&g.name) == k) {
                g.founder = founder;
            }
        }
        Event::GroupFlagsSet { name, account, flags } => {
            let k = key(&name);
            if let Some(g) = net.groups.iter_mut().find(|g| key(&g.name) == k) {
                g.members.retain(|m| !m.account.eq_ignore_ascii_case(&account));
                g.members.push(GroupMember { account, flags });
            }
        }
        Event::GroupMemberDel { name, account } => {
            let k = key(&name);
            if let Some(g) = net.groups.iter_mut().find(|g| key(&g.name) == k) {
                g.members.retain(|m| !m.account.eq_ignore_ascii_case(&account));
            }
        }
        Event::OperGranted { account, privs, expires } => {
            net.opers.insert(key(&account), OperGrant { privs, expires });
        }
        Event::OperRevoked { account } => {
            net.opers.remove(&key(&account));
        }
        Event::SessionExceptionAdded { mask, limit, reason } => {
            net.sess_exceptions.retain(|e| !e.mask.eq_ignore_ascii_case(&mask));
            net.sess_exceptions.push(SessionException { mask, limit, reason });
        }
        Event::SessionExceptionRemoved { mask } => {
            net.sess_exceptions.retain(|e| !e.mask.eq_ignore_ascii_case(&mask));
        }
    }
}

// Case-insensitive glob match supporting `*` (any run) and `?` (one char),
// used for auto-kick hostmasks. Iterative with backtracking, no allocation.
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

fn hash_password(password: &str) -> Option<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).ok().map(|h| h.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

// The module-facing account/channel store. Every method forwards to Db's own
// (fully-qualified so it is the inherent method, never this trait method), with
// reads projected into credential-free views. Internal callers keep using the
// richer inherent methods directly.
impl Store for Db {
    fn exists(&self, name: &str) -> bool {
        Db::exists(self, name)
    }
    fn account(&self, name: &str) -> Option<AccountView> {
        Db::account(self, name).map(|a| AccountView {
            name: a.name.clone(),
            email: a.email.clone(),
            ts: a.ts,
            verified: a.verified,
            greet: a.greet.clone(),
        })
    }
    fn resolve_account(&self, name: &str) -> Option<&str> {
        Db::resolve_account(self, name)
    }
    fn authenticate(&self, name: &str, password: &str) -> Option<&str> {
        Db::authenticate(self, name, password)
    }
    fn grouped_nicks(&self, account: &str) -> Vec<String> {
        Db::grouped_nicks(self, account)
    }
    fn certfps(&self, account: &str) -> &[String] {
        Db::certfps(self, account)
    }
    fn is_verified(&self, account: &str) -> bool {
        Db::is_verified(self, account)
    }
    fn channel(&self, name: &str) -> Option<ChannelView> {
        Db::channel(self, name).map(channel_view)
    }
    fn channels(&self) -> Vec<ChannelView> {
        Db::channels(self).map(channel_view).collect()
    }
    fn channels_owned_by(&self, account: &str) -> Vec<String> {
        Db::channels_owned_by(self, account)
    }
    fn email_enabled(&self) -> bool {
        Db::email_enabled(self)
    }
    fn email_brand(&self) -> &str {
        Db::email_brand(self)
    }
    fn email_accent(&self) -> &str {
        Db::email_accent(self)
    }
    fn email_logo(&self) -> &str {
        Db::email_logo(self)
    }
    fn issue_code(&mut self, account: &str, kind: CodeKind) -> String {
        Db::issue_code(self, account, kind)
    }
    fn take_code(&mut self, account: &str, kind: CodeKind, code: &str) -> bool {
        Db::take_code(self, account, kind, code)
    }
    fn auth_lockout(&self, account: &str) -> Option<u64> {
        Db::auth_lockout(self, account)
    }
    fn note_auth(&mut self, account: &str, success: bool) {
        Db::note_auth(self, account, success)
    }
    fn verify_account(&mut self, account: &str) -> Result<(), RegError> {
        Db::verify_account(self, account)
    }
    fn set_email(&mut self, account: &str, email: Option<String>) -> Result<(), RegError> {
        Db::set_email(self, account, email)
    }
    fn set_greet(&mut self, account: &str, greet: &str) -> Result<(), RegError> {
        Db::set_greet(self, account, greet)
    }
    fn set_vhost(&mut self, account: &str, host: &str, setter: &str, ttl: Option<u64>) -> Result<(), RegError> {
        Db::set_vhost(self, account, host, setter, ttl)
    }
    fn del_vhost(&mut self, account: &str) -> Result<bool, RegError> {
        Db::del_vhost(self, account)
    }
    fn vhost(&self, account: &str) -> Option<VhostView> {
        Db::account(self, account).and_then(|a| {
            a.vhost.as_ref().filter(|v| v.expires.is_none_or(|e| e > now())).map(|v| VhostView { account: a.name.clone(), host: v.host.clone(), setter: v.setter.clone(), expires: v.expires })
        })
    }
    fn vhosts(&self) -> Vec<VhostView> {
        Db::vhosts(self).into_iter().map(|(account, host, setter, expires)| VhostView { account, host, setter, expires }).collect()
    }
    fn vhost_owner(&self, host: &str) -> Option<String> {
        Db::vhost_owner(self, host)
    }
    fn request_vhost(&mut self, account: &str, host: &str) -> Result<(), RegError> {
        Db::request_vhost(self, account, host)
    }
    fn vhost_request_wait(&self, account: &str) -> u64 {
        Db::vhost_request_wait(self, account)
    }
    fn take_vhost_request(&mut self, account: &str) -> Result<Option<String>, RegError> {
        Db::take_vhost_request(self, account)
    }
    fn vhost_requests(&self) -> Vec<(String, String)> {
        Db::vhost_requests(self)
    }
    fn vhost_offer_add(&mut self, host: &str) -> Result<bool, RegError> {
        Db::vhost_offer_add(self, host)
    }
    fn vhost_offer_del(&mut self, index: usize) -> Result<Option<String>, RegError> {
        Db::vhost_offer_del(self, index)
    }
    fn vhost_offers(&self) -> Vec<String> {
        Db::vhost_offers(self).to_vec()
    }
    fn vhost_forbid_add(&mut self, pattern: &str) -> Result<bool, RegError> {
        Db::vhost_forbid_add(self, pattern)
    }
    fn vhost_forbid_del(&mut self, index: usize) -> Result<Option<String>, RegError> {
        Db::vhost_forbid_del(self, index)
    }
    fn vhost_forbidden(&self) -> Vec<String> {
        Db::vhost_forbidden(self).to_vec()
    }
    fn vhost_is_forbidden(&self, host: &str) -> bool {
        Db::vhost_is_forbidden(self, host)
    }
    fn set_vhost_template(&mut self, template: Option<String>) -> Result<(), RegError> {
        Db::set_vhost_template(self, template)
    }
    fn vhost_template(&self) -> Option<String> {
        Db::vhost_template(self).map(str::to_string)
    }
    fn group_nick(&mut self, nick: &str, account: &str) -> Result<(), RegError> {
        Db::group_nick(self, nick, account)
    }
    fn ungroup_nick(&mut self, nick: &str) -> Result<bool, RegError> {
        Db::ungroup_nick(self, nick)
    }
    fn drop_account(&mut self, account: &str) -> Result<bool, RegError> {
        Db::drop_account(self, account)
    }
    fn certfp_add(&mut self, account: &str, fp: &str) -> Result<(), CertError> {
        Db::certfp_add(self, account, fp)
    }
    fn certfp_del(&mut self, account: &str, fp: &str) -> Result<bool, CertError> {
        Db::certfp_del(self, account, fp)
    }
    fn ajoin_list(&self, account: &str) -> Vec<AjoinView> {
        Db::ajoin_list(self, account)
            .iter()
            .map(|e| AjoinView { channel: e.channel.clone(), key: e.key.clone() })
            .collect()
    }
    fn ajoin_add(&mut self, account: &str, channel: &str, key: &str) -> Result<bool, RegError> {
        Db::ajoin_add(self, account, channel, key)
    }
    fn ajoin_del(&mut self, account: &str, channel: &str) -> Result<bool, RegError> {
        Db::ajoin_del(self, account, channel)
    }
    fn suspend_account(&mut self, account: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), RegError> {
        Db::suspend_account(self, account, by, reason, expires)
    }
    fn unsuspend_account(&mut self, account: &str) -> Result<bool, RegError> {
        Db::unsuspend_account(self, account)
    }
    fn is_suspended(&self, account: &str) -> bool {
        Db::is_suspended(self, account)
    }
    fn suspension(&self, account: &str) -> Option<SuspensionView> {
        Db::suspension(self, account)
    }
    fn set_account_noexpire(&mut self, account: &str, on: bool) -> Result<bool, RegError> {
        Db::set_account_noexpire(self, account, on)
    }
    fn set_channel_noexpire(&mut self, channel: &str, on: bool) -> Result<bool, ChanError> {
        Db::set_channel_noexpire(self, channel, on)
    }
    fn akill_add(&mut self, kind: &str, mask: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError> {
        Db::akill_add(self, kind, mask, setter, reason, expires)
    }
    fn akill_del(&mut self, kind: &str, mask: &str) -> Result<bool, RegError> {
        Db::akill_del(self, kind, mask)
    }
    fn akills(&self) -> Vec<AkillView> {
        Db::akills(self)
    }
    fn ignore_add(&mut self, mask: &str, reason: &str, expires: Option<u64>) {
        Db::ignore_add(self, mask, reason, expires)
    }
    fn ignore_del(&mut self, mask: &str) -> bool {
        Db::ignore_del(self, mask)
    }
    fn ignores(&self) -> Vec<IgnoreView> {
        Db::ignores(self)
    }
    fn jupe_add(&mut self, name: &str, reason: &str) -> String {
        Db::jupe_add(self, name, reason)
    }
    fn jupe_del(&mut self, name: &str) -> Option<String> {
        Db::jupe_del(self, name)
    }
    fn jupes(&self) -> Vec<(String, String, String)> {
        Db::jupes(self)
    }
    fn defcon(&self) -> u8 {
        Db::defcon(self)
    }
    fn set_defcon(&mut self, level: u8) {
        Db::set_defcon(self, level)
    }
    fn registrations_frozen(&self) -> bool {
        Db::registrations_frozen(self)
    }
    fn channel_regs_frozen(&self) -> bool {
        Db::channel_regs_frozen(self)
    }
    fn external_accounts(&self) -> bool {
        Db::external_accounts(self)
    }
    fn set_account_note(&mut self, account: &str, note: Option<String>) -> bool {
        Db::set_account_note(self, account, note)
    }
    fn account_note(&self, account: &str) -> Option<String> {
        Db::account_note(self, account)
    }
    fn set_channel_note(&mut self, channel: &str, note: Option<String>) -> bool {
        Db::set_channel_note(self, channel, note)
    }
    fn channel_note(&self, channel: &str) -> Option<String> {
        Db::channel_note(self, channel)
    }
    fn news_add(&mut self, kind: &str, text: &str, setter: &str) -> u64 {
        Db::news_add(self, kind, text, setter)
    }
    fn news_del(&mut self, id: u64) -> bool {
        Db::news_del(self, id)
    }
    fn news(&self, kind: &str) -> Vec<NewsView> {
        Db::news(self, kind)
    }
    fn report_file(&mut self, reporter: &str, target: &str, reason: &str) -> Option<u64> {
        Db::report_file(self, reporter, target, reason)
    }
    fn report_close(&mut self, id: u64) -> bool {
        Db::report_close(self, id)
    }
    fn report_del(&mut self, id: u64) -> bool {
        Db::report_del(self, id)
    }
    fn reports(&self, open_only: bool) -> Vec<ReportView> {
        Db::reports(self, open_only)
    }
    fn report(&self, id: u64) -> Option<ReportView> {
        Db::report(self, id)
    }
    fn group_register(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        Db::group_register(self, name, founder)
    }
    fn group_drop(&mut self, name: &str) -> Result<(), ChanError> {
        Db::group_drop(self, name)
    }
    fn group_set_flags(&mut self, name: &str, account: &str, flags: &str) -> Result<(), ChanError> {
        Db::group_set_flags(self, name, account, flags)
    }
    fn group_del_member(&mut self, name: &str, account: &str) -> Result<bool, ChanError> {
        Db::group_del_member(self, name, account)
    }
    fn group_set_founder(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        Db::group_set_founder(self, name, founder)
    }
    fn group(&self, name: &str) -> Option<GroupView> {
        Db::group(self, name)
    }
    fn groups(&self) -> Vec<String> {
        Db::groups(self)
    }
    fn groups_of(&self, account: &str) -> Vec<String> {
        Db::groups_of(self, account)
    }
    fn channel_caps(&self, channel: &str, account: &str) -> Caps {
        Db::channel_caps(self, channel, account)
    }
    fn oper_grant(&mut self, account: &str, privs: Vec<String>, expires: Option<u64>) {
        Db::oper_grant(self, account, privs, expires)
    }
    fn oper_revoke(&mut self, account: &str) -> bool {
        Db::oper_revoke(self, account)
    }
    fn opers_list(&self) -> Vec<(String, Vec<String>, Option<u64>)> {
        Db::opers_list(self)
    }
    fn session_except_add(&mut self, mask: &str, limit: u32, reason: &str) {
        Db::session_except_add(self, mask, limit, reason)
    }
    fn session_except_del(&mut self, mask: &str) -> bool {
        Db::session_except_del(self, mask)
    }
    fn session_exceptions(&self) -> Vec<(String, u32, String)> {
        Db::session_exceptions(self)
    }
    fn register_channel(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        Db::register_channel(self, name, founder)
    }
    fn drop_channel(&mut self, name: &str) -> Result<(), ChanError> {
        Db::drop_channel(self, name)
    }
    fn set_mlock(&mut self, name: &str, on: &str, off: &str) -> Result<(), ChanError> {
        Db::set_mlock(self, name, on, off)
    }
    fn set_desc(&mut self, channel: &str, desc: &str) -> Result<(), ChanError> {
        Db::set_desc(self, channel, desc)
    }
    fn set_channel_setting(&mut self, channel: &str, setting: ChanSetting, on: bool) -> Result<(), ChanError> {
        Db::set_channel_setting(self, channel, setting, on)
    }
    fn set_kicker(&mut self, channel: &str, kicker: Kicker, on: bool) -> Result<(), ChanError> {
        Db::set_kicker(self, channel, kicker, on)
    }
    fn set_caps_kicker(&mut self, channel: &str, caps_min: u16, caps_percent: u16) -> Result<(), ChanError> {
        Db::set_caps_kicker(self, channel, caps_min, caps_percent)
    }
    fn set_flood_kicker(&mut self, channel: &str, lines: u16, secs: u16) -> Result<(), ChanError> {
        Db::set_flood_kicker(self, channel, lines, secs)
    }
    fn set_repeat_kicker(&mut self, channel: &str, times: u16) -> Result<(), ChanError> {
        Db::set_repeat_kicker(self, channel, times)
    }
    fn set_ttb(&mut self, channel: &str, ttb: u16) -> Result<(), ChanError> {
        Db::set_ttb(self, channel, ttb)
    }
    fn set_ban_expire(&mut self, channel: &str, secs: u32) -> Result<(), ChanError> {
        Db::set_ban_expire(self, channel, secs)
    }
    fn set_votekick(&mut self, channel: &str, votes: u16) -> Result<(), ChanError> {
        Db::set_votekick(self, channel, votes)
    }
    fn badword_add(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError> {
        Db::badword_add(self, channel, pattern)
    }
    fn badword_del(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError> {
        Db::badword_del(self, channel, pattern)
    }
    fn badword_clear(&mut self, channel: &str) -> Result<usize, ChanError> {
        Db::badword_clear(self, channel)
    }
    fn badwords(&self, channel: &str) -> Vec<String> {
        Db::badwords(self, channel).to_vec()
    }
    fn kicker_test(&self, channel: &str, text: &str) -> Option<String> {
        Db::kicker_test(self, channel, text)
    }
    fn copy_bot_config(&mut self, src: &str, dst: &str) -> Result<(), ChanError> {
        Db::copy_bot_config(self, src, dst)
    }
    fn trigger_add(&mut self, channel: &str, pattern: &str, response: &str, cooldown: u32) -> Result<bool, ChanError> {
        Db::trigger_add(self, channel, pattern, response, cooldown)
    }
    fn trigger_del(&mut self, channel: &str, index: usize) -> Result<bool, ChanError> {
        Db::trigger_del(self, channel, index)
    }
    fn trigger_clear(&mut self, channel: &str) -> Result<usize, ChanError> {
        Db::trigger_clear(self, channel)
    }
    fn triggers(&self, channel: &str) -> Vec<TriggerView> {
        Db::triggers(self, channel).iter().map(|t| TriggerView { pattern: t.pattern.clone(), response: t.response.clone(), cooldown: t.cooldown }).collect()
    }
    fn set_channel_topic(&mut self, channel: &str, topic: &str) -> Result<(), ChanError> {
        Db::set_channel_topic(self, channel, topic)
    }
    fn suspend_channel(&mut self, channel: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), ChanError> {
        Db::suspend_channel(self, channel, by, reason, expires)
    }
    fn unsuspend_channel(&mut self, channel: &str) -> Result<bool, ChanError> {
        Db::unsuspend_channel(self, channel)
    }
    fn is_channel_suspended(&self, channel: &str) -> bool {
        Db::is_channel_suspended(self, channel)
    }
    fn channel_suspension(&self, channel: &str) -> Option<SuspensionView> {
        Db::channel_suspension(self, channel)
    }
    fn bot_add(&mut self, nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError> {
        Db::bot_add(self, nick, user, host, gecos)
    }
    fn bot_change(&mut self, old: &str, new_nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError> {
        Db::bot_change(self, old, new_nick, user, host, gecos)
    }
    fn bot_set_private(&mut self, nick: &str, private: bool) -> Result<bool, ChanError> {
        Db::bot_set_private(self, nick, private)
    }
    fn bot_del(&mut self, nick: &str) -> Result<bool, ChanError> {
        Db::bot_del(self, nick)
    }
    fn bot_del_all(&mut self) -> Result<usize, ChanError> {
        Db::bot_del_all(self)
    }
    fn bots(&self) -> Vec<BotView> {
        Db::bots(self).map(|b| BotView { nick: b.nick.clone(), user: b.user.clone(), host: b.host.clone(), gecos: b.gecos.clone(), private: b.private }).collect()
    }
    fn assign_bot(&mut self, channel: &str, bot: &str) -> Result<(), ChanError> {
        Db::assign_bot(self, channel, bot)
    }
    fn unassign_bot(&mut self, channel: &str) -> Result<bool, ChanError> {
        Db::unassign_bot(self, channel)
    }
    fn memo_send(&mut self, account: &str, from: &str, text: &str) -> Result<(), RegError> {
        Db::memo_send(self, account, from, text)
    }
    fn memo_list(&self, account: &str) -> Vec<MemoView> {
        Db::memo_list(self, account)
    }
    fn memo_read(&mut self, account: &str, index: usize) -> Option<MemoView> {
        Db::memo_read(self, account, index)
    }
    fn memo_del(&mut self, account: &str, index: usize) -> bool {
        Db::memo_del(self, account, index)
    }
    fn unread_memos(&self, account: &str) -> usize {
        Db::unread_memos(self, account)
    }
    fn set_entrymsg(&mut self, channel: &str, msg: &str) -> Result<(), ChanError> {
        Db::set_entrymsg(self, channel, msg)
    }
    fn set_founder(&mut self, channel: &str, account: &str) -> Result<(), ChanError> {
        Db::set_founder(self, channel, account)
    }
    fn access_add(&mut self, channel: &str, account: &str, level: &str) -> Result<(), ChanError> {
        Db::access_add(self, channel, account, level)
    }
    fn access_del(&mut self, channel: &str, account: &str) -> Result<bool, ChanError> {
        Db::access_del(self, channel, account)
    }
    fn akick_add(&mut self, channel: &str, mask: &str, reason: &str) -> Result<(), ChanError> {
        Db::akick_add(self, channel, mask, reason)
    }
    fn akick_del(&mut self, channel: &str, mask: &str) -> Result<bool, ChanError> {
        Db::akick_del(self, channel, mask)
    }
}

fn channel_view(c: &ChannelInfo) -> ChannelView {
    ChannelView {
        name: c.name.clone(),
        founder: c.founder.clone(),
        ts: c.ts,
        lock_on: c.lock_on.clone(),
        lock_off: c.lock_off.clone(),
        access: c.access.iter().map(|a| ChanAccessView { account: a.account.clone(), level: a.level.clone() }).collect(),
        akick: c.akick.iter().map(|k| ChanAkickView { mask: k.mask.clone(), reason: k.reason.clone() }).collect(),
        desc: c.desc.clone(),
        entrymsg: c.entrymsg.clone(),
        signkick: c.settings.signkick,
        private: c.settings.private,
        peace: c.settings.peace,
        secureops: c.settings.secureops,
        keeptopic: c.settings.keeptopic,
        topiclock: c.settings.topiclock,
        topic: c.topic.clone(),
        suspended: c.suspension.as_ref().is_some_and(|s| s.expires.is_none_or(|e| e > now())),
        assigned_bot: c.assigned_bot.clone(),
        bot_greet: c.settings.bot_greet,
        nobot: c.settings.nobot,
        kickers_active: c.kickers.any(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fedserv-log-{name}.jsonl"));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn cert(account: &str, fp: &str) -> Event {
        Event::CertAdded { account: account.into(), fp: fp.into() }
    }

    #[test]
    fn formats_unix_time_as_utc() {
        assert_eq!(fedserv_api::human_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fedserv_api::human_time(1783844590), "2026-07-12 08:23:10 UTC");
    }

    #[test]
    fn glob_matches_hostmasks() {
        assert!(glob_match("*!*@host.example", "bob!~b@host.example"));
        assert!(glob_match("bob!*@*", "BOB!~b@1.2.3.4"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("nick?!*@*", "nickX!~x@h"));
        assert!(!glob_match("*!*@host.example", "bob!~b@other"));
        assert!(!glob_match("alice!*@*", "bob!~b@h"));
    }

    #[test]
    fn account_conflict_resolves_deterministically() {
        let alice = |hash: &str, ts: u64, home: &str| Account {
            name: "alice".into(), password_hash: hash.into(), email: None,
            ts, home: home.into(), scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![], suspension: None, memos: vec![], greet: String::new(), vhost: None, vhost_request: None, last_seen: ts, noexpire: false, expiry_warned: false, oper_note: None,
        };
        let converge = |first: &Account, second: &Account| {
            let (mut acc, mut ch, mut gr, mut bo, mut hc, mut nd) = (HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new(), HostConfig::default(), NetData::default());
            apply(&mut acc, &mut ch, &mut gr, &mut bo, &mut hc, &mut nd, Event::AccountRegistered(Box::new(first.clone())));
            apply(&mut acc, &mut ch, &mut gr, &mut bo, &mut hc, &mut nd, Event::AccountRegistered(Box::new(second.clone())));
            acc["alice"].password_hash.clone()
        };
        // Earlier registration wins, regardless of which claim applies first.
        let early = alice("EARLY", 100, "nodeB");
        let late = alice("LATE", 200, "nodeA");
        assert_eq!(converge(&early, &late), "EARLY");
        assert_eq!(converge(&late, &early), "EARLY", "commutative: same winner in either order");
        // Same ts: the lower origin wins, in either order.
        let a = alice("A", 100, "nodeA");
        let b = alice("B", 100, "nodeB");
        assert_eq!(converge(&a, &b), "A");
        assert_eq!(converge(&b, &a), "A", "ts tie broken by lower origin, either order");
        // Idempotent: re-delivering the winner keeps it.
        assert_eq!(converge(&a, &a), "A");
    }

    #[test]
    fn channel_state_is_node_local_but_persists() {
        let path = tmp("scope");
        {
            let mut db = Db::open(&path, "N1");
            db.register("alice", "pw", None).unwrap(); // global
            db.register_channel("#c", "alice").unwrap(); // local
            db.set_mlock("#c", "nt", "").unwrap(); // local
            // Only the account advances the version vector.
            assert_eq!(db.version_vector().get("N1"), Some(&0), "channels don't advance the vector");
            // A fresh peer is offered the account, never the channel.
            let missing = db.missing_for(&HashMap::new());
            assert_eq!(missing.len(), 1, "only the global account entry is offered: {missing:?}");
            assert!(matches!(missing[0].event, Event::AccountRegistered(_)));
        }
        // Reopen: node-local channel state replays from disk unchanged.
        let db = Db::open(&path, "N1");
        assert!(db.exists("alice"));
        assert_eq!(db.channel("#c").map(|c| c.lock_on.clone()), Some("nt".to_string()), "channel state persists locally");
        assert_eq!(db.version_vector().get("N1"), Some(&0), "vector unchanged after replay");
    }

    #[test]
    fn akick_add_del_and_match() {
        let mut db = Db::open(&tmp("akick"), "N1");
        db.register_channel("#c", "founder").unwrap();
        db.akick_add("#c", "*!*@bad.host", "spam").unwrap();
        let info = db.channel("#c").unwrap();
        assert!(info.akick_match("evil!~e@bad.host").is_some());
        assert!(info.akick_match("good!~g@ok.host").is_none());
        assert!(db.akick_del("#c", "*!*@bad.host").unwrap());
        assert!(!db.akick_del("#c", "*!*@bad.host").unwrap());
        assert!(db.channel("#c").unwrap().akick.is_empty());
    }

    // The auto-join list adds, updates a key in place, removes case-insensitively,
    // and replays from the event log after a reopen.
    #[test]
    fn ajoin_add_del_and_persist() {
        let p = tmp("ajoin");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "pw", None).unwrap();
            assert!(db.ajoin_add("alice", "#chat", "").unwrap(), "newly added");
            assert!(!db.ajoin_add("alice", "#chat", "sekret").unwrap(), "re-add updates the key, not newly added");
            db.ajoin_add("alice", "#dev", "").unwrap();
            assert_eq!(db.ajoin_list("alice").len(), 2);
            assert_eq!(db.ajoin_list("alice")[0].key, "sekret", "key updated in place");
            assert!(db.ajoin_del("alice", "#CHAT").unwrap(), "case-insensitive remove");
            assert!(!db.ajoin_del("alice", "#chat").unwrap(), "already gone");
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.ajoin_list("alice").len(), 1, "list replays from the log");
        assert_eq!(db.ajoin_list("alice")[0].channel, "#dev");
    }

    // Channel SET options default off, toggle, and replay from the log.
    #[test]
    fn channel_settings_toggle_and_persist() {
        let p = tmp("chansettings");
        {
            let mut db = Db::open(&p, "N1");
            db.register_channel("#c", "boss").unwrap();
            assert!(!db.channel("#c").unwrap().settings.signkick, "defaults off");
            db.set_channel_setting("#c", ChanSetting::SignKick, true).unwrap();
            db.set_channel_setting("#c", ChanSetting::Private, true).unwrap();
            db.set_channel_setting("#c", ChanSetting::Private, false).unwrap();
            let s = db.channel("#c").unwrap().settings;
            assert!(s.signkick && !s.private, "one flag on, the other flipped back off");
        }
        let s = Db::open(&p, "N1").channel("#c").unwrap().settings;
        assert!(s.signkick && !s.private, "settings replay from the log");
    }

    // Access ranks order founder > op > voice > none for PEACE comparisons.
    #[test]
    fn access_rank_orders_founder_op_voice() {
        let mut db = Db::open(&tmp("rank"), "N1");
        db.register_channel("#c", "boss").unwrap();
        db.access_add("#c", "op1", "op").unwrap();
        db.access_add("#c", "v1", "voice").unwrap();
        let cv = Store::channel(&db, "#c").unwrap();
        assert_eq!(cv.access_rank(Some("boss")), 3);
        assert_eq!(cv.access_rank(Some("OP1")), 2, "case-insensitive");
        assert_eq!(cv.access_rank(Some("v1")), 1);
        assert_eq!(cv.access_rank(Some("nobody")), 0);
        assert_eq!(cv.access_rank(None), 0);
    }

    // Suspension sets/lifts, expires lazily, and replays from the log.
    #[test]
    fn suspend_lifts_expires_and_persists() {
        let p = tmp("suspend");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "password1", None).unwrap();
            assert!(!db.is_suspended("alice"));
            db.suspend_account("alice", "oper", "spamming", None).unwrap();
            assert!(db.is_suspended("alice"));
            assert_eq!(db.suspension("alice").unwrap().reason, "spamming");
            assert!(db.unsuspend_account("alice").unwrap());
            assert!(!db.is_suspended("alice"));
            assert!(!db.unsuspend_account("alice").unwrap(), "already lifted");
            // A past expiry is not active, but the record still shows in INFO.
            db.suspend_account("alice", "oper", "temp", Some(1)).unwrap();
            assert!(!db.is_suspended("alice"), "expired suspension is inactive");
            assert!(db.suspension("alice").is_some());
        }
        {
            let mut db = Db::open(&p, "N1");
            db.suspend_account("alice", "oper", "again", None).unwrap();
        }
        assert!(Db::open(&p, "N1").is_suspended("alice"), "suspension replays from the log");
    }

    // A channel suspension lifts, expires lazily, and survives compaction + reopen.
    #[test]
    fn channel_suspend_lifts_persists_and_compacts() {
        let p = tmp("chansuspend");
        let mut db = Db::open(&p, "N1");
        db.register_channel("#c", "boss").unwrap();
        db.suspend_channel("#c", "oper", "raided", Some(1)).unwrap();
        assert!(!db.is_channel_suspended("#c"), "a past expiry is inactive");
        db.suspend_channel("#c", "oper", "raided", None).unwrap();
        assert!(db.is_channel_suspended("#c"));
        db.compact().unwrap(); // the snapshot must retain the suspension
        drop(db);
        let db = Db::open(&p, "N1");
        assert!(db.is_channel_suspended("#c"), "survives compaction + reopen");
        assert_eq!(db.channel_suspension("#c").unwrap().by, "oper");
    }

    // The bot registry adds (case-insensitively unique), deletes, and replays.
    #[test]
    fn bots_add_del_and_persist() {
        let p = tmp("bots");
        {
            let mut db = Db::open(&p, "N1");
            assert_eq!(db.bots().count(), 0);
            db.bot_add("Bendy", "bot", "services.host", "A helper").unwrap();
            assert!(matches!(db.bot_add("bendy", "x", "y", "z"), Err(ChanError::Exists)), "dup is case-insensitive");
            assert_eq!(db.bots().count(), 1);
            assert!(db.bot_del("BENDY").unwrap(), "case-insensitive delete");
            assert!(!db.bot_del("bendy").unwrap(), "already gone");
        }
        {
            let mut db = Db::open(&p, "N1");
            db.bot_add("Botty", "b", "h", "g").unwrap();
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.bots().count(), 1, "bots replay from the log");
        assert_eq!(db.bots().next().unwrap().nick, "Botty");
    }

    // Memos send, mark read on read, delete (shifting indices), and replay.
    #[test]
    fn memos_send_read_delete_and_persist() {
        let p = tmp("memos");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "password1", None).unwrap();
            assert_eq!(db.unread_memos("alice"), 0);
            db.memo_send("alice", "bob", "hello there").unwrap();
            db.memo_send("alice", "carol", "second").unwrap();
            assert_eq!(db.unread_memos("alice"), 2);
            let m = db.memo_read("alice", 0).unwrap();
            assert_eq!(m.from, "bob");
            assert_eq!(db.unread_memos("alice"), 1, "reading marks it read");
            assert!(db.memo_del("alice", 0));
            assert_eq!(db.memo_list("alice").len(), 1);
            assert_eq!(db.memo_list("alice")[0].text, "second", "delete shifts indices");
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.memo_list("alice").len(), 1, "memos replay from the log");
        assert_eq!(db.unread_memos("alice"), 1);
    }

    // A wrong code is tolerated a few times, then the code is burned so it can't
    // be ground down online even though it is short.
    #[test]
    fn code_burns_after_too_many_wrong_guesses() {
        let mut db = Db::open(&tmp("code"), "N1");
        db.scram_iterations = 4096;
        db.register("alice", "password", None).unwrap();
        let code = db.issue_code("alice", CodeKind::Reset);
        for _ in 0..CODE_TRIES {
            assert!(!db.take_code("alice", CodeKind::Reset, "WRONG000"), "wrong guess fails");
        }
        assert!(!db.take_code("alice", CodeKind::Reset, &code), "the real code is now burned too");
    }

    // Password auth backs off after a few failures and the throttle clears on success.
    #[test]
    fn auth_throttle_locks_then_clears() {
        let mut db = Db::open(&tmp("throttle"), "N1");
        for _ in 0..=AUTH_FREE_TRIES {
            db.note_auth("mallory", false);
        }
        assert!(db.auth_lockout("mallory").is_some(), "locked out after the free tries");
        db.note_auth("mallory", true);
        assert!(db.auth_lockout("mallory").is_none(), "a success clears the throttle");
    }

    // Locally-authored events get an incrementing per-origin seq and a ticking
    // Lamport clock.
    #[test]
    fn append_stamps_monotonic_metadata() {
        let (mut log, ev) = EventLog::open(tmp("append"), "nodeA".into());
        assert!(ev.is_empty());
        log.append(cert("x", "f1")).unwrap();
        log.append(cert("x", "f2")).unwrap();
        assert_eq!(log.versions.get("nodeA"), Some(&1)); // seqs 0 then 1
        assert_eq!(log.lamport, 2);
        assert_eq!(log.next_seq(), 2);
    }

    // Reopening the log recovers the clocks so seqs are never reused.
    #[test]
    fn reopen_recovers_clocks() {
        let p = tmp("reopen");
        {
            let (mut log, _) = EventLog::open(p.clone(), "nodeA".into());
            log.append(cert("x", "f1")).unwrap();
            log.append(cert("x", "f2")).unwrap();
        }
        let (log, events) = EventLog::open(p, "nodeA".into());
        assert_eq!(events.len(), 2);
        assert_eq!(log.next_seq(), 2);
        assert_eq!(log.lamport, 2);
    }

    // Ingesting a peer's entry applies it once and advances the Lamport clock;
    // a re-delivered entry is dropped (gossip convergence).
    #[test]
    fn ingest_is_idempotent() {
        let (mut log, _) = EventLog::open(tmp("ingest"), "local".into());
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 5, event: cert("x", "f") };
        assert!(log.ingest(entry.clone()).unwrap().is_some(), "first ingest applies");
        assert_eq!(log.versions.get("peer"), Some(&0));
        assert_eq!(log.lamport, 6, "receive rule: max(local, remote) + 1");
        assert!(log.ingest(entry).unwrap().is_none(), "duplicate ingest is a no-op");
    }

    // The gossip seam folds a peer's account into local state.
    #[test]
    fn db_ingest_folds_peer_account() {
        let mut db = Db::open(tmp("dbingest"), "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        let bob = Account {
            name: "bob".into(), password_hash: "x".into(), email: None,
            ts: 0, home: "peer".into(), scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![], suspension: None, memos: vec![], greet: String::new(), vhost: None, vhost_request: None, last_seen: 0, noexpire: false, expiry_warned: false, oper_note: None,
        };
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 1, event: Event::AccountRegistered(Box::new(bob)) };
        db.ingest(entry).unwrap();
        assert!(db.exists("bob"), "peer's account is present locally");
        assert!(db.exists("alice"), "local account still there");
    }

    // Compaction collapses churn to one entry per account and survives a reload.
    #[test]
    fn compact_preserves_state_and_shrinks() {
        let p = tmp("compact");
        let mut db = Db::open(&p, "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        for i in 0..10u32 {
            let fp = format!("{i:032x}");
            db.certfp_add("alice", &fp).unwrap();
            db.certfp_del("alice", &fp).unwrap();
        }
        let kept = "bb".repeat(16);
        db.certfp_add("bob", &kept).unwrap();

        let before = db.log.len();
        db.compact().unwrap();
        assert!(db.log.len() < before, "log shrank: {before} -> {}", db.log.len());
        assert_eq!(db.log.len(), 2, "one entry per account");

        drop(db);
        let db = Db::open(&p, "local");
        assert!(db.authenticate("alice", "pw").is_some(), "password survives compaction");
        assert!(db.certfps("alice").is_empty(), "churned certs are gone");
        assert_eq!(db.certfps("bob"), &[kept][..], "kept cert survives");
    }

    // A peer with an empty log converges from a node that has already compacted.
    #[test]
    fn compacted_node_still_converges() {
        let mut a = Db::open(tmp("compA"), "A");
        a.scram_iterations = 4096;
        a.register("alice", "pw", None).unwrap();
        let fp = "cc".repeat(16);
        a.certfp_add("alice", &fp).unwrap();
        a.compact().unwrap();

        let mut b = Db::open(tmp("compB"), "B");
        b.scram_iterations = 4096;
        for entry in a.missing_for(&b.version_vector()) {
            b.ingest(entry).unwrap();
        }
        assert!(b.exists("alice"), "B converges from a compacted node");
        assert_eq!(b.certfps("alice"), &[fp][..], "certs arrive folded into the snapshot");
    }

    // Channels register (case-insensitively unique), persist, and drop.
    #[test]
    fn channels_register_drop_and_persist() {
        let p = tmp("chan");
        let mut db = Db::open(&p, "local");
        db.register_channel("#Chat", "alice").unwrap();
        assert!(matches!(db.register_channel("#chat", "bob"), Err(ChanError::Exists)), "dup is case-insensitive");
        assert_eq!(db.channel("#CHAT").map(|c| c.founder.as_str()), Some("alice"));

        drop(db);
        let mut db = Db::open(&p, "local");
        assert_eq!(db.channel("#chat").map(|c| c.founder.as_str()), Some("alice"), "survives reopen");
        db.drop_channel("#chat").unwrap();
        assert!(db.channel("#chat").is_none());
        assert!(matches!(db.drop_channel("#chat"), Err(ChanError::NoChannel)));
    }

    // Mode lock persists, renders the applied string, and detects violations.
    #[test]
    fn mode_lock_persists_and_enforces() {
        let p = tmp("mlock");
        let mut db = Db::open(&p, "local");
        db.register_channel("#chan", "alice").unwrap();
        db.set_mlock("#chan", "nt", "s").unwrap();

        let info = db.channel("#chan").unwrap();
        assert_eq!(info.lock_modes(), "+rnt-s");
        assert_eq!(info.enforce("-nt"), Some("+nt".to_string())); // locked-on removed
        assert_eq!(info.enforce("+s"), Some("-s".to_string()));   // locked-off added
        assert_eq!(info.enforce("-r"), Some("+r".to_string()));   // +r always locked
        assert_eq!(info.enforce("+m"), None);                     // unrelated mode ignored

        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#chan").unwrap().lock_modes(), "+rnt-s", "survives reopen");
    }

    // Access list drives join modes, is case-insensitive, and persists.
    #[test]
    fn access_list_grants_join_modes() {
        let p = tmp("access");
        let mut db = Db::open(&p, "local");
        db.register_channel("#c", "boss").unwrap();
        db.access_add("#c", "alice", "op").unwrap();
        db.access_add("#c", "bob", "voice").unwrap();

        let info = db.channel("#c").unwrap();
        assert_eq!(info.join_mode("boss"), Some("+o"));  // founder
        assert_eq!(info.join_mode("ALICE"), Some("+o")); // op, case-insensitive
        assert_eq!(info.join_mode("bob"), Some("+v"));   // voice
        assert_eq!(info.join_mode("nobody"), None);

        assert!(db.access_del("#c", "alice").unwrap());
        assert!(!db.access_del("#c", "alice").unwrap());

        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#c").unwrap().join_mode("bob"), Some("+v"), "survives reopen");
        assert_eq!(db.channel("#c").unwrap().join_mode("alice"), None, "removal survives reopen");
    }
}
