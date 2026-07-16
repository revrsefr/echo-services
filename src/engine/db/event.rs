use super::*;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

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
    AccountAutoOpSet { account: String, on: bool },
    AccountPasswordSet { account: String, scram256: String, scram512: String },
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
    MemoSent { account: String, from: String, text: String, ts: u64, #[serde(default)] receipt: bool },
    MemoRead { account: String, index: usize },
    MemoDeleted { account: String, index: usize },
    MemoIgnoreAdd { account: String, target: String },
    MemoIgnoreDel { account: String, target: String },
    MemoPrefsSet { account: String, notify: bool, limit: Option<u32> },
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
    ChannelSuccessorSet { channel: String, successor: Option<String> },
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
    // The bot auto-assigned to newly registered channels (BotServ AUTOASSIGN).
    DefaultBotSet { bot: Option<String> },
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
    // Help-desk tickets (HelpServ). Global so any node's helpers see the queue.
    HelpRequested { id: u64, requester: String, message: String, ts: u64 },
    HelpTaken { id: u64, handler: String },
    HelpClosed { id: u64 },
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
    // Registration bans (OperServ FORBID). Global network policy. `kind` is
    // "NICK", "CHAN", or "EMAIL".
    ForbidAdded { kind: String, mask: String, setter: String, reason: String, ts: u64 },
    ForbidRemoved { kind: String, mask: String },
}

// Whether an event replicates across the federation. Account identity is Global
// (one owner, gossiped everywhere); channel state is Local (scoped to the one
// network that authored it, so a node can't be handed ownership of a channel it
// never saw registered). Exhaustive on purpose: a new event must pick a side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Global,
    Local,
}

impl Event {
    pub(crate) fn scope(&self) -> Scope {
        match self {
            Event::AccountRegistered(_)
            | Event::CertAdded { .. }
            | Event::CertRemoved { .. }
            | Event::AccountEmailSet { .. }
            | Event::AccountGreetSet { .. }
            | Event::AccountAutoOpSet { .. }
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
            | Event::MemoIgnoreAdd { .. }
            | Event::MemoIgnoreDel { .. }
            | Event::MemoPrefsSet { .. }
            | Event::NickGrouped { .. }
            | Event::NickUngrouped { .. }
            | Event::AccountSeen { .. }
            | Event::AccountNoExpire { .. }
            | Event::AccountExpiryWarned { .. }
            | Event::AccountOperNoteSet { .. }
            | Event::AkillAdded { .. }
            | Event::AkillRemoved { .. }
            | Event::ForbidAdded { .. }
            | Event::ForbidRemoved { .. }
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
            | Event::HelpRequested { .. }
            | Event::HelpTaken { .. }
            | Event::HelpClosed { .. }
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
            | Event::ChannelSuccessorSet { .. }
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
            | Event::DefaultBotSet { .. }
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
pub(crate) fn apply(accounts: &mut HashMap<String, Account>, channels: &mut HashMap<String, ChannelInfo>, grouped: &mut HashMap<String, String>, bots: &mut HashMap<String, Bot>, host_cfg: &mut HostConfig, net: &mut NetData, event: Event) {
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
        Event::AccountAutoOpSet { account, on } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.no_autoop = !on;
            }
        }
        Event::AccountPasswordSet { account, scram256, scram512 } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
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
        Event::MemoSent { account, from, text, ts, receipt } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.memos.push(Memo { from, text, ts, read: false, receipt });
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
        Event::MemoIgnoreAdd { account, target } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                if !a.memo_ignore.iter().any(|t| t.eq_ignore_ascii_case(&target)) {
                    a.memo_ignore.push(target);
                }
            }
        }
        Event::MemoIgnoreDel { account, target } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.memo_ignore.retain(|t| !t.eq_ignore_ascii_case(&target));
            }
        }
        Event::MemoPrefsSet { account, notify, limit } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.memo_notify = notify;
                a.memo_limit = limit;
            }
        }
        Event::NickGrouped { nick, account } => {
            grouped.insert(key(&nick), account);
        }
        Event::NickUngrouped { nick } => {
            grouped.remove(&key(&nick));
        }
        Event::ChannelRegistered { name, founder, ts } => {
            channels.insert(key(&name), ChannelInfo { name, founder, ts, lock_on: String::new(), lock_off: String::new(), access: Vec::new(), akick: Vec::new(), successor: None, desc: String::new(), entrymsg: String::new(), settings: ChanSettings::default(), topic: String::new(), suspension: None, assigned_bot: None , kickers: KickerSettings::default() , badwords: Vec::new(), badwords_rev: 0 , triggers: Vec::new(), triggers_rev: 0, last_used: ts, noexpire: false, expiry_warned: false, oper_note: None });
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
        Event::ChannelSuccessorSet { channel, successor } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.successor = successor;
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
            // A default bot that was just removed can't stay the default.
            if net.default_bot.as_deref() == Some(key(&nick).as_str()) {
                net.default_bot = None;
            }
        }
        Event::DefaultBotSet { bot } => {
            net.default_bot = bot.map(|b| key(&b));
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
        Event::ForbidAdded { kind, mask, setter, reason, ts } => {
            net.forbids.retain(|f| !(f.kind == kind && f.mask.eq_ignore_ascii_case(&mask)));
            net.forbids.push(Forbid { kind, mask, setter, reason, ts });
        }
        Event::ForbidRemoved { kind, mask } => {
            net.forbids.retain(|f| !(f.kind == kind && f.mask.eq_ignore_ascii_case(&mask)));
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
        Event::HelpRequested { id, requester, message, ts } => {
            net.help_seq = net.help_seq.max(id + 1);
            if !net.help.iter().any(|t| t.id == id) {
                net.help.push(HelpTicket { id, requester, message, ts, handler: None, open: true });
            }
        }
        Event::HelpTaken { id, handler } => {
            if let Some(t) = net.help.iter_mut().find(|t| t.id == id) {
                t.handler = Some(handler);
            }
        }
        Event::HelpClosed { id } => {
            if let Some(t) = net.help.iter_mut().find(|t| t.id == id) {
                t.open = false;
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
