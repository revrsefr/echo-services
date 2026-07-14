use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

// The read-only network view a module sees; re-exported so the engine keeps
// naming it locally.
pub use fedserv_api::{NetView, SeenView};

// Live network view, rebuilt from the uplink's burst each connect (ephemeral —
// unlike the account store, which persists).
#[derive(Default)]
pub struct Network {
    pub users: HashMap<String, User>, // keyed by UID
    channels: HashMap<String, Channel>, // keyed by lowercase name
    accounts: HashMap<String, String>, // UID -> logged-in account, until logout/quit
    seen: HashMap<String, Seen>,       // lowercase nick -> last activity
    // Our own service bots (lowercase nick -> live uid). Kept separate from
    // `users` so a reconnect can clear them wholesale without disturbing the
    // uplink-sourced user map.
    bots: HashMap<String, String>,
    // Shared, namespaced stat counters any service contributes to (ephemeral,
    // ordered for a stable snapshot). Read by StatServ and the gRPC Stats API.
    stats: BTreeMap<String, u64>,
    // Live session count per connecting IP, for OperServ session limiting.
    sessions: HashMap<String, u32>,
}

pub struct User {
    pub uid: String,
    pub nick: String,
    pub host: String,
    pub ip: String,
}

// A channel's live membership, ops, and current key (+k), tracked from the burst.
#[derive(Default)]
pub struct Channel {
    pub members: HashSet<String>, // uids
    pub ops: HashSet<String>,     // uids holding channel-operator status
    pub voices: HashSet<String>,  // uids holding +v
    pub key: Option<String>,
    // BOTSTATS: lines seen this session, and per-nick counts (top-talkers). Bounded.
    pub lines: u64,
    pub talkers: HashMap<String, u64>,
}

// The last time a nick was seen, and doing what.
pub struct Seen {
    pub nick: String,
    pub ts: u64,
    pub what: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn lc(s: &str) -> String {
    s.to_ascii_lowercase()
}

impl Network {
    pub fn user_connect(&mut self, uid: String, nick: String, host: String, ip: String) {
        if !ip.is_empty() {
            *self.sessions.entry(ip.clone()).or_insert(0) += 1;
        }
        self.users.insert(uid.clone(), User { uid, nick, host, ip });
    }

    // Live sessions from `ip`.
    pub fn session_count(&self, ip: &str) -> u32 {
        self.sessions.get(ip).copied().unwrap_or(0)
    }

    // IPs with at least `min` live sessions, most sessions first.
    pub fn sessions_over(&self, min: u32) -> Vec<(String, u32)> {
        let mut v: Vec<(String, u32)> = self.sessions.iter().filter(|(_, &n)| n >= min).map(|(ip, &n)| (ip.clone(), n)).collect();
        v.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
        v
    }

    // Resolve a nick to its uid (case-insensitive). Checks real users first,
    // then our own service bots.
    pub fn uid_by_nick(&self, nick: &str) -> Option<&str> {
        self.users
            .values()
            .find(|u| u.nick.eq_ignore_ascii_case(nick))
            .map(|u| u.uid.as_str())
            .or_else(|| self.bots.get(&nick.to_ascii_lowercase()).map(String::as_str))
    }

    // Track / forget one of our service bots by lowercase nick.
    pub fn bot_connect(&mut self, nick: &str, uid: &str) {
        self.bots.insert(nick.to_ascii_lowercase(), uid.to_string());
    }

    pub fn bot_forget(&mut self, nick_lc: &str) {
        self.bots.remove(nick_lc);
    }

    pub fn clear_bots(&mut self) {
        self.bots.clear();
    }

    pub fn host_of(&self, uid: &str) -> Option<&str> {
        self.users.get(uid).map(|u| u.host.as_str())
    }

    pub fn user_nick_change(&mut self, uid: &str, nick: String) {
        if let Some(user) = self.users.get_mut(uid) {
            self.seen.insert(lc(&nick), Seen { nick: nick.clone(), ts: now(), what: format!("changing nick from {}", user.nick) });
            user.nick = nick;
        }
    }

    pub fn user_quit(&mut self, uid: &str) {
        if let Some(u) = self.users.get(uid) {
            self.seen.insert(lc(&u.nick), Seen { nick: u.nick.clone(), ts: now(), what: "quitting".to_string() });
            // Release the user's session slot.
            if let Some(n) = self.sessions.get_mut(&u.ip) {
                *n -= 1;
                if *n == 0 {
                    self.sessions.remove(&u.ip);
                }
            }
        }
        self.users.remove(uid);
        self.accounts.remove(uid);
        for c in self.channels.values_mut() {
            c.members.remove(uid);
            c.ops.remove(uid);
            c.voices.remove(uid);
        }
    }

    pub fn nick_of(&self, uid: &str) -> Option<&str> {
        self.users.get(uid).map(|u| u.nick.as_str())
    }

    // A user's currently identified account, if any. Kept in step with the
    // accountname metadata the engine emits (login sets it, logout clears it).
    pub fn account_of(&self, uid: &str) -> Option<&str> {
        self.accounts.get(uid).map(String::as_str)
    }

    // Uids of every live session currently identified to `account`.
    pub fn uids_logged_into(&self, account: &str) -> Vec<String> {
        self.accounts
            .iter()
            .filter(|(_, a)| a.eq_ignore_ascii_case(account))
            .map(|(uid, _)| uid.clone())
            .collect()
    }

    pub fn set_account(&mut self, uid: &str, account: &str) {
        self.accounts.insert(uid.to_string(), account.to_string());
    }

    pub fn clear_account(&mut self, uid: &str) {
        self.accounts.remove(uid);
    }

    // A user joined a channel: record membership (and op status) and last-seen.
    pub fn channel_join(&mut self, channel: &str, uid: &str, op: bool) {
        let c = self.channels.entry(lc(channel)).or_default();
        c.members.insert(uid.to_string());
        if op {
            c.ops.insert(uid.to_string());
        }
        if let Some(nick) = self.nick_of(uid) {
            self.seen.insert(lc(nick), Seen { nick: nick.to_string(), ts: now(), what: format!("joining {channel}") });
        }
    }

    // A user left a channel (part/kick): drop membership and record last-seen.
    pub fn channel_part(&mut self, channel: &str, uid: &str) {
        if let Some(c) = self.channels.get_mut(&lc(channel)) {
            c.members.remove(uid);
            c.ops.remove(uid);
            c.voices.remove(uid);
        }
        if let Some(nick) = self.nick_of(uid) {
            self.seen.insert(lc(nick), Seen { nick: nick.to_string(), ts: now(), what: format!("leaving {channel}") });
        }
    }

    // Set or clear a user's channel-operator status (FMODE +o/-o).
    pub fn set_op(&mut self, channel: &str, uid: &str, op: bool) {
        let c = self.channels.entry(lc(channel)).or_default();
        if op {
            c.ops.insert(uid.to_string());
        } else {
            c.ops.remove(uid);
        }
    }

    // Whether `uid` currently holds operator status in `channel`.
    pub fn is_op(&self, channel: &str, uid: &str) -> bool {
        self.channels.get(&lc(channel)).is_some_and(|c| c.ops.contains(uid))
    }

    // Set or clear a user's voice status (+v).
    pub fn set_voice(&mut self, channel: &str, uid: &str, voice: bool) {
        let c = self.channels.entry(lc(channel)).or_default();
        if voice {
            c.voices.insert(uid.to_string());
        } else {
            c.voices.remove(uid);
        }
    }

    // Whether `uid` currently holds voice in `channel`.
    pub fn is_voiced(&self, channel: &str, uid: &str) -> bool {
        self.channels.get(&lc(channel)).is_some_and(|c| c.voices.contains(uid))
    }

    // Record a line spoken in `channel` by `nick`, for BOTSTATS. The per-nick map
    // is capped so a busy channel can't grow it without bound.
    pub fn record_line(&mut self, channel: &str, nick: &str) {
        const TALKER_CAP: usize = 512;
        let c = self.channels.entry(lc(channel)).or_default();
        c.lines = c.lines.saturating_add(1);
        if c.talkers.len() < TALKER_CAP || c.talkers.contains_key(nick) {
            *c.talkers.entry(nick.to_string()).or_insert(0) += 1;
        }
    }

    // Increment a shared stat counter.
    pub fn bump(&mut self, key: &str) {
        *self.stats.entry(key.to_string()).or_insert(0) += 1;
    }

    // The raw shared counters (sorted). Gauges are merged in by the reader.
    pub fn stat_counters(&self) -> &BTreeMap<String, u64> {
        &self.stats
    }

    // BOTSTATS view: (total lines, top talkers by count, descending).
    pub fn channel_activity(&self, channel: &str) -> Option<(u64, Vec<(String, u64)>)> {
        let c = self.channels.get(&lc(channel))?;
        let mut top: Vec<(String, u64)> = c.talkers.iter().map(|(n, v)| (n.clone(), *v)).collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top.truncate(10);
        Some((c.lines, top))
    }

    // Uids currently in `channel`.
    pub fn channel_members(&self, channel: &str) -> impl Iterator<Item = &str> {
        self.channels.get(&lc(channel)).into_iter().flat_map(|c| c.members.iter().map(String::as_str))
    }

    pub fn set_channel_key(&mut self, channel: &str, key: Option<String>) {
        self.channels.entry(lc(channel)).or_default().key = key;
    }

    pub fn channel_key(&self, channel: &str) -> Option<&str> {
        self.channels.get(&lc(channel)).and_then(|c| c.key.as_deref())
    }

    pub fn last_seen(&self, nick: &str) -> Option<&Seen> {
        self.seen.get(&lc(nick))
    }
}

// The module-facing network view. Reads forward to Network's own accessors,
// with the seen record projected into a plain view.
impl NetView for Network {
    fn uid_by_nick(&self, nick: &str) -> Option<&str> {
        Network::uid_by_nick(self, nick)
    }
    fn nick_of(&self, uid: &str) -> Option<&str> {
        Network::nick_of(self, uid)
    }
    fn host_of(&self, uid: &str) -> Option<&str> {
        Network::host_of(self, uid)
    }
    fn account_of(&self, uid: &str) -> Option<&str> {
        Network::account_of(self, uid)
    }
    fn uids_logged_into(&self, account: &str) -> Vec<String> {
        Network::uids_logged_into(self, account)
    }
    fn is_op(&self, channel: &str, uid: &str) -> bool {
        Network::is_op(self, channel, uid)
    }
    fn channel_members(&self, channel: &str) -> Vec<String> {
        Network::channel_members(self, channel).map(str::to_string).collect()
    }
    fn channel_key(&self, channel: &str) -> Option<&str> {
        Network::channel_key(self, channel)
    }
    fn last_seen(&self, nick: &str) -> Option<SeenView> {
        Network::last_seen(self, nick).map(|s| SeenView {
            nick: s.nick.clone(),
            ts: s.ts,
            what: s.what.clone(),
        })
    }
    fn channel_activity(&self, channel: &str) -> Option<(u64, Vec<(String, u64)>)> {
        Network::channel_activity(self, channel)
    }
    fn stat_counters(&self) -> Vec<(String, u64)> {
        Network::stat_counters(self).iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
    fn session_count(&self, ip: &str) -> u32 {
        Network::session_count(self, ip)
    }
    fn sessions_over(&self, min: u32) -> Vec<(String, u32)> {
        Network::sessions_over(self, min)
    }
}
