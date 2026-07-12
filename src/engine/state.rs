use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

// Live network view, rebuilt from the uplink's burst each connect (ephemeral —
// unlike the account store, which persists).
#[derive(Default)]
pub struct Network {
    pub users: HashMap<String, User>, // keyed by UID
    channels: HashMap<String, Channel>, // keyed by lowercase name
    accounts: HashMap<String, String>, // UID -> logged-in account, until logout/quit
    seen: HashMap<String, Seen>,       // lowercase nick -> last activity
}

pub struct User {
    pub uid: String,
    pub nick: String,
    pub host: String,
}

// A channel's live membership, ops, and current key (+k), tracked from the burst.
#[derive(Default)]
pub struct Channel {
    pub members: HashSet<String>, // uids
    pub ops: HashSet<String>,     // uids holding channel-operator status
    pub key: Option<String>,
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
    pub fn user_connect(&mut self, uid: String, nick: String, host: String) {
        self.users.insert(uid.clone(), User { uid, nick, host });
    }

    // Resolve a nick to its uid (case-insensitive).
    pub fn uid_by_nick(&self, nick: &str) -> Option<&str> {
        self.users.values().find(|u| u.nick.eq_ignore_ascii_case(nick)).map(|u| u.uid.as_str())
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
        }
        self.users.remove(uid);
        self.accounts.remove(uid);
        for c in self.channels.values_mut() {
            c.members.remove(uid);
            c.ops.remove(uid);
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
