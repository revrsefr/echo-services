use std::collections::HashMap;

// Live network view, rebuilt from the uplink's burst each connect (ephemeral —
// unlike the account store, which persists).
#[derive(Default)]
pub struct Network {
    pub users: HashMap<String, User>, // keyed by UID
    pub channels: HashMap<String, Channel>,
    accounts: HashMap<String, String>, // UID -> logged-in account, until logout/quit
}

pub struct User {
    pub uid: String,
    pub nick: String,
}

#[allow(dead_code)]
pub struct Channel {
    pub name: String,
    pub ts: u64,
}

impl Network {
    pub fn user_connect(&mut self, uid: String, nick: String) {
        self.users.insert(uid.clone(), User { uid, nick });
    }

    pub fn user_nick_change(&mut self, uid: &str, nick: String) {
        if let Some(user) = self.users.get_mut(uid) {
            user.nick = nick;
        }
    }

    pub fn user_quit(&mut self, uid: &str) {
        self.users.remove(uid);
        self.accounts.remove(uid);
    }

    pub fn nick_of(&self, uid: &str) -> Option<&str> {
        self.users.get(uid).map(|u| u.nick.as_str())
    }

    // A user's currently identified account, if any. Kept in step with the
    // accountname metadata the engine emits (login sets it, logout clears it).
    pub fn account_of(&self, uid: &str) -> Option<&str> {
        self.accounts.get(uid).map(String::as_str)
    }

    pub fn set_account(&mut self, uid: &str, account: &str) {
        self.accounts.insert(uid.to_string(), account.to_string());
    }

    pub fn clear_account(&mut self, uid: &str) {
        self.accounts.remove(uid);
    }
}
