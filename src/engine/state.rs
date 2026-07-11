use std::collections::HashMap;

// Live network view, rebuilt from the uplink's burst each connect (ephemeral —
// unlike the account store, which persists).
#[derive(Default)]
pub struct Network {
    pub users: HashMap<String, User>, // keyed by UID
    pub channels: HashMap<String, Channel>,
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

    pub fn user_quit(&mut self, uid: &str) {
        self.users.remove(uid);
    }

    pub fn nick_of(&self, uid: &str) -> Option<&str> {
        self.users.get(uid).map(|u| u.nick.as_str())
    }
}
