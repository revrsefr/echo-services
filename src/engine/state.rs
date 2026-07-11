use std::collections::HashMap;

// Live network view the services reason about.
#[derive(Default)]
pub struct Network {
    pub users: HashMap<String, User>,    // keyed by UID
    pub channels: HashMap<String, Channel>,
}

pub struct User {
    pub uid: String,
    pub nick: String,
    pub account: Option<String>,
}

pub struct Channel {
    pub name: String,
    pub ts: u64,
}

// The Sable-inspired core: every persistent change is an Event, and state is a
// fold over the log. Single-node today; replicating this log across service
// nodes is what turns it federated later, without rewriting the services.
#[derive(Debug, Clone)]
pub enum Event {
    AccountRegistered { account: String, uid: String },
    ChannelRegistered { channel: String, founder: String },
}

#[derive(Default)]
pub struct EventLog {
    pub events: Vec<Event>,
}

impl EventLog {
    pub fn append(&mut self, event: Event) {
        self.events.push(event);
    }
}
