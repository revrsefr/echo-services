pub mod db;
pub mod service;
pub mod state;

use crate::proto::{NetAction, NetEvent};
use db::Db;
use service::{Sender, Service, ServiceCtx};
use state::Network;

pub struct Engine {
    services: Vec<Box<dyn Service>>,
    network: Network,
    db: Db,
}

impl Engine {
    pub fn new(services: Vec<Box<dyn Service>>, db: Db) -> Self {
        Self { services, network: Network::default(), db }
    }

    // Sent right after the SERVER line: burst, introduce every service, endburst.
    pub fn startup_actions(&self) -> Vec<NetAction> {
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
        out.push(NetAction::EndBurst);
        out
    }

    pub fn handle(&mut self, event: NetEvent) -> Vec<NetAction> {
        match event {
            NetEvent::Ping { token, from } => vec![NetAction::Pong { token, from }],
            NetEvent::UserConnect { uid, nick } => {
                self.network.user_connect(uid, nick);
                Vec::new()
            }
            NetEvent::Quit { uid } => {
                self.network.user_quit(&uid);
                Vec::new()
            }
            NetEvent::Privmsg { from, to, text } => self.dispatch(&from, &to, &text),
            _ => Vec::new(),
        }
    }

    // Route a PRIVMSG addressed to a service (by uid or nick) into that service,
    // handing it the sender's resolved nick and the account store.
    fn dispatch(&mut self, from: &str, to: &str, text: &str) -> Vec<NetAction> {
        let nick = self.network.nick_of(from).unwrap_or(from).to_string();
        let mut ctx = ServiceCtx::default();
        let sender = Sender { uid: from, nick: &nick };
        let Self { services, db, .. } = self;
        for svc in services.iter_mut() {
            if to.eq_ignore_ascii_case(svc.uid()) || to.eq_ignore_ascii_case(svc.nick()) {
                let args: Vec<&str> = text.split_whitespace().collect();
                svc.on_command(&sender, &args, &mut ctx, db);
                break;
            }
        }
        ctx.actions
    }
}
