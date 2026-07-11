pub mod service;
pub mod state;

use crate::proto::{NetAction, NetEvent};
use service::{Service, ServiceCtx};
use state::{EventLog, Network};

pub struct Engine {
    services: Vec<Box<dyn Service>>,
    #[allow(dead_code)]
    network: Network,
    #[allow(dead_code)]
    log: EventLog,
}

impl Engine {
    pub fn new(services: Vec<Box<dyn Service>>) -> Self {
        Self {
            services,
            network: Network::default(),
            log: EventLog::default(),
        }
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
            NetEvent::Privmsg { from, to, text } => self.dispatch(&from, &to, &text),
            _ => Vec::new(),
        }
    }

    // Route a PRIVMSG addressed to a service (by uid or nick) into that service.
    fn dispatch(&mut self, from: &str, to: &str, text: &str) -> Vec<NetAction> {
        let mut ctx = ServiceCtx::default();
        for svc in self.services.iter_mut() {
            if to.eq_ignore_ascii_case(svc.uid()) || to.eq_ignore_ascii_case(svc.nick()) {
                let args: Vec<&str> = text.split_whitespace().collect();
                svc.on_command(from, &args, &mut ctx);
                break;
            }
        }
        ctx.actions
    }
}
