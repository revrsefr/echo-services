use crate::engine::db::Db;
use crate::engine::service::{Sender, Service, ServiceCtx};
use crate::engine::state::Network;

#[path = "register.rs"]
mod register;
#[path = "identify.rs"]
mod identify;
#[path = "logout.rs"]
mod logout;
#[path = "cert.rs"]
mod cert;

pub struct NickServ {
    pub uid: String,
    // Nick prefix assigned on LOGOUT (default "Guest"); a per-session sequence is
    // appended so successive guests don't collide within a run.
    pub guest_nick: String,
    pub guest_seq: u32,
}

impl Service for NickServ {
    fn nick(&self) -> &str {
        "NickServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Nickname Services"
    }
    fn manages_accounts(&self) -> bool {
        true
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &Network, db: &mut Db) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REGISTER") => register::handle(me, from, args, ctx),
            Some("IDENTIFY") | Some("ID") => identify::handle(me, from, args, ctx, db),
            Some("LOGOUT") | Some("LOGOFF") => logout::handle(me, &self.guest_nick, &mut self.guest_seq, from, ctx),
            Some("CERT") => cert::handle(me, from, args, ctx, db),
            Some("HELP") => ctx.notice(me, from.uid, "NickServ looks after your nickname. Commands: \x02REGISTER\x02 <password> [email], \x02IDENTIFY\x02 [account] <password>, \x02LOGOUT\x02, \x02CERT\x02 ADD|DEL|LIST <password> [fingerprint]."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
            None => {}
        }
    }
}
