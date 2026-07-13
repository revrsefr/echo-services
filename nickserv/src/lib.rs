use fedserv_api::Store;
use fedserv_api::{Sender, Service, ServiceCtx};
use fedserv_api::NetView;

#[path = "register.rs"]
mod register;
#[path = "identify.rs"]
mod identify;
#[path = "logout.rs"]
mod logout;
#[path = "cert.rs"]
mod cert;
#[path = "info.rs"]
mod info;
#[path = "alist.rs"]
mod alist;
#[path = "set.rs"]
mod set;
#[path = "drop.rs"]
mod drop;
#[path = "group.rs"]
mod group;
#[path = "glist.rs"]
mod glist;
#[path = "ungroup.rs"]
mod ungroup;
#[path = "ghost.rs"]
mod ghost;
#[path = "resetpass.rs"]
mod resetpass;
#[path = "confirm.rs"]
mod confirm;
#[path = "ajoin.rs"]
mod ajoin;
#[path = "password.rs"]
mod password;

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

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REGISTER") => register::handle(me, from, args, ctx),
            Some("IDENTIFY") | Some("ID") => identify::handle(me, from, args, ctx, db),
            Some("LOGOUT") | Some("LOGOFF") => logout::handle(me, &self.guest_nick, &mut self.guest_seq, from, ctx),
            Some("CERT") => cert::handle(me, from, args, ctx, db),
            Some("INFO") => info::handle(me, from, args, ctx, db),
            Some("ALIST") => alist::handle(me, from, ctx, db),
            Some("SET") => set::handle(me, from, args, ctx, db),
            Some("DROP") => drop::handle(me, from, args, ctx, net, db),
            Some("GROUP") => group::handle(me, from, args, ctx, db),
            Some("GLIST") => glist::handle(me, from, ctx, db),
            Some("UNGROUP") => ungroup::handle(me, from, args, ctx, db),
            Some("GHOST") | Some("RECOVER") => ghost::handle(me, &self.guest_nick, &mut self.guest_seq, from, args, ctx, net, db),
            Some("RESETPASS") => resetpass::handle(me, from, args, ctx, db),
            Some("CONFIRM") => confirm::handle(me, from, args, ctx, db),
            Some("AJOIN") => ajoin::handle(me, from, args, ctx, db),
            Some("HELP") => ctx.notice(me, from.uid, "NickServ looks after your nickname. Commands: \x02REGISTER\x02 <password> [email], \x02IDENTIFY\x02 [account] <password>, \x02INFO\x02 [account], \x02ALIST\x02, \x02GROUP\x02/\x02GLIST\x02/\x02UNGROUP\x02, \x02GHOST\x02 <nick> [password], \x02SET\x02 PASSWORD|EMAIL, \x02AJOIN\x02 ADD|DEL|LIST, \x02RESETPASS\x02 <account>, \x02CONFIRM\x02 <code>, \x02DROP\x02 <password>, \x02LOGOUT\x02, \x02CERT\x02 ADD|DEL|LIST <password> [fingerprint]."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
            None => {}
        }
    }
}
