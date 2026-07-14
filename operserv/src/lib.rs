//! OperServ gives services operators network-wide tools: AKILL/SQLINE network
//! bans (event-sourced, lazily expiring, re-asserted at burst), a GLOBAL
//! announcement to every user, and KILL to disconnect one. `lib.rs` dispatches;
//! each command family is its own file.

use fedserv_api::{NetView, Sender, Service, ServiceCtx, Store};

#[path = "xline.rs"]
mod xline;
#[path = "global.rs"]
mod global;
#[path = "kill.rs"]
mod kill;

pub struct OperServ {
    pub uid: String,
}

impl Service for OperServ {
    fn nick(&self) -> &str {
        "OperServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Operator Service"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        // Every OperServ command is operator-only: reveal nothing to others.
        if !from.privs.any() {
            ctx.notice(me, from.uid, "Access denied — OperServ is for services operators.");
            return;
        }
        match args.first().copied() {
            Some(cmd) if cmd.eq_ignore_ascii_case("AKILL") => xline::AKILL.handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("SQLINE") => xline::SQLINE.handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("GLOBAL") => global::handle(me, from, args, ctx),
            Some(cmd) if cmd.eq_ignore_ascii_case("KILL") => kill::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("HELP") => help(me, from, ctx),
            None => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "OperServ holds network operator tools (Priv::Admin): \x02AKILL\x02 ADD|DEL|LIST (user@host bans), \x02SQLINE\x02 ADD|DEL|LIST (nick bans), \x02GLOBAL\x02 <message> (announce to everyone), \x02KILL\x02 <nick> [reason] (disconnect a user).");
}
