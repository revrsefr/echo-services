//! OperServ gives services operators network-wide tools. The first is AKILL:
//! network bans (G-lines) that keep matching users off the whole network,
//! event-sourced so they survive a restart and re-apply at burst, with lazy
//! expiry like the rest of the store. `lib.rs` dispatches; each command is its
//! own file.

use fedserv_api::{NetView, Sender, Service, ServiceCtx, Store};

#[path = "akill.rs"]
mod akill;

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

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        // Every OperServ command is operator-only: reveal nothing to others.
        if !from.privs.any() {
            ctx.notice(me, from.uid, "Access denied — OperServ is for services operators.");
            return;
        }
        match args.first().copied() {
            Some(cmd) if cmd.eq_ignore_ascii_case("AKILL") => akill::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("HELP") => help(me, from, ctx),
            None => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02AKILL\x02 or \x02HELP\x02.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "OperServ holds network operator tools. \x02AKILL ADD\x02 [+expiry] <user@host> <reason>, \x02AKILL DEL\x02 <user@host|number>, \x02AKILL LIST\x02 [pattern] — network bans (Priv::Admin).");
}
