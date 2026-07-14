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
#[path = "kick.rs"]
mod kick;
#[path = "mode.rs"]
mod mode;
#[path = "ignore.rs"]
mod ignore;
#[path = "stats.rs"]
mod stats;
#[path = "svs.rs"]
mod svs;
#[path = "info.rs"]
mod info;
#[path = "oper.rs"]
mod oper;
#[path = "session.rs"]
mod session;
#[path = "jupe.rs"]
mod jupe;
#[path = "chankill.rs"]
mod chankill;
#[path = "logsearch.rs"]
mod logsearch;
#[path = "defcon.rs"]
mod defcon;

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
            Some(cmd) if cmd.eq_ignore_ascii_case("SNLINE") => xline::SNLINE.handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("SHUN") => xline::SHUN.handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("CBAN") => xline::CBAN.handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("GLOBAL") => global::handle(me, from, args, ctx),
            Some(cmd) if cmd.eq_ignore_ascii_case("KILL") => kill::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("KICK") => kick::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("MODE") => mode::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("IGNORE") => ignore::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("STATS") => stats::handle(me, from, db, ctx),
            Some(cmd) if cmd.eq_ignore_ascii_case("SVSNICK") => svs::nick(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("SVSJOIN") => svs::join(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("INFO") => info::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("OPER") => oper::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("SESSION") => session::handle_session(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("EXCEPTION") => session::handle_exception(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("JUPE") => jupe::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("CHANKILL") => chankill::handle(me, from, args, ctx, net, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("LOGSEARCH") => logsearch::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("DEFCON") => defcon::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("HELP") => help(me, from, ctx),
            None => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "OperServ holds network operator tools (Priv::Admin): \x02AKILL\x02 ADD|DEL|LIST (user@host bans), \x02SQLINE\x02 ADD|DEL|LIST (nick bans), \x02SNLINE\x02 ADD|DEL|LIST (realname bans), \x02SHUN\x02 ADD|DEL|LIST (silence a host), \x02CBAN\x02 ADD|DEL|LIST (ban a channel name), \x02CHANKILL\x02 <#chan> (clear a channel), \x02GLOBAL\x02 <message> (announce to everyone), \x02KILL\x02 <nick> [reason] (disconnect a user), \x02KICK\x02 <#chan> <nick> [reason], \x02MODE\x02 <#chan> <modes> [params], \x02IGNORE\x02 ADD|DEL|LIST (silence a user from services), \x02STATS\x02 (enforcement overview), \x02SVSNICK\x02 <nick> <newnick>, \x02SVSJOIN\x02 <nick> <#chan> [key], \x02INFO\x02 ADD|DEL <target> (staff notes — bulletins are on \x02InfoServ\x02), \x02OPER\x02 ADD|DEL|LIST (runtime operators), \x02SESSION\x02 LIST|VIEW + \x02EXCEPTION\x02 ADD|DEL|LIST (per-IP session limits), \x02JUPE\x02 <server> | DEL | LIST, \x02LOGSEARCH\x02 [pattern] (search the action log), \x02DEFCON\x02 [1-5] (network defence level).");
}
