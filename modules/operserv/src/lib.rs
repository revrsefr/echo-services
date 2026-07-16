//! OperServ gives services operators network-wide tools: AKILL/SQLINE network
//! bans (event-sourced, lazily expiring, re-asserted at burst), a GLOBAL
//! announcement to every user, and KILL to disconnect one. `lib.rs` dispatches;
//! each command family is its own file.

use echo_api::{HelpEntry, NetView, Sender, Service, ServiceCtx, Store};

#[path = "xline.rs"]
mod xline;
#[path = "forbid.rs"]
mod forbid;
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

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
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
            Some(cmd) if cmd.eq_ignore_ascii_case("FORBID") => forbid::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("GLOBAL") => global::handle(me, from, args, ctx),
            Some(cmd) if cmd.eq_ignore_ascii_case("KILL") => kill::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("KICK") => kick::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("MODE") => mode::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("IGNORE") => ignore::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("STATS") => stats::handle(me, from, db, ctx),
            Some(cmd) if cmd.eq_ignore_ascii_case("SVSNICK") => svs::nick(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("SVSJOIN") => svs::join(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("SVSPART") => svs::part(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("INFO") => info::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("OPER") => oper::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("SESSION") => session::handle_session(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("EXCEPTION") => session::handle_exception(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("JUPE") => jupe::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("CHANKILL") => chankill::handle(me, from, args, ctx, net, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("LOGSEARCH") => logsearch::handle(me, from, args, ctx, net),
            Some(cmd) if cmd.eq_ignore_ascii_case("DEFCON") => defcon::handle(me, from, args, ctx, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("HELP") => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            None => echo_api::help(me, from, ctx, BLURB, TOPICS, None),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}

const BLURB: &str = "OperServ holds the network operator tools. Every command is operator-only.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "AKILL", summary: "network-ban a user@host", detail: "Syntax: \x02AKILL ADD [+expiry] <user@host> <reason> | AKILL DEL <mask|number> | AKILL LIST [pattern]\x02\nA network-wide user@host ban." },
    HelpEntry { cmd: "FORBID", summary: "ban a nick/chan/email from registration", detail: "Syntax: \x02FORBID ADD <NICK|CHAN|EMAIL> <mask> <reason> | FORBID DEL <NICK|CHAN|EMAIL> <mask> | FORBID LIST\x02\nStops a nick, channel, or email pattern from being registered." },
    HelpEntry { cmd: "SQLINE", summary: "ban a nick pattern", detail: "Syntax: \x02SQLINE ADD [+expiry] <nick> <reason> | SQLINE DEL <mask|number> | SQLINE LIST [pattern]\x02\nBans matching nicknames." },
    HelpEntry { cmd: "SNLINE", summary: "ban a realname pattern", detail: "Syntax: \x02SNLINE ADD [+expiry] <realname> <reason> | SNLINE DEL <mask|number> | SNLINE LIST [pattern]\x02\nBans matching real names." },
    HelpEntry { cmd: "SHUN", summary: "silence a host", detail: "Syntax: \x02SHUN ADD [+expiry] <mask> <reason> | SHUN DEL <mask|number> | SHUN LIST [pattern]\x02\nSilences a matching host: it stays connected but can't act." },
    HelpEntry { cmd: "CBAN", summary: "ban a channel name", detail: "Syntax: \x02CBAN ADD [+expiry] <#channel> <reason> | CBAN DEL <mask|number> | CBAN LIST [pattern]\x02\nBlocks matching channel names from being joined." },
    HelpEntry { cmd: "CHANKILL", summary: "clear a channel", detail: "Syntax: \x02CHANKILL <#channel> [reason]\x02\nRemoves everyone from a channel and holds it briefly." },
    HelpEntry { cmd: "GLOBAL", summary: "announce to everyone", detail: "Syntax: \x02GLOBAL <message>\x02\nSends a notice to every user on the network." },
    HelpEntry { cmd: "KILL", summary: "disconnect a user", detail: "Syntax: \x02KILL <nick> [reason]\x02\nDisconnects a user from the network." },
    HelpEntry { cmd: "KICK", summary: "kick from a channel", detail: "Syntax: \x02KICK <#channel> <nick> [reason]\x02\nKicks a user from a channel." },
    HelpEntry { cmd: "MODE", summary: "set channel modes", detail: "Syntax: \x02MODE <#channel> <modes> [params]\x02\nSets modes on a channel." },
    HelpEntry { cmd: "IGNORE", summary: "silence a user from services", detail: "Syntax: \x02IGNORE ADD [+expiry] <mask> [reason] | IGNORE DEL <mask> | IGNORE LIST\x02\nMakes services ignore commands from a matching user." },
    HelpEntry { cmd: "STATS", summary: "enforcement overview", detail: "Syntax: \x02STATS\x02\nShows an overview of the enforcement lists." },
    HelpEntry { cmd: "SVSNICK", summary: "force a nick change", detail: "Syntax: \x02SVSNICK <nick> <newnick>\x02\nForces a user to change nick." },
    HelpEntry { cmd: "SVSJOIN", summary: "force a channel join", detail: "Syntax: \x02SVSJOIN <nick> <#channel> [key]\x02\nForces a user to join a channel." },
    HelpEntry { cmd: "SVSPART", summary: "force a channel part", detail: "Syntax: \x02SVSPART <nick> <#channel> [reason]\x02\nForces a user out of a channel." },
    HelpEntry { cmd: "INFO", summary: "staff notes on a target", detail: "Syntax: \x02INFO <target> | INFO ADD <target> <note> | INFO DEL <target>\x02\nReads or sets staff notes on an account or channel. (Bulletins are on InfoServ.)" },
    HelpEntry { cmd: "OPER", summary: "runtime operators", detail: "Syntax: \x02OPER ADD <account> <priv[,priv]> [+duration] | OPER DEL <account> | OPER LIST\x02\nGrants or revokes runtime operator privileges: auspex, suspend, admin." },
    HelpEntry { cmd: "SESSION", summary: "inspect per-IP sessions", detail: "Syntax: \x02SESSION LIST <min> | SESSION VIEW <ip>\x02\nInspects per-IP session counts." },
    HelpEntry { cmd: "EXCEPTION", summary: "session-limit exceptions", detail: "Syntax: \x02EXCEPTION ADD <ip-mask> <limit> [reason] | EXCEPTION DEL <ip-mask> | EXCEPTION LIST\x02\nAdjusts the per-IP session limit for a mask (0 = unlimited)." },
    HelpEntry { cmd: "JUPE", summary: "jupe a server name", detail: "Syntax: \x02JUPE <server.name> [reason] | JUPE DEL <server.name> | JUPE LIST\x02\nBlocks a server name from linking." },
    HelpEntry { cmd: "LOGSEARCH", summary: "search the action log", detail: "Syntax: \x02LOGSEARCH [pattern]\x02\nSearches the incident and action log." },
    HelpEntry { cmd: "DEFCON", summary: "network defence level", detail: "Syntax: \x02DEFCON [1-5]\x02\nShows or sets the network defence level (5 = normal, 1 = lockdown)." },
];
