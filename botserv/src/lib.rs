//! BotServ registers service bots — pseudo-clients that get assigned to channels
//! and (in later slices) run fantasy commands. `lib.rs` holds the dispatcher;
//! each command lives in its own file, matching NickServ/ChanServ.

use fedserv_api::{NetView, Priv, Sender, Service, ServiceCtx, Store};

#[path = "bot.rs"]
mod bot;
#[path = "assign.rs"]
mod assign;
#[path = "info.rs"]
mod info;
#[path = "say.rs"]
mod say;
#[path = "set.rs"]
mod set;
#[path = "kick.rs"]
mod kick;
#[path = "badwords.rs"]
mod badwords;
#[path = "copy.rs"]
mod copy;
#[path = "trigger.rs"]
mod trigger;
#[path = "stats.rs"]
mod stats;

// Shared gate: the sender may administer <chan>'s bot options only as its
// founder or a services admin. Notices and returns false on failure.
fn require_channel_admin(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, db: &dyn Store) -> bool {
    let Some(founder) = db.channel(chan).map(|c| c.founder) else {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
        return false;
    };
    if from.account != Some(founder.as_str()) && !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can change that."));
        return false;
    }
    true
}

pub struct BotServ {
    pub uid: String,
}

impl Service for BotServ {
    fn nick(&self) -> &str {
        "BotServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Bot Services"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("BOT") => bot::handle(me, from, args, ctx, db),
            Some("ASSIGN") => assign::handle(me, from, args, ctx, db, true),
            Some("UNASSIGN") => assign::handle(me, from, args, ctx, db, false),
            Some("INFO") => info::handle(me, from, args, ctx, db),
            Some("SAY") => say::handle(me, from, args, ctx, net, db, false),
            Some("ACT") => say::handle(me, from, args, ctx, net, db, true),
            Some("SET") => set::handle(me, from, args, ctx, db),
            Some("KICK") => kick::handle(me, from, args, ctx, db),
            Some("BADWORDS") => badwords::handle(me, from, args, ctx, db),
            Some("COPY") => copy::handle(me, from, args, ctx, db),
            Some("TRIGGER") => trigger::handle(me, from, args, ctx, db),
            Some("BOTSTATS") | Some("STATS") => stats::handle(me, from, args, ctx, net, db),
            Some("HELP") | None => ctx.notice(me, from.uid, "BotServ keeps service bots for your channels: \x02ASSIGN\x02 <#channel> <bot> puts a bot in your channel, \x02UNASSIGN\x02 <#channel> removes it, \x02INFO\x02 <bot|#channel> shows details, \x02SAY\x02/\x02ACT\x02 <#channel> <text> speaks through the bot, \x02SET\x02 <#channel> GREET <on|off> toggles greets, \x02KICK\x02 <#channel> <type> <on|off> configures kickers (with \x02TEST\x02/\x02WARN\x02/\x02TTB\x02), \x02BADWORDS\x02 and \x02TRIGGER\x02 <#channel> ADD|DEL|LIST manage badword regexes and auto-responses, \x02COPY\x02 <#src> <#dst> clones settings. Operators also have \x02BOT\x02 ADD|CHANGE|DEL|LIST."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}
