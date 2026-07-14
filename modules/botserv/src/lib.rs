//! BotServ registers service bots — pseudo-clients that get assigned to channels
//! and (in later slices) run fantasy commands. `lib.rs` holds the dispatcher;
//! each command lives in its own file, matching NickServ/ChanServ.

use echo_api::{HelpEntry, NetView, Priv, Sender, Service, ServiceCtx, Store};

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

const BLURB: &str = "BotServ keeps service bots for your channels: assign a bot, speak through it, and configure kickers, badwords, and triggers.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "ASSIGN", summary: "put a bot in a channel", detail: "Syntax: \x02ASSIGN <#channel> <bot>\x02\nPuts a service bot in your channel." },
    HelpEntry { cmd: "UNASSIGN", summary: "remove a channel's bot", detail: "Syntax: \x02UNASSIGN <#channel>\x02\nRemoves the assigned bot from your channel." },
    HelpEntry { cmd: "INFO", summary: "show bot/channel settings", detail: "Syntax: \x02INFO <bot | #channel>\x02\nShows a bot's details or a channel's bot settings." },
    HelpEntry { cmd: "SAY", summary: "speak through the bot", detail: "Syntax: \x02SAY <#channel> <text>\x02\nSays a line as the channel's bot." },
    HelpEntry { cmd: "ACT", summary: "action through the bot", detail: "Syntax: \x02ACT <#channel> <text>\x02\nSends a /me action as the channel's bot." },
    HelpEntry { cmd: "SET", summary: "configure bot behavior", detail: "Syntax: \x02SET <#channel> <GREET|BANEXPIRE|NOBOT|VOTEKICK> <value>\x02, or \x02SET <bot> PRIVATE <ON|OFF>\x02\nConfigures a channel's bot behavior, or marks a bot private." },
    HelpEntry { cmd: "KICK", summary: "configure kickers", detail: "Syntax: \x02KICK <#channel> <CAPS|FLOOD|REPEAT|BADWORDS|...> <ON|OFF> [params]\x02, or \x02KICK <#channel> TTB <n> | TEST <message>\x02\nConfigures a channel's automatic kickers." },
    HelpEntry { cmd: "BADWORDS", summary: "manage badword patterns", detail: "Syntax: \x02BADWORDS <#channel> ADD|DEL|LIST|CLEAR [pattern]\x02\nManages the channel's badword patterns." },
    HelpEntry { cmd: "TRIGGER", summary: "manage auto-responses", detail: "Syntax: \x02TRIGGER <#channel> ADD <regex>|<response>[|<cooldown>] | DEL <num> | LIST | CLEAR\x02\nManages the channel's auto-response triggers." },
    HelpEntry { cmd: "COPY", summary: "clone bot settings", detail: "Syntax: \x02COPY <#source> <#dest>\x02\nClones a channel's bot settings to another channel." },
    HelpEntry { cmd: "BOT", summary: "manage the bots (operator)", detail: "Syntax: \x02BOT ADD|CHANGE|DEL|LIST\x02\nCreates and manages the service bots themselves. Operators only." },
];

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
            Some("HELP") | None => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}
