//! BotServ registers service bots — pseudo-clients that get assigned to channels
//! and (in later slices) run fantasy commands. `lib.rs` holds the dispatcher;
//! each command lives in its own file, matching NickServ/ChanServ.

use fedserv_api::{NetView, Sender, Service, ServiceCtx, Store};

#[path = "bot.rs"]
mod bot;
#[path = "assign.rs"]
mod assign;

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

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("BOT") => bot::handle(me, from, args, ctx, db),
            Some("ASSIGN") => assign::handle(me, from, args, ctx, db, true),
            Some("UNASSIGN") => assign::handle(me, from, args, ctx, db, false),
            Some("HELP") | None => ctx.notice(me, from.uid, "BotServ keeps service bots for your channels: \x02ASSIGN\x02 <#channel> <bot> puts a bot in your channel, \x02UNASSIGN\x02 <#channel> removes it. Operators also have \x02BOT\x02 ADD|DEL|LIST."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}
