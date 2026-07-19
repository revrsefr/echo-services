use echo_api::{t, Priv, Sender, ServiceCtx, Store};

// AUTOASSIGN <bot> | OFF: set the bot automatically assigned to every newly
// registered channel, or turn auto-assignment off. Oper-only (Priv::Admin) —
// it's a network-wide default. No argument reports the current setting.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — AUTOASSIGN is for services operators.");
        return;
    }
    let Some(&arg) = args.get(1) else {
        match db.default_bot() {
            Some(bot) => ctx.notice(me, from.uid, t!(ctx, "New channels are auto-assigned \x02{bot}\x02. Use \x02AUTOASSIGN OFF\x02 to stop.", bot = bot)),
            None => ctx.notice(me, from.uid, "No bot is auto-assigned to new channels. Set one with \x02AUTOASSIGN <bot>\x02."),
        }
        return;
    };
    if arg.eq_ignore_ascii_case("OFF") || arg.eq_ignore_ascii_case("NONE") {
        match db.set_default_bot(None) {
            Ok(()) => ctx.notice(me, from.uid, "New channels will no longer be auto-assigned a bot."),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        }
        return;
    }
    // Store the bot's canonical nick, so the setting survives a re-cased lookup.
    let Some(bot) = db.bots().into_iter().find(|b| b.nick.eq_ignore_ascii_case(arg)) else {
        ctx.notice(me, from.uid, t!(ctx, "There's no bot named \x02{nick}\x02. See \x02BOTLIST\x02.", nick = arg));
        return;
    };
    match db.set_default_bot(Some(&bot.nick)) {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "New channels will be auto-assigned \x02{nick}\x02.", nick = bot.nick)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
