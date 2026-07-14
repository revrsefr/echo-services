use echo_api::{Priv, Sender, ServiceCtx, Store};

// ASSIGN <#channel> <bot> / UNASSIGN <#channel>: put a bot in a channel (or take
// it out). Channel founder only (or a services admin).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store, assigning: bool) {
    let Some(&chan) = args.get(1) else {
        let syntax = if assigning { "Syntax: ASSIGN <#channel> <bot>" } else { "Syntax: UNASSIGN <#channel>" };
        ctx.notice(me, from.uid, syntax);
        return;
    };
    if !super::require_channel_admin(me, from, chan, ctx, db) {
        return;
    }
    // NOBOT reserves (un)assignment for services operators.
    let is_admin = from.privs.has(Priv::Admin);
    if !is_admin && db.channel(chan).is_some_and(|c| c.nobot) {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 is set \x02NOBOT\x02 — only a services operator can change its bot."));
        return;
    }
    if !assigning {
        match db.unassign_bot(chan) {
            Ok(true) => ctx.notice(me, from.uid, format!("The bot has left \x02{chan}\x02.")),
            Ok(false) => ctx.notice(me, from.uid, format!("\x02{chan}\x02 has no bot assigned.")),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        }
        return;
    }
    let Some(&bot) = args.get(2) else {
        ctx.notice(me, from.uid, "Syntax: ASSIGN <#channel> <bot>");
        return;
    };
    let Some(target) = db.bots().into_iter().find(|b| b.nick.eq_ignore_ascii_case(bot)) else {
        ctx.notice(me, from.uid, format!("There's no bot named \x02{bot}\x02. See \x02BOT LIST\x02."));
        return;
    };
    if target.private && !is_admin {
        ctx.notice(me, from.uid, format!("Bot \x02{}\x02 is private — only a services operator can assign it.", target.nick));
        return;
    }
    let botnick = target.nick;
    match db.assign_bot(chan, &botnick) {
        Ok(()) => ctx.notice(me, from.uid, format!("Bot \x02{botnick}\x02 is now assigned to \x02{chan}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
