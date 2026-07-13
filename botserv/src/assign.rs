use fedserv_api::{Priv, Sender, ServiceCtx, Store};

// ASSIGN <#channel> <bot> / UNASSIGN <#channel>: put a bot in a channel (or take
// it out). Channel founder only (or a services admin).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store, assigning: bool) {
    let Some(&chan) = args.get(1) else {
        let syntax = if assigning { "Syntax: ASSIGN <#channel> <bot>" } else { "Syntax: UNASSIGN <#channel>" };
        ctx.notice(me, from.uid, syntax);
        return;
    };
    let Some(founder) = db.channel(chan).map(|c| c.founder) else {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
        return;
    };
    if from.account != Some(founder.as_str()) && !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can assign a bot to it."));
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
    let Some(botnick) = db.bots().into_iter().find(|b| b.nick.eq_ignore_ascii_case(bot)).map(|b| b.nick) else {
        ctx.notice(me, from.uid, format!("There's no bot named \x02{bot}\x02. See \x02BOT LIST\x02."));
        return;
    };
    match db.assign_bot(chan, &botnick) {
        Ok(()) => ctx.notice(me, from.uid, format!("Bot \x02{botnick}\x02 is now assigned to \x02{chan}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
