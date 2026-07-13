use fedserv_api::{Sender, ServiceCtx, Store};

// INFO <bot> — describe a bot and list the channels it serves.
// INFO <#channel> — show which bot (if any) is assigned to a channel.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(&target) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: INFO <bot | #channel>");
        return;
    };

    if target.starts_with('#') {
        let Some(chan) = db.channel(target) else {
            ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
            return;
        };
        match chan.assigned_bot {
            Some(bot) => ctx.notice(me, from.uid, format!("\x02{target}\x02 is served by bot \x02{bot}\x02.")),
            None => ctx.notice(me, from.uid, format!("\x02{target}\x02 has no bot assigned. Assign one with \x02ASSIGN\x02 {target} <bot>.")),
        }
        return;
    }

    let Some(bot) = db.bots().into_iter().find(|b| b.nick.eq_ignore_ascii_case(target)) else {
        ctx.notice(me, from.uid, format!("There's no bot named \x02{target}\x02. See \x02BOT LIST\x02."));
        return;
    };
    let channels: Vec<String> = db
        .channels()
        .into_iter()
        .filter(|c| c.assigned_bot.as_deref().is_some_and(|b| b.eq_ignore_ascii_case(&bot.nick)))
        .map(|c| c.name)
        .collect();

    ctx.notice(me, from.uid, format!("Bot \x02{}\x02 — {}@{}", bot.nick, bot.user, bot.host));
    ctx.notice(me, from.uid, format!("  Real name: {}", bot.gecos));
    if channels.is_empty() {
        ctx.notice(me, from.uid, "  Not assigned to any channel.");
    } else {
        ctx.notice(me, from.uid, format!("  Serving {} channel(s): {}", channels.len(), channels.join(", ")));
    }
}
