use echo_api::{t, NetView, Priv, Sender, ServiceCtx, Store};

// SAY <#channel> <text> — make the channel's assigned bot say something.
// ACT <#channel> <text> — the same, as a CTCP ACTION (/me).
// Requires channel-operator access (founder, op, or a services admin).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store, action: bool) {
    let verb = if action { "ACT" } else { "SAY" };
    if args.len() < 3 {
        ctx.notice(me, from.uid, t!(ctx, "Syntax: {verb} <#channel> <text>", verb = verb));
        return;
    }
    let chan = args[1];
    let text = args[2..].join(" ");

    let Some(info) = db.channel(chan) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 isn't registered.", chan = chan));
        return;
    };
    let allowed = from.privs.has(Priv::Admin) || from.account.is_some_and(|a| info.is_op(a));
    if !allowed {
        ctx.notice(me, from.uid, t!(ctx, "Access denied — you need operator access in \x02{chan}\x02.", chan = chan));
        return;
    }
    let Some(bot) = info.assigned_bot else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 has no bot assigned. Assign one with \x02ASSIGN\x02 {chan} <bot>.", chan = chan));
        return;
    };
    let Some(botuid) = net.uid_by_nick(&bot) else {
        ctx.notice(me, from.uid, t!(ctx, "Bot \x02{bot}\x02 isn't on the network right now.", bot = bot));
        return;
    };
    let botuid = botuid.to_string();
    let payload = if action { format!("\x01ACTION {text}\x01") } else { text };
    ctx.privmsg(&botuid, chan, payload);
}
