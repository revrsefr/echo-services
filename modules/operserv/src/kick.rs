use fedserv_api::{NetView, Priv, Sender, ServiceCtx};

// KICK <#channel> <nick> [reason]: remove a user from a channel, sourced from
// OperServ so it's clearly a staff action. Admin-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — KICK needs the \x02admin\x02 privilege.");
        return;
    }
    let Some(&chan) = args.get(1).filter(|c| c.starts_with('#') || c.starts_with('&')) else {
        ctx.notice(me, from.uid, "Syntax: KICK <#channel> <nick> [reason]");
        return;
    };
    let Some(&target) = args.get(2) else {
        ctx.notice(me, from.uid, "Syntax: KICK <#channel> <nick> [reason]");
        return;
    };
    let Some(uid) = net.uid_by_nick(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("There's no \x02{target}\x02 online."));
        return;
    };
    let by = from.account.unwrap_or(from.nick);
    let reason = if args.len() > 3 { args[3..].join(" ") } else { "Removed by services".to_string() };
    ctx.kick(me, chan, &uid, &format!("({by}) {reason}"));
    ctx.notice(me, from.uid, format!("\x02{target}\x02 kicked from \x02{chan}\x02."));
}
