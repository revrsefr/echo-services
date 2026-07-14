use fedserv_api::{NetView, Priv, Sender, ServiceCtx};

// KILL <nick> [reason]: disconnect a user from the network. Admin-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — KILL needs the \x02admin\x02 privilege.");
        return;
    }
    let Some(&target) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: KILL <nick> [reason]");
        return;
    };
    let Some(uid) = net.uid_by_nick(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("There's no \x02{target}\x02 online."));
        return;
    };
    let by = from.account.unwrap_or(from.nick);
    let reason = if args.len() > 2 { args[2..].join(" ") } else { "No reason given".to_string() };
    ctx.kill(me, &uid, &format!("({by}) {reason}"));
    ctx.notice(me, from.uid, format!("\x02{target}\x02 has been disconnected."));
}
