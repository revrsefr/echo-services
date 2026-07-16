use echo_api::{NetView, Priv, Sender, ServiceCtx};

// SVSNICK <nick> <newnick>: force a user to change nick. Admin-only.
pub fn nick(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — SVSNICK needs the \x02admin\x02 privilege.");
        return;
    }
    let (Some(&target), Some(&newnick)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: SVSNICK <nick> <newnick>");
        return;
    };
    if newnick.is_empty() || newnick.starts_with('#') || newnick.contains(|c: char| c.is_whitespace() || c == ',') {
        ctx.notice(me, from.uid, format!("\x02{newnick}\x02 isn't a valid nick."));
        return;
    }
    let Some(uid) = net.uid_by_nick(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("There's no \x02{target}\x02 online."));
        return;
    };
    ctx.force_nick(&uid, newnick);
    ctx.notice(me, from.uid, format!("\x02{target}\x02 has been renamed to \x02{newnick}\x02."));
}

// SVSJOIN <nick> <#channel> [key]: force a user into a channel. Admin-only.
pub fn join(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — SVSJOIN needs the \x02admin\x02 privilege.");
        return;
    }
    let (Some(&target), Some(&chan)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: SVSJOIN <nick> <#channel> [key]");
        return;
    };
    if !chan.starts_with('#') && !chan.starts_with('&') {
        ctx.notice(me, from.uid, "SVSJOIN targets a channel.");
        return;
    }
    let Some(uid) = net.uid_by_nick(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("There's no \x02{target}\x02 online."));
        return;
    };
    ctx.force_join(&uid, chan, args.get(3).copied().unwrap_or(""));
    ctx.notice(me, from.uid, format!("\x02{target}\x02 has been joined to \x02{chan}\x02."));
}

// SVSPART <nick> <#channel> [reason]: force a user out of a channel. Admin-only.
pub fn part(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — SVSPART needs the \x02admin\x02 privilege.");
        return;
    }
    let (Some(&target), Some(&chan)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: SVSPART <nick> <#channel> [reason]");
        return;
    };
    if !chan.starts_with('#') && !chan.starts_with('&') {
        ctx.notice(me, from.uid, "SVSPART targets a channel.");
        return;
    }
    let Some(uid) = net.uid_by_nick(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("There's no \x02{target}\x02 online."));
        return;
    };
    let reason = if args.len() > 3 { args[3..].join(" ") } else { "Removed by services".to_string() };
    ctx.force_part(&uid, chan, &reason);
    ctx.notice(me, from.uid, format!("\x02{target}\x02 has been removed from \x02{chan}\x02."));
}
