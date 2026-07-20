use echo_api::{t, NetView, Priv, Sender, ServiceCtx, Store, XlineKind};
use std::collections::HashSet;

// CHANKILL <#channel> [reason]: AKILL every user in a channel by host, clearing
// a spam or attack channel in one shot. The G-lines the ircd applies also kill
// the matching sessions. Admin-only, and never bans the operator running it.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — CHANKILL needs the \x02admin\x02 privilege.");
        return;
    }
    let Some(&chan) = args.get(1).filter(|c| c.starts_with('#') || c.starts_with('&')) else {
        ctx.notice(me, from.uid, "Syntax: CHANKILL <#channel> [reason]");
        return;
    };
    let members = net.channel_members(chan);
    if members.is_empty() {
        ctx.notice(me, from.uid, t!(ctx, "No one is in \x02{chan}\x02 (or it isn't tracked).", chan = chan));
        return;
    }
    let reason = if args.len() > 2 { args[2..].join(" ") } else { "Channel cleared by services".to_string() };
    let setter = from.account.unwrap_or(from.nick);
    let mut seen: HashSet<String> = HashSet::new();
    let mut banned = 0;
    for uid in &members {
        if uid.as_str() == from.uid {
            continue; // never ban yourself
        }
        let Some(host) = net.host_of(uid) else { continue };
        if seen.insert(host.to_string()) {
            let mask = format!("*@{host}");
            let _ = db.akill_add(XlineKind::Gline, &mask, setter, &reason, None);
            ctx.add_line(XlineKind::Gline, &mask, from.nick, 0, &reason);
            banned += 1;
        }
    }
    ctx.notice(me, from.uid, echo_api::plural!(ctx, banned, one = "CHANKILL on \x02{chan}\x02: \x02{banned}\x02 host AKILL'd.", other = "CHANKILL on \x02{chan}\x02: \x02{banned}\x02 hosts AKILL'd.", chan = chan, banned = banned));
}
