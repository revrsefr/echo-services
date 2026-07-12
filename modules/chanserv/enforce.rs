use crate::engine::db::Db;
use crate::engine::service::{Sender, ServiceCtx};
use crate::engine::state::Network;

// ENFORCE <#channel>: re-apply the channel's settings to everyone present —
// the mode lock, access status modes, and the auto-kick list.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &Network, db: &Db) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: ENFORCE <#channel>");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    let Some(info) = db.channel(chan).cloned() else {
        return;
    };
    ctx.channel_mode(me, chan, &info.lock_modes());
    let members: Vec<String> = net.channel_members(chan).map(str::to_string).collect();
    for uid in members {
        match net.account_of(&uid).and_then(|a| info.join_mode(a)) {
            Some(m) => ctx.channel_mode(me, chan, &format!("{m} {uid}")),
            None => {
                let nick = net.nick_of(&uid).unwrap_or("*");
                let host = net.host_of(&uid).unwrap_or("*");
                if let Some(k) = info.akick_match(&format!("{nick}!*@{host}")) {
                    ctx.channel_mode(me, chan, &format!("+b {}", k.mask));
                    let reason = if k.reason.is_empty() { "You are banned from this channel." } else { &k.reason };
                    ctx.kick(me, chan, &uid, reason);
                }
            }
        }
    }
    ctx.notice(me, from.uid, format!("Re-applied \x02{chan}\x02's settings to everyone present."));
}
