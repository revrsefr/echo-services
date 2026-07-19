use echo_api::Store;
use echo_api::{status_mode, Sender, ServiceCtx};
use echo_api::NetView;
use echo_api::t;

// ENFORCE <#channel>: re-apply the channel's settings to everyone present —
// the mode lock, access status modes, and the auto-kick list.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: ENFORCE <#channel>");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    let Some(info) = db.channel(chan) else {
        return;
    };
    ctx.channel_mode(me, chan, &info.lock_modes());
    // Re-assert the bans for extbans the ircd enforces (echo can't match them itself).
    for k in &info.akick {
        if echo_api::ircd_enforced(&k.mask) {
            ctx.channel_mode(me, chan, &format!("+b {}", k.mask));
        }
    }
    let members: Vec<String> = net.channel_members(chan);
    for uid in members {
        match net.account_of(&uid).and_then(|a| info.join_mode(a)) {
            Some(m) => ctx.channel_mode(me, chan, &status_mode(m, &uid)),
            None => {
                if let Some(k) = net.ban_target(&uid).and_then(|t| info.akick_match(&t)) {
                    ctx.channel_mode(me, chan, &format!("+b {}", k.mask));
                    let reason = if k.reason.is_empty() { "You are banned from this channel." } else { &k.reason };
                    ctx.kick(me, chan, &uid, reason);
                }
            }
        }
    }
    ctx.notice(me, from.uid, t!(ctx, "Re-applied \x02{chan}\x02's settings to everyone present.", chan = chan));
}
