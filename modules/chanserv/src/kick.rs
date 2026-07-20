use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;
use echo_api::t;

// KICK <#channel> <nick> [reason]: kick a user.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let (Some(&chan), Some(&nick)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: KICK <#channel> <nick> [reason]");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    let Some(target) = net.uid_by_nick(nick) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{nick}\x02 isn't here.", nick = nick));
        return;
    };
    if super::peace_blocks(me, from, chan, target, ctx, net, db) {
        return;
    }
    let mut reason = if args.len() > 3 { args[3..].join(" ") } else { "Kicked".to_string() };
    // SIGNKICK: attribute the kick to the requester. LEVEL mode signs only kicks
    // by users without op-level access, leaving trusted ops' kicks unsigned.
    if let Some(c) = db.channel(chan) {
        let kicker_op = from.account.is_some_and(|a| c.is_op(a));
        if c.signkick && (!c.signkick_level || !kicker_op) {
            reason = format!("{reason} (requested by {})", from.nick);
        }
    }
    ctx.kick(me, chan, target, &reason);
}
