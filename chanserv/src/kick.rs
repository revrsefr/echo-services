use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};
use fedserv_api::NetView;

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
        ctx.notice(me, from.uid, format!("\x02{nick}\x02 isn't here."));
        return;
    };
    let reason = if args.len() > 3 { args[3..].join(" ") } else { "Kicked".to_string() };
    ctx.kick(me, chan, target, &reason);
}
