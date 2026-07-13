use crate::engine::db::Store;
use crate::engine::service::{Sender, ServiceCtx};
use crate::engine::state::NetView;

// BAN <#channel> <nick> [reason]: ban *!*@host and kick the user.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let (Some(&chan), Some(&nick)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: BAN <#channel> <nick> [reason]");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    let Some(target) = net.uid_by_nick(nick).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{nick}\x02 isn't here."));
        return;
    };
    let host = net.host_of(&target).unwrap_or("*");
    ctx.channel_mode(me, chan, &format!("+b *!*@{host}"));
    let reason = if args.len() > 3 { args[3..].join(" ") } else { "Banned".to_string() };
    ctx.kick(me, chan, &target, &reason);
}
