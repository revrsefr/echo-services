use crate::engine::db::Store;
use crate::engine::service::{Sender, ServiceCtx};
use crate::engine::state::NetView;

// INVITE <#channel> [nick]: invite a user (self if no nick) into the channel.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: INVITE <#channel> [nick]");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    let target = match args.get(2) {
        Some(&nick) => match net.uid_by_nick(nick) {
            Some(u) => u.to_string(),
            None => {
                ctx.notice(me, from.uid, format!("\x02{nick}\x02 isn't here."));
                return;
            }
        },
        None => from.uid.to_string(),
    };
    ctx.invite(me, &target, chan);
    ctx.notice(me, from.uid, format!("Invited to \x02{chan}\x02."));
}
