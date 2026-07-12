use crate::engine::db::Db;
use crate::engine::service::{Sender, ServiceCtx};
use crate::engine::state::Network;

// OP/DEOP/VOICE/DEVOICE <#channel> [nick]: set a status mode on a user (self if
// no nick given). `mode` is the mode to apply, e.g. "+o".
pub fn handle(me: &str, from: &Sender, mode: &str, args: &[&str], ctx: &mut ServiceCtx, net: &Network, db: &Db) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: OP/DEOP/VOICE/DEVOICE <#channel> [nick]");
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
    ctx.channel_mode(me, chan, &format!("{mode} {target}"));
}
