use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};
use fedserv_api::NetView;

// OP/DEOP/VOICE/DEVOICE <#channel> [nick]: set a status mode on a user (self if
// no nick given). `mode` is the mode to apply, e.g. "+o".
pub fn handle(me: &str, from: &Sender, mode: &str, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
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
    // PEACE only guards removing status (-o/-v) from an equal-or-higher user.
    if mode.starts_with('-') && super::peace_blocks(me, from, chan, &target, ctx, net, db) {
        return;
    }
    ctx.channel_mode(me, chan, &format!("{mode} {target}"));
}
