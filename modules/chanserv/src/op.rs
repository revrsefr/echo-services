use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;
use echo_api::t;

// OP/DEOP/VOICE/DEVOICE <#channel> [nick]: set a status mode on a user (self if
// no nick given). `mode` is the mode to apply, e.g. "+o".
pub fn handle(me: &str, from: &Sender, mode: &str, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: OP/DEOP/VOICE/DEVOICE <#channel> [nick]");
        return;
    };
    // Granting owner (+q) is founder-only; op/halfop/protect need op access.
    let allowed = if mode.contains('q') {
        super::require_founder(me, from, chan, ctx, db)
    } else {
        super::require_op(me, from, chan, ctx, db)
    };
    if !allowed {
        return;
    }
    let target = match args.get(2) {
        Some(&nick) => match net.uid_by_nick(nick) {
            Some(u) => u.to_string(),
            None => {
                ctx.notice(me, from.uid, t!(ctx, "\x02{nick}\x02 isn't here.", nick = nick));
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
