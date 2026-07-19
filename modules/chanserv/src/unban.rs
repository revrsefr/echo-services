use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;
use echo_api::t;

// UNBAN <#channel> [nick]: remove the *!*@host ban of a user (self if no nick).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: UNBAN <#channel> [nick]");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    let target = args
        .get(2)
        .and_then(|&n| net.uid_by_nick(n))
        .map(str::to_string)
        .unwrap_or_else(|| from.uid.to_string());
    let host = net.host_of(&target).unwrap_or("*");
    ctx.channel_mode(me, chan, &format!("-b *!*@{host}"));
    ctx.notice(me, from.uid, t!(ctx, "Cleared the *!*@{host} ban on \x02{chan}\x02.", host = host, chan = chan));
}
