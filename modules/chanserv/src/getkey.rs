use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;

// GETKEY <#channel>: report the channel key (+k), for ops who need to let
// someone in.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: GETKEY <#channel>");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    match net.channel_key(chan) {
        Some(key) => ctx.notice(me, from.uid, format!("Key for \x02{chan}\x02 is \x02{key}\x02.")),
        None => ctx.notice(me, from.uid, format!("\x02{chan}\x02 has no key set.")),
    }
}
