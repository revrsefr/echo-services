use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

// TOPIC <#channel> <text>: set the channel topic (empty clears it).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: TOPIC <#channel> <text>");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    let text = if args.len() > 2 { args[2..].join(" ") } else { String::new() };
    ctx.topic(me, chan, &text);
    // Persist it too: the ircd filters our own FTOPIC back out, so without this the
    // stored topic stays stale and KEEPTOPIC/TOPICLOCK restore the old one on
    // recreation/restart. Ignore NoChannel (require_op already proved it exists).
    let _ = db.set_channel_topic(chan, &text);
    ctx.notice(me, from.uid, t!(ctx, "Topic for \x02{chan}\x02 updated.", chan = chan));
}
