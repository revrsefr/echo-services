use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};

// TOPIC <#channel> <text>: set the channel topic (empty clears it).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: TOPIC <#channel> <text>");
        return;
    };
    if !super::require_op(me, from, chan, ctx, db) {
        return;
    }
    let text = if args.len() > 2 { args[2..].join(" ") } else { String::new() };
    ctx.topic(me, chan, &text);
    ctx.notice(me, from.uid, format!("Topic for \x02{chan}\x02 updated."));
}
