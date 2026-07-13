use fedserv_api::{Sender, ServiceCtx, Store};

// COPY <#source> <#dest>: copy a channel's bot configuration — kickers,
// badwords, greet and nobot — onto another. Requires founder-or-admin on both.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(&src), Some(&dst)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: COPY <#source> <#dest>");
        return;
    };
    if !super::require_channel_admin(me, from, src, ctx, db) || !super::require_channel_admin(me, from, dst, ctx, db) {
        return;
    }
    match db.copy_bot_config(src, dst) {
        Ok(()) => ctx.notice(me, from.uid, format!("Copied \x02{src}\x02's bot settings (kickers, badwords, greet, nobot) to \x02{dst}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
