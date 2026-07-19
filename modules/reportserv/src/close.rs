use echo_api::{t, Sender, ServiceCtx, Store};

// CLOSE <id> (aka RESOLVE): mark a report resolved.
pub fn handle(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = id.and_then(|n| n.parse::<u64>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: CLOSE <id>");
        return;
    };
    if db.report_close(n) {
        ctx.notice(me, from.uid, t!(ctx, "Report \x02#{n}\x02 closed.", n = n));
    } else {
        ctx.notice(me, from.uid, t!(ctx, "Report \x02#{n}\x02 isn't open (or doesn't exist).", n = n));
    }
}
