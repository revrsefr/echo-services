use echo_api::{t, Sender, ServiceCtx, Store};

// DEL <id> (aka REMOVE): delete a report outright.
pub fn handle(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = id.and_then(|n| n.parse::<u64>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: DEL <id>");
        return;
    };
    if db.report_del(n) {
        ctx.notice(me, from.uid, t!(ctx, "Report \x02#{n}\x02 deleted.", n = n));
    } else {
        ctx.notice(me, from.uid, t!(ctx, "There's no report \x02#{n}\x02.", n = n));
    }
}
