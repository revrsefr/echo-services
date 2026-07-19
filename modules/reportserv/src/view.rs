use echo_api::{human_time, t, Sender, ServiceCtx, Store};

// VIEW <id> (aka READ): operators read a report in full.
pub fn handle(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(r) = id.and_then(|n| n.parse::<u64>().ok()).and_then(|n| db.report(n)) else {
        ctx.notice(me, from.uid, "No such report. Syntax: VIEW <id>");
        return;
    };
    ctx.notice(me, from.uid, t!(ctx, "Report \x02#{id}\x02 ({state}):", id = r.id, state = if r.open { "open" } else { "closed" }));
    ctx.notice(me, from.uid, t!(ctx, "  By       : \x02{by}\x02", by = r.reporter));
    ctx.notice(me, from.uid, t!(ctx, "  About    : \x02{target}\x02", target = r.target));
    ctx.notice(me, from.uid, t!(ctx, "  Filed    : {when}", when = human_time(r.ts)));
    ctx.notice(me, from.uid, t!(ctx, "  Reason   : {reason}", reason = r.reason));
}
