use echo_api::{human_time, Sender, ServiceCtx, Store};

// VIEW <id> (aka READ): operators read a report in full.
pub fn handle(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(r) = id.and_then(|n| n.parse::<u64>().ok()).and_then(|n| db.report(n)) else {
        ctx.notice(me, from.uid, "No such report. Syntax: VIEW <id>");
        return;
    };
    ctx.notice(me, from.uid, format!("Report \x02#{}\x02 ({}):", r.id, if r.open { "open" } else { "closed" }));
    ctx.notice(me, from.uid, format!("  By       : \x02{}\x02", r.reporter));
    ctx.notice(me, from.uid, format!("  About    : \x02{}\x02", r.target));
    ctx.notice(me, from.uid, format!("  Filed    : {}", human_time(r.ts)));
    ctx.notice(me, from.uid, format!("  Reason   : {}", r.reason));
}
