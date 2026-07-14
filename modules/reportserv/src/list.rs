use echo_api::{Sender, ServiceCtx, Store};

// LIST [ALL]: operators list the open reports (or every report with ALL).
pub fn handle(me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let open_only = !arg.is_some_and(|a| a.eq_ignore_ascii_case("ALL"));
    let reports = db.reports(open_only);
    if reports.is_empty() {
        ctx.notice(me, from.uid, if open_only { "No open reports." } else { "No reports." });
        return;
    }
    for r in &reports {
        let flag = if r.open { "" } else { " (closed)" };
        let short: String = r.reason.chars().take(60).collect();
        ctx.notice(me, from.uid, format!("\x02#{}\x02 {} → \x02{}\x02: {}{}", r.id, r.reporter, r.target, short, flag));
    }
    ctx.notice(me, from.uid, format!("{} report(s). \x02VIEW\x02 <id> for detail.", reports.len()));
}
