use echo_api::{t, Sender, ServiceCtx, Store};

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
        ctx.notice(me, from.uid, t!(ctx, "\x02#{id}\x02 {reporter} → \x02{target}\x02: {short}{flag}", id = r.id, reporter = r.reporter, target = r.target, short = short, flag = flag));
    }
    ctx.notice(me, from.uid, echo_api::plural!(ctx, reports.len(), one = "{n} report. \x02VIEW\x02 <id> for detail.", other = "{n} reports. \x02VIEW\x02 <id> for detail.", n = reports.len()));
}
