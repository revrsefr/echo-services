use echo_api::{Sender, ServiceCtx, Store};

// REPORT <nick|#channel> <reason>: file an abuse report. Rate-limited.
pub fn handle(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some((&target, reason_words)) = rest.split_first() else {
        ctx.notice(me, from.uid, "Syntax: REPORT <nick|#channel> <reason>");
        return;
    };
    if reason_words.is_empty() {
        ctx.notice(me, from.uid, "Please say what the problem is: REPORT <nick|#channel> <reason>");
        return;
    }
    let reason = reason_words.join(" ");
    // Require identification, so the cooldown keys on a stable account rather than a
    // spoofable nick a flooder can cycle to reset it.
    let Some(reporter) = from.account else {
        ctx.notice(me, from.uid, "Please identify to NickServ before filing a report.");
        return;
    };
    match db.report_file(reporter, target, &reason) {
        Some(id) => ctx.notice(me, from.uid, format!("Thanks — your report (\x02#{id}\x02) about \x02{target}\x02 has been sent to the staff.")),
        None => ctx.notice(me, from.uid, "You just filed a report — please wait a moment before filing another."),
    }
}
