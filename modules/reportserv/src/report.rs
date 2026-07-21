use echo_api::{t, NetView, Sender, ServiceCtx, Store};

// REPORT <nick|#channel> <reason>: file an abuse report. Rate-limited.
pub fn handle(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let Some((&target, reason_words)) = rest.split_first() else {
        ctx.notice(me, from.uid, "Syntax: REPORT <nick|#channel> <reason>");
        return;
    };
    if reason_words.is_empty() {
        ctx.notice(me, from.uid, "Please say what the problem is: REPORT <nick|#channel> <reason>");
        return;
    }
    let reason = reason_words.join(" ");
    let reporter = from.account.unwrap_or(from.nick);
    // Rate-limit on the real host, not the (spoofable) nick a flooder could cycle to
    // reset the cooldown. Anonymous reports still work; the host anchors the limit.
    // Rate-limit by host; fall back to the nick, never the uid (a uid is per-connection,
    // so keying on it would reset the cooldown on every reconnect).
    let cooldown_key = net.host_of(from.uid).unwrap_or(from.nick);
    match db.report_file(reporter, cooldown_key, target, &reason) {
        Some(id) => ctx.notice(me, from.uid, t!(ctx, "Thanks — your report (\x02#{id}\x02) about \x02{target}\x02 has been sent to the staff.", id = id, target = target)),
        None => ctx.notice(me, from.uid, "You just filed a report — please wait a moment before filing another."),
    }
}
