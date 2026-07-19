use echo_api::{human_time, t, NetView, Priv, Sender, ServiceCtx};

// LOGSEARCH [pattern]: search the recent action log — every kick, kill, ban,
// registration/drop, akill, suspension, vhost, note, and so on. A bare id (as
// stamped into a kick reason, e.g. from `[#3F]`) or any word from the summary
// matches; no argument lists the most recent. Read-only, so any operator who can
// see hidden info (Priv::Auspex) may run it.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    if !from.privs.has(Priv::Auspex) {
        ctx.notice(me, from.uid, "Access denied — LOGSEARCH needs the \x02auspex\x02 privilege.");
        return;
    }
    let pattern = args[1..].join(" ");
    let hits = net.search_incidents(&pattern, 20);
    if hits.is_empty() {
        ctx.notice(me, from.uid, "No matching log entries.");
        return;
    }
    for h in &hits {
        ctx.notice(me, from.uid, t!(ctx, "[\x02#{id}\x02] {when} — {summary}", id = h.id, when = human_time(h.ts), summary = h.summary));
    }
    ctx.notice(me, from.uid, t!(ctx, "End of results ({count} shown, newest first — refine the search to narrow).", count = hits.len()));
}
