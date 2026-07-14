use echo_api::{Sender, ServiceCtx, Store};

// LIST [ALL]: operators list the open queue (or every ticket with ALL).
pub fn handle(me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let open_only = !arg.is_some_and(|a| a.eq_ignore_ascii_case("ALL"));
    let tickets = db.help_tickets(open_only);
    if tickets.is_empty() {
        ctx.notice(me, from.uid, if open_only { "No open tickets." } else { "No tickets." });
        return;
    }
    for t in &tickets {
        let state = match (&t.handler, t.open) {
            (_, false) => " (closed)".to_string(),
            (Some(h), true) => format!(" (taken by {h})"),
            (None, true) => String::new(),
        };
        let short: String = t.message.chars().take(60).collect();
        ctx.notice(me, from.uid, format!("\x02#{}\x02 {} — {}{}", t.id, t.requester, short, state));
    }
    ctx.notice(me, from.uid, format!("{} ticket(s). \x02VIEW\x02 <id> for detail.", tickets.len()));
}
