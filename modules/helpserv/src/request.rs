use echo_api::{t, NetView, Sender, ServiceCtx, Store};

// REQUEST <message> (aka HELPME): open a help-desk ticket for the staff.
pub fn handle(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let message = rest.join(" ");
    if message.trim().is_empty() {
        ctx.notice(me, from.uid, "Tell us what you need help with: REQUEST <message>");
        return;
    }
    let requester = from.account.unwrap_or(from.nick);
    // Rate-limit on the real host, not the spoofable nick (see REPORT).
    let cooldown_key = net.host_of(from.uid).unwrap_or(from.uid);
    match db.help_request(requester, cooldown_key, &message) {
        Some(id) => ctx.notice(me, from.uid, t!(ctx, "Thanks — your request (\x02#{id}\x02) is in the queue. A staff member will be with you.", id = id)),
        None => ctx.notice(me, from.uid, "You just opened a ticket — please wait a moment before opening another."),
    }
}
