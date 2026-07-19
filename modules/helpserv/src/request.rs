use echo_api::{Sender, ServiceCtx, Store};

// REQUEST <message> (aka HELPME): open a help-desk ticket for the staff.
pub fn handle(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let message = rest.join(" ");
    if message.trim().is_empty() {
        ctx.notice(me, from.uid, "Tell us what you need help with: REQUEST <message>");
        return;
    }
    // Require identification, so the cooldown keys on a stable account rather than a
    // spoofable nick a flooder can cycle to reset it.
    let Some(requester) = from.account else {
        ctx.notice(me, from.uid, "Please identify to NickServ before opening a ticket.");
        return;
    };
    match db.help_request(requester, &message) {
        Some(id) => ctx.notice(me, from.uid, format!("Thanks — your request (\x02#{id}\x02) is in the queue. A staff member will be with you.")),
        None => ctx.notice(me, from.uid, "You just opened a ticket — please wait a moment before opening another."),
    }
}
