use fedserv_api::{Sender, ServiceCtx, Store};

// CANCEL: withdraw your own newest open ticket.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let who = from.account.unwrap_or(from.nick);
    let mine = db.help_tickets(true).into_iter().find(|t| t.requester.eq_ignore_ascii_case(who));
    match mine {
        Some(t) => {
            db.help_close(t.id);
            ctx.notice(me, from.uid, format!("Your request \x02#{}\x02 has been cancelled.", t.id));
        }
        None => ctx.notice(me, from.uid, "You have no open request to cancel."),
    }
}
