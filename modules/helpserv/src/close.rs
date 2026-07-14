use echo_api::{Sender, ServiceCtx, Store};

// CLOSE <id> (aka RESOLVE): resolve a ticket.
pub fn handle(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = id.and_then(|n| n.parse::<u64>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: CLOSE <id>");
        return;
    };
    if db.help_close(n) {
        ctx.notice(me, from.uid, format!("Ticket \x02#{n}\x02 closed."));
    } else {
        ctx.notice(me, from.uid, format!("Ticket \x02#{n}\x02 isn't open (or doesn't exist)."));
    }
}
