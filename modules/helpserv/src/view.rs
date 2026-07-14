use fedserv_api::{human_time, Sender, ServiceCtx, Store};

// VIEW <id> (aka READ): operators read a ticket in full.
pub fn handle(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(t) = id.and_then(|n| n.parse::<u64>().ok()).and_then(|n| db.help_ticket(n)) else {
        ctx.notice(me, from.uid, "No such ticket. Syntax: VIEW <id>");
        return;
    };
    let state = if !t.open { "closed" } else if t.handler.is_some() { "taken" } else { "open" };
    ctx.notice(me, from.uid, format!("Ticket \x02#{}\x02 ({state}):", t.id));
    ctx.notice(me, from.uid, format!("  From    : \x02{}\x02", t.requester));
    if let Some(h) = &t.handler {
        ctx.notice(me, from.uid, format!("  Handler : \x02{h}\x02"));
    }
    ctx.notice(me, from.uid, format!("  Opened  : {}", human_time(t.ts)));
    ctx.notice(me, from.uid, format!("  Message : {}", t.message));
}
