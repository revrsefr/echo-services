use echo_api::{human_time, t, Sender, ServiceCtx, Store};

// VIEW <id> (aka READ): operators read a ticket in full.
pub fn handle(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(t) = id.and_then(|n| n.parse::<u64>().ok()).and_then(|n| db.help_ticket(n)) else {
        ctx.notice(me, from.uid, "No such ticket. Syntax: VIEW <id>");
        return;
    };
    let state = if !t.open { t!(ctx, "closed") } else if t.handler.is_some() { t!(ctx, "taken") } else { t!(ctx, "open") };
    ctx.notice(me, from.uid, t!(ctx, "Ticket \x02#{id}\x02 ({state}):", id = t.id, state = state));
    ctx.notice(me, from.uid, t!(ctx, "  From    : \x02{requester}\x02", requester = t.requester));
    if let Some(h) = &t.handler {
        ctx.notice(me, from.uid, t!(ctx, "  Handler : \x02{handler}\x02", handler = h));
    }
    ctx.notice(me, from.uid, t!(ctx, "  Opened  : {when}", when = human_time(t.ts)));
    ctx.notice(me, from.uid, t!(ctx, "  Message : {msg}", msg = t.message));
}
