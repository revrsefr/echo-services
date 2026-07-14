use fedserv_api::{Sender, ServiceCtx, Store};

// TAKE <id> (aka ASSIGN): claim a specific ticket.
pub fn handle(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = id.and_then(|n| n.parse::<u64>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: TAKE <id>");
        return;
    };
    super::take_id(me, from, n, ctx, db);
}
