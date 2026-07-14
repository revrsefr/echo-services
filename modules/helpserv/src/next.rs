use fedserv_api::{Sender, ServiceCtx, Store};

// NEXT: claim the oldest unassigned ticket.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    match db.help_next_open() {
        Some(id) => super::take_id(me, from, id, ctx, db),
        None => ctx.notice(me, from.uid, "No unassigned tickets are waiting."),
    }
}
