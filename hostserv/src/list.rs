use fedserv_api::{Sender, ServiceCtx, Store};

// LIST: every account with an assigned vhost. Operators only.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let vhosts = db.vhosts();
    if vhosts.is_empty() {
        ctx.notice(me, from.uid, "No vhosts have been assigned.");
        return;
    }
    ctx.notice(me, from.uid, format!("Assigned vhosts ({}):", vhosts.len()));
    for v in &vhosts {
        ctx.notice(me, from.uid, format!("  \x02{}\x02 — {} (by {})", v.account, v.host, v.setter));
    }
}
