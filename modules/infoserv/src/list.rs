use echo_api::{Sender, ServiceCtx, Store};

// LIST/OLIST: show the bulletins of a kind. Public is open; oper is oper-only.
pub fn handle(me: &str, from: &Sender, kind: &str, oper_only: bool, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if oper_only && !from.privs.any() {
        ctx.notice(me, from.uid, "Access denied — oper bulletins are for services operators.");
        return;
    }
    let items = db.news(kind);
    let which = if kind == super::OPER { "oper" } else { "public" };
    if items.is_empty() {
        ctx.notice(me, from.uid, format!("There are no {which} bulletins."));
        return;
    }
    for (i, item) in items.iter().enumerate() {
        ctx.notice(me, from.uid, format!("{}. {} — by {}", i + 1, item.text, item.setter));
    }
    ctx.notice(me, from.uid, format!("End of {which} bulletins ({} shown).", items.len()));
}
