use echo_api::{t, NewsKind, Sender, ServiceCtx, Store};

// LIST/OLIST: show the bulletins of a kind. Public is open; oper is oper-only.
pub fn handle(me: &str, from: &Sender, kind: NewsKind, oper_only: bool, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if oper_only && !from.privs.any() {
        ctx.notice(me, from.uid, "Access denied — oper bulletins are for services operators.");
        return;
    }
    let items = db.news(kind);
    let which = if kind == super::OPER { "oper" } else { "public" };
    if items.is_empty() {
        ctx.notice(me, from.uid, t!(ctx, "There are no {which} bulletins.", which = which));
        return;
    }
    for (i, item) in items.iter().enumerate() {
        ctx.notice(me, from.uid, t!(ctx, "{num}. {text} — by {by}", num = i + 1, text = item.text, by = item.setter));
    }
    ctx.notice(me, from.uid, t!(ctx, "End of {which} bulletins ({count} shown).", which = which, count = items.len()));
}
