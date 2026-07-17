use echo_api::{NewsKind, Priv, Sender, ServiceCtx, Store};

// POST/OPOST <message>: add a bulletin (public or oper). Admin only.
pub fn handle(me: &str, from: &Sender, kind: NewsKind, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — posting bulletins is for services operators.");
        return;
    }
    let message = rest.join(" ");
    if message.trim().is_empty() {
        ctx.notice(me, from.uid, format!("Syntax: {} <message>", if kind == super::OPER { "OPOST" } else { "POST" }));
        return;
    }
    let setter = from.account.unwrap_or(from.nick);
    db.news_add(kind, &message, setter);
    let which = if kind == super::OPER { "oper" } else { "public" };
    ctx.notice(me, from.uid, format!("Added a \x02{which}\x02 bulletin."));
}
