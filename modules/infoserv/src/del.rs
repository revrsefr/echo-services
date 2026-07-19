use echo_api::{t, NewsKind, Priv, Sender, ServiceCtx, Store};

// DEL/ODEL <number>: remove a bulletin by its listed position. Admin only.
pub fn handle(me: &str, from: &Sender, kind: NewsKind, num: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — that command is for services operators.");
        return;
    }
    let which = if kind == super::OPER { "oper" } else { "public" };
    let Some(n) = num.and_then(|n| n.parse::<usize>().ok()) else {
        ctx.notice(me, from.uid, t!(ctx, "Syntax: {cmd} <number>", cmd = if kind == super::OPER { "ODEL" } else { "DEL" }));
        return;
    };
    match db.news(kind).get(n.wrapping_sub(1)) {
        Some(item) if n >= 1 => {
            db.news_del(item.id);
            ctx.notice(me, from.uid, t!(ctx, "Removed \x02{which}\x02 bulletin \x02{n}\x02.", which = which, n = n));
        }
        _ => ctx.notice(me, from.uid, t!(ctx, "There's no \x02{which}\x02 bulletin \x02{n}\x02.", which = which, n = n)),
    }
}
