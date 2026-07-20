use echo_api::{t, Sender, ServiceCtx, Store};

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
    ctx.notice(me, from.uid, t!(ctx, "Assigned vhosts ({count}):", count = vhosts.len()));
    for v in vhosts.iter().take(echo_api::LIST_CAP) {
        let temp = if v.expires.is_some() { t!(ctx, ", temporary") } else { String::new() };
        ctx.notice(me, from.uid, t!(ctx, "  \x02{account}\x02 — {host} (by {setter}{temp})", account = v.account, host = v.host, setter = v.setter, temp = temp));
    }
    if vhosts.len() > echo_api::LIST_CAP {
        ctx.notice(me, from.uid, t!(ctx, "… and \x02{more}\x02 more; showing the first {cap}.", more = vhosts.len() - echo_api::LIST_CAP, cap = echo_api::LIST_CAP));
    }
}
