use echo_api::{t, Sender, ServiceCtx, Store};

// WAITING: pending vhost requests awaiting approval. Operators only.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let requests = db.vhost_requests();
    if requests.is_empty() {
        ctx.notice(me, from.uid, "No vhost requests are waiting.");
        return;
    }
    ctx.notice(me, from.uid, t!(ctx, "Pending vhost requests ({count}):", count = requests.len()));
    for (account, host) in &requests {
        ctx.notice(me, from.uid, t!(ctx, "  \x02{account}\x02 — {host}", account = account, host = host));
    }
    ctx.notice(me, from.uid, "Approve with \x02ACTIVATE\x02 <account> or turn down with \x02REJECT\x02 <account>.");
}
