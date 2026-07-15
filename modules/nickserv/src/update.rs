use echo_api::{Sender, ServiceCtx, Store};

// UPDATE: re-apply your account's auto-joins and vhost, and re-check for waiting
// memos, without having to re-identify.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    for entry in db.ajoin_list(account) {
        ctx.force_join(from.uid, &entry.channel, &entry.key);
    }
    if let Some(v) = db.vhost(account) {
        ctx.apply_vhost(from.uid, &v.host);
    }
    let unread = db.unread_memos(account);
    if unread > 0 {
        ctx.notice(me, from.uid, format!("You have \x02{unread}\x02 new memo(s). Read them with \x02/msg MemoServ READ NEW\x02."));
    }
    ctx.notice(me, from.uid, "Your status has been refreshed.");
}
