use echo_api::{Sender, ServiceCtx, Store};

// INFO: a summary of your mailbox (total, unread, capacity).
pub fn handle(me: &str, from: &Sender, account: &str, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let total = db.memo_list(account).len();
    let unread = db.unread_memos(account);
    ctx.notice(
        me,
        from.uid,
        echo_api::plural!(ctx, total, one = "You have \x02{total}\x02 memo, \x02{unread}\x02 unread, of a maximum \x02{max}\x02.", other = "You have \x02{total}\x02 memos, \x02{unread}\x02 unread, of a maximum \x02{max}\x02.", total = total, unread = unread, max = super::MAX_MEMOS),
    );
}
