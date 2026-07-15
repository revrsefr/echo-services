use echo_api::{Sender, ServiceCtx, Store};

// INFO: a summary of your mailbox (total, unread, capacity).
pub fn handle(me: &str, from: &Sender, account: &str, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let total = db.memo_list(account).len();
    let unread = db.unread_memos(account);
    ctx.notice(
        me,
        from.uid,
        format!("You have \x02{total}\x02 memo(s), \x02{unread}\x02 unread, of a maximum \x02{}\x02.", super::MAX_MEMOS),
    );
}
