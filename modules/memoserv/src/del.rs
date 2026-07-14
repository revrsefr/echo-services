use echo_api::{Sender, ServiceCtx, Store};

// DEL <num>|ALL: remove a memo (or the whole mailbox).
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ALL") => {
            let count = db.memo_list(account).len();
            // Delete from the end so earlier indices stay valid as we go.
            for i in (0..count).rev() {
                db.memo_del(account, i);
            }
            ctx.notice(me, from.uid, format!("Deleted all \x02{count}\x02 memo(s)."));
        }
        Some(numstr) => {
            let Some(n) = numstr.parse::<usize>().ok().filter(|n| *n >= 1) else {
                ctx.notice(me, from.uid, "Syntax: DEL <num>|ALL");
                return;
            };
            if db.memo_del(account, n - 1) {
                ctx.notice(me, from.uid, format!("Memo #\x02{n}\x02 deleted."));
            } else {
                ctx.notice(me, from.uid, format!("You have no memo #\x02{n}\x02."));
            }
        }
        None => ctx.notice(me, from.uid, "Syntax: DEL <num>|ALL"),
    }
}
