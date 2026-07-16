use echo_api::{Sender, ServiceCtx, Store};

use super::MAX_MEMOS;

// SEND <nick> <text>: leave a memo on a registered account's mailbox.
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if args.len() < 3 {
        ctx.notice(me, from.uid, "Syntax: SEND <nick> <text>");
        return;
    }
    let target = args[1];
    let text = args[2..].join(" ");
    let Some(dest) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };
    let limit = db.memo_limit_of(&dest).unwrap_or(MAX_MEMOS as u32) as usize;
    if db.memo_list(&dest).len() >= limit {
        ctx.notice(me, from.uid, format!("\x02{target}\x02's mailbox is full — they'll need to clear some memos first."));
        return;
    }
    // If the recipient is ignoring the sender, drop it silently — the sender is
    // told it was sent, so the ignore isn't revealed.
    if db.memo_is_ignored(&dest, account) {
        ctx.notice(me, from.uid, format!("Memo sent to \x02{target}\x02."));
        return;
    }
    match db.memo_send(&dest, account, &text) {
        Ok(()) => ctx.notice(me, from.uid, format!("Memo sent to \x02{target}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
