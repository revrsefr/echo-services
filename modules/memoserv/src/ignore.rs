use echo_api::{t, Sender, ServiceCtx, Store};

// IGNORE ADD <nick> | DEL <nick> | LIST: manage your memo-ignore list. Memos
// from an ignored account are silently dropped.
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => {
            let Some(&nick) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: IGNORE ADD <nick>");
                return;
            };
            let target = db.resolve_account(nick).map(str::to_string).unwrap_or_else(|| nick.to_string());
            // Cap the list so it (and the replicated event log) can't grow without
            // bound — mirrors AJOIN/CERT; unthrottled for identified users otherwise.
            const MAX_IGNORE: usize = 50;
            if db.memo_ignores(account).len() >= MAX_IGNORE {
                ctx.notice(me, from.uid, t!(ctx, "Your memo-ignore list is full (max {max}).", max = MAX_IGNORE));
                return;
            }
            if db.memo_ignore_add(account, &target) {
                ctx.notice(me, from.uid, t!(ctx, "Now ignoring memos from \x02{target}\x02.", target = target));
            } else {
                ctx.notice(me, from.uid, t!(ctx, "You're already ignoring \x02{target}\x02.", target = target));
            }
        }
        Some("DEL") | Some("REMOVE") => {
            let Some(&nick) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: IGNORE DEL <nick>");
                return;
            };
            let target = db.resolve_account(nick).map(str::to_string).unwrap_or_else(|| nick.to_string());
            if db.memo_ignore_del(account, &target) {
                ctx.notice(me, from.uid, t!(ctx, "No longer ignoring \x02{target}\x02.", target = target));
            } else {
                ctx.notice(me, from.uid, t!(ctx, "You weren't ignoring \x02{target}\x02.", target = target));
            }
        }
        Some("LIST") | None => {
            let list = db.memo_ignores(account);
            if list.is_empty() {
                ctx.notice(me, from.uid, "Your memo-ignore list is empty.");
            } else {
                ctx.notice(me, from.uid, t!(ctx, "You're ignoring memos from: {names}", names = list.join(", ")));
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: IGNORE ADD <nick> | DEL <nick> | LIST"),
    }
}
