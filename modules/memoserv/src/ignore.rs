use echo_api::{Sender, ServiceCtx, Store};

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
            if db.memo_ignore_add(account, &target) {
                ctx.notice(me, from.uid, format!("Now ignoring memos from \x02{target}\x02."));
            } else {
                ctx.notice(me, from.uid, format!("You're already ignoring \x02{target}\x02."));
            }
        }
        Some("DEL") | Some("REMOVE") => {
            let Some(&nick) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: IGNORE DEL <nick>");
                return;
            };
            let target = db.resolve_account(nick).map(str::to_string).unwrap_or_else(|| nick.to_string());
            if db.memo_ignore_del(account, &target) {
                ctx.notice(me, from.uid, format!("No longer ignoring \x02{target}\x02."));
            } else {
                ctx.notice(me, from.uid, format!("You weren't ignoring \x02{target}\x02."));
            }
        }
        Some("LIST") | None => {
            let list = db.memo_ignores(account);
            if list.is_empty() {
                ctx.notice(me, from.uid, "Your memo-ignore list is empty.");
            } else {
                ctx.notice(me, from.uid, format!("You're ignoring memos from: {}", list.join(", ")));
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: IGNORE ADD <nick> | DEL <nick> | LIST"),
    }
}
