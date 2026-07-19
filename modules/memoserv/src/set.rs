use echo_api::{t, Sender, ServiceCtx, Store};

// SET NOTIFY {ON|OFF} | SET LIMIT <n>|NONE: your MemoServ preferences.
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("NOTIFY") => {
            let on = match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
                Some("ON") => true,
                Some("OFF") => false,
                _ => {
                    ctx.notice(me, from.uid, "Syntax: SET NOTIFY {ON|OFF}");
                    return;
                }
            };
            db.set_memo_notify(account, on);
            ctx.notice(me, from.uid, t!(ctx, "New-memo notification is now \x02{state}\x02.", state = if on { "on" } else { "off" }));
        }
        Some("LIMIT") => {
            let limit = match args.get(2) {
                None => None,
                Some(&n) if n.eq_ignore_ascii_case("NONE") || n.eq_ignore_ascii_case("OFF") => None,
                Some(&n) => match n.parse::<u32>() {
                    Ok(v) if v <= super::MAX_MEMOS as u32 => Some(v),
                    _ => {
                        ctx.notice(me, from.uid, t!(ctx, "The limit must be a number from 0 to {max}, or NONE.", max = super::MAX_MEMOS));
                        return;
                    }
                },
            };
            db.set_memo_limit(account, limit);
            match limit {
                Some(v) => ctx.notice(me, from.uid, t!(ctx, "Your mailbox limit is now \x02{v}\x02.", v = v)),
                None => ctx.notice(me, from.uid, t!(ctx, "Your mailbox limit is now the network default (\x02{max}\x02).", max = super::MAX_MEMOS)),
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: SET NOTIFY {ON|OFF} | SET LIMIT <n>|NONE"),
    }
}
