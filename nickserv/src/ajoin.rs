use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};

// A sane cap so a runaway list can't bloat an account or flood a user on identify.
const MAX_AJOIN: usize = 25;

// AJOIN [ADD <#channel> [key] | DEL <#channel> | LIST]: manage your auto-join
// list — the channels NickServ joins you to each time you identify.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You must identify to NickServ to use \x02AJOIN\x02.");
        return;
    };
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => {
            let Some(&channel) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: AJOIN ADD <#channel> [key]");
                return;
            };
            if !channel.starts_with('#') {
                ctx.notice(me, from.uid, "That doesn't look like a channel name.");
                return;
            }
            let key = args.get(3).copied().unwrap_or("");
            if db.ajoin_list(account).len() >= MAX_AJOIN {
                ctx.notice(me, from.uid, format!("Your auto-join list is full (max {MAX_AJOIN})."));
                return;
            }
            match db.ajoin_add(account, channel, key) {
                Ok(true) => ctx.notice(me, from.uid, format!("Added \x02{channel}\x02 to your auto-join list.")),
                Ok(false) => ctx.notice(me, from.uid, format!("Updated the key for \x02{channel}\x02 on your auto-join list.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("DEL") => {
            let Some(&channel) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: AJOIN DEL <#channel>");
                return;
            };
            match db.ajoin_del(account, channel) {
                Ok(true) => ctx.notice(me, from.uid, format!("Removed \x02{channel}\x02 from your auto-join list.")),
                Ok(false) => ctx.notice(me, from.uid, format!("\x02{channel}\x02 isn't on your auto-join list.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        None | Some("LIST") => {
            let list = db.ajoin_list(account);
            if list.is_empty() {
                ctx.notice(me, from.uid, "Your auto-join list is empty. Add channels with \x02AJOIN ADD <#channel>\x02.");
                return;
            }
            ctx.notice(me, from.uid, format!("Your auto-join list ({}):", list.len()));
            for e in &list {
                if e.key.is_empty() {
                    ctx.notice(me, from.uid, format!("  \x02{}\x02", e.channel));
                } else {
                    ctx.notice(me, from.uid, format!("  \x02{}\x02 (key: {})", e.channel, e.key));
                }
            }
        }
        Some(other) => ctx.notice(me, from.uid, format!("Unknown AJOIN command \x02{other}\x02. Use \x02ADD\x02, \x02DEL\x02 or \x02LIST\x02.")),
    }
}
