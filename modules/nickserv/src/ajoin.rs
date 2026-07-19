use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

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
                ctx.notice(me, from.uid, t!(ctx, "Your auto-join list is full (max {max}).", max = MAX_AJOIN));
                return;
            }
            match db.ajoin_add(account, channel, key) {
                Ok(true) => ctx.notice(me, from.uid, t!(ctx, "Added \x02{channel}\x02 to your auto-join list.", channel = channel)),
                Ok(false) => ctx.notice(me, from.uid, t!(ctx, "Updated the key for \x02{channel}\x02 on your auto-join list.", channel = channel)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("DEL") => {
            let Some(&channel) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: AJOIN DEL <#channel>");
                return;
            };
            match db.ajoin_del(account, channel) {
                Ok(true) => ctx.notice(me, from.uid, t!(ctx, "Removed \x02{channel}\x02 from your auto-join list.", channel = channel)),
                Ok(false) => ctx.notice(me, from.uid, t!(ctx, "\x02{channel}\x02 isn't on your auto-join list.", channel = channel)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        None | Some("LIST") => {
            let list = db.ajoin_list(account);
            if list.is_empty() {
                ctx.notice(me, from.uid, "Your auto-join list is empty. Add channels with \x02AJOIN ADD <#channel>\x02.");
                return;
            }
            ctx.notice(me, from.uid, t!(ctx, "Your auto-join list ({count}):", count = list.len()));
            for e in &list {
                if e.key.is_empty() {
                    ctx.notice(me, from.uid, t!(ctx, "  \x02{channel}\x02", channel = e.channel));
                } else {
                    ctx.notice(me, from.uid, t!(ctx, "  \x02{channel}\x02 (key: {key})", channel = e.channel, key = e.key));
                }
            }
        }
        Some(other) => ctx.notice(me, from.uid, t!(ctx, "Unknown AJOIN command \x02{other}\x02. Use \x02ADD\x02, \x02DEL\x02 or \x02LIST\x02.", other = other)),
    }
}
