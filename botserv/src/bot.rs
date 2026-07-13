use fedserv_api::{Priv, Sender, ServiceCtx, Store};

// BOT ADD <nick> <user> <host> [gecos] | BOT DEL <nick> | BOT LIST — manage the
// bot registry. Administering bots is oper-only (Priv::Admin).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — managing bots is for services operators.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => {
            let (Some(&nick), Some(&user), Some(&host)) = (args.get(2), args.get(3), args.get(4)) else {
                ctx.notice(me, from.uid, "Syntax: BOT ADD <nick> <user> <host> [gecos]");
                return;
            };
            let gecos = if args.len() > 5 { args[5..].join(" ") } else { "Service Bot".to_string() };
            match db.bot_add(nick, user, host, &gecos) {
                Ok(()) => ctx.notice(me, from.uid, format!("Bot \x02{nick}\x02 (\x02{user}@{host}\x02) added.")),
                Err(_) => ctx.notice(me, from.uid, format!("A bot named \x02{nick}\x02 already exists, or that didn't work.")),
            }
        }
        Some("DEL") => {
            let Some(&nick) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: BOT DEL <nick>");
                return;
            };
            match db.bot_del(nick) {
                Ok(true) => ctx.notice(me, from.uid, format!("Bot \x02{nick}\x02 deleted.")),
                Ok(false) => ctx.notice(me, from.uid, format!("There's no bot named \x02{nick}\x02.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        None | Some("LIST") => {
            let bots = db.bots();
            if bots.is_empty() {
                ctx.notice(me, from.uid, "No bots have been added yet. Add one with \x02BOT ADD\x02.");
                return;
            }
            ctx.notice(me, from.uid, format!("Bots ({}):", bots.len()));
            for b in &bots {
                ctx.notice(me, from.uid, format!("  \x02{}\x02 ({}@{}) — {}", b.nick, b.user, b.host, b.gecos));
            }
        }
        Some(other) => ctx.notice(me, from.uid, format!("Unknown BOT command \x02{other}\x02. Use \x02ADD\x02, \x02DEL\x02 or \x02LIST\x02.")),
    }
}
