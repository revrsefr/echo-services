use fedserv_api::{ChanError, Priv, Sender, ServiceCtx, Store};

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
        Some("CHANGE") => {
            let (Some(&old), Some(&newnick)) = (args.get(2), args.get(3)) else {
                ctx.notice(me, from.uid, "Syntax: BOT CHANGE <oldnick> <newnick> [user [host [gecos]]]");
                return;
            };
            // Omitted fields keep the bot's current values.
            let Some(cur) = db.bots().into_iter().find(|b| b.nick.eq_ignore_ascii_case(old)) else {
                ctx.notice(me, from.uid, format!("There's no bot named \x02{old}\x02."));
                return;
            };
            let user = args.get(4).map(|s| s.to_string()).unwrap_or(cur.user);
            let host = args.get(5).map(|s| s.to_string()).unwrap_or(cur.host);
            let gecos = if args.len() > 6 { args[6..].join(" ") } else { cur.gecos };
            match db.bot_change(old, newnick, &user, &host, &gecos) {
                Ok(()) => ctx.notice(me, from.uid, format!("Bot \x02{old}\x02 is now \x02{newnick}\x02 (\x02{user}@{host}\x02).")),
                Err(ChanError::Exists) => ctx.notice(me, from.uid, format!("A bot named \x02{newnick}\x02 already exists.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("DEL") => {
            let Some(&nick) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: BOT DEL <nick> (or \x02*\x02 for all)");
                return;
            };
            if nick == "*" {
                match db.bot_del_all() {
                    Ok(n) => ctx.notice(me, from.uid, format!("Removed all \x02{n}\x02 bot(s).")),
                    Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                }
                return;
            }
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
                let flag = if b.private { " \x02[private]\x02" } else { "" };
                ctx.notice(me, from.uid, format!("  \x02{}\x02 ({}@{}) — {}{flag}", b.nick, b.user, b.host, b.gecos));
            }
        }
        Some(other) => ctx.notice(me, from.uid, format!("Unknown BOT command \x02{other}\x02. Use \x02ADD\x02, \x02CHANGE\x02, \x02DEL\x02 or \x02LIST\x02.")),
    }
}
