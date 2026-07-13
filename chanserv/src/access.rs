use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};

// ACCESS <#channel> LIST | ADD <account> <op|voice> | DEL <account>
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: ACCESS <#channel> LIST | ADD <account> <op|voice> | DEL <account>");
        return;
    };
    match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
        None | Some("LIST") => match db.channel(chan) {
            None => ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered.")),
            Some(info) => {
                ctx.notice(me, from.uid, format!("Access list for \x02{}\x02:", info.name));
                ctx.notice(me, from.uid, format!("  \x02{}\x02 (founder)", info.founder));
                for a in &info.access {
                    ctx.notice(me, from.uid, format!("  \x02{}\x02 ({})", a.account, a.level));
                }
            }
        },
        Some("ADD") => {
            let (Some(&account), Some(&level)) = (args.get(3), args.get(4)) else {
                ctx.notice(me, from.uid, "Syntax: ACCESS <#channel> ADD <account> <op|voice>");
                return;
            };
            let level = level.to_ascii_lowercase();
            if level != "op" && level != "voice" {
                ctx.notice(me, from.uid, "Level must be \x02op\x02 or \x02voice\x02.");
                return;
            }
            if !is_founder(me, from, chan, ctx, db) {
                return;
            }
            match db.access_add(chan, account, &level) {
                Ok(()) => ctx.notice(me, from.uid, format!("Added \x02{account}\x02 to \x02{chan}\x02 as \x02{level}\x02.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("DEL") => {
            let Some(&account) = args.get(3) else {
                ctx.notice(me, from.uid, "Syntax: ACCESS <#channel> DEL <account>");
                return;
            };
            if !is_founder(me, from, chan, ctx, db) {
                return;
            }
            match db.access_del(chan, account) {
                Ok(true) => ctx.notice(me, from.uid, format!("Removed \x02{account}\x02 from \x02{chan}\x02.")),
                Ok(false) => ctx.notice(me, from.uid, format!("\x02{account}\x02 has no access to \x02{chan}\x02.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: ACCESS <#channel> LIST | ADD <account> <op|voice> | DEL <account>"),
    }
}

// True if `from` is the channel's founder; otherwise notices why and returns false.
fn is_founder(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, db: &dyn Store) -> bool {
    match db.channel(chan) {
        None => {
            ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
            false
        }
        Some(info) if from.account != Some(info.founder.as_str()) => {
            ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can change access."));
            false
        }
        Some(_) => true,
    }
}
