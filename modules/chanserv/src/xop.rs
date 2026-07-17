use echo_api::{access_role, Sender, ServiceCtx, Store};

// SOP/AOP/HOP/VOP <#channel> ADD <account> | DEL <account> | LIST — tiered
// shortcuts over the access list. `level` is the tier they map to ("sop", "op",
// "halfop", "voice"); `word` is the tier the user typed ("SOP".."VOP").
pub fn handle(me: &str, from: &Sender, word: &str, level: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, format!("Syntax: {word} <#channel> ADD <account> | DEL <account> | LIST"));
        return;
    };
    match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
        None | Some("LIST") => match db.channel(chan) {
            None => ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered.")),
            Some(info) => {
                ctx.notice(me, from.uid, format!("{word} list for \x02{}\x02:", info.name));
                // List by resolved tier, not the raw level string, so an entry set
                // via granular FLAGS appears under the same tier a XOP ADD would.
                for a in info.access.iter().filter(|a| access_role(&a.level).xop_word() == Some(word)) {
                    ctx.notice(me, from.uid, format!("  \x02{}\x02", a.account));
                }
            }
        },
        Some("ADD") => {
            let Some(&account) = args.get(3) else {
                ctx.notice(me, from.uid, format!("Syntax: {word} <#channel> ADD <account>"));
                return;
            };
            if !super::require_founder(me, from, chan, ctx, db) {
                return;
            }
            match db.access_add(chan, account, level) {
                Ok(()) => ctx.notice(me, from.uid, format!("Added \x02{account}\x02 to \x02{chan}\x02's {word} list.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("DEL") => {
            let Some(&account) = args.get(3) else {
                ctx.notice(me, from.uid, format!("Syntax: {word} <#channel> DEL <account>"));
                return;
            };
            if !super::require_founder(me, from, chan, ctx, db) {
                return;
            }
            match db.access_del(chan, account) {
                Ok(true) => ctx.notice(me, from.uid, format!("Removed \x02{account}\x02 from \x02{chan}\x02's {word} list.")),
                Ok(false) => ctx.notice(me, from.uid, format!("\x02{account}\x02 has no access to \x02{chan}\x02.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        _ => ctx.notice(me, from.uid, format!("Syntax: {word} <#channel> ADD <account> | DEL <account> | LIST")),
    }
}
