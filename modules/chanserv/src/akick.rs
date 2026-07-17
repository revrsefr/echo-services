use echo_api::Store;
use echo_api::{Sender, ServiceCtx};

// AKICK <#channel> ADD <mask> [reason] | DEL <mask> | LIST
// Masks are nick!user@host globs or an extban echo can match: account:<glob>,
// realname:<glob>, realmask:<host>+<realname>, or unauthed:<host>. Matching users
// are banned and kicked on join.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: AKICK <#channel> ADD <mask> [reason] | DEL <mask> | LIST");
        return;
    };
    match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
        None | Some("LIST") => match db.channel(chan) {
            None => ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered.")),
            Some(info) if info.akick.is_empty() => ctx.notice(me, from.uid, format!("\x02{chan}\x02 has an empty auto-kick list.")),
            Some(info) => {
                ctx.notice(me, from.uid, format!("Auto-kick list for \x02{}\x02:", info.name));
                for k in &info.akick {
                    ctx.notice(me, from.uid, format!("  \x02{}\x02 ({})", k.mask, k.reason));
                }
            }
        },
        Some("ADD") => {
            let Some(&mask) = args.get(3) else {
                ctx.notice(me, from.uid, "Syntax: AKICK <#channel> ADD <mask> [reason]");
                return;
            };
            // Reject extbans echo has no per-user data to match (country, class, …),
            // so we never store an akick that can't be enforced.
            if let echo_api::AkickMask::Other(name) = echo_api::AkickMask::parse(mask) {
                ctx.notice(me, from.uid, format!("Can't auto-kick by the \x02{name}\x02 extban. Use a host mask or \x02account:\x02 / \x02realname:\x02 / \x02realmask:\x02 / \x02unauthed:\x02."));
                return;
            }
            if !super::require_op(me, from, chan, ctx, db) {
                return;
            }
            let reason = if args.len() > 4 { args[4..].join(" ") } else { "Auto-kicked".to_string() };
            match db.akick_add(chan, mask, &reason) {
                Ok(()) => ctx.notice(me, from.uid, format!("Added \x02{mask}\x02 to \x02{chan}\x02's auto-kick list.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("DEL") => {
            let Some(&mask) = args.get(3) else {
                ctx.notice(me, from.uid, "Syntax: AKICK <#channel> DEL <mask>");
                return;
            };
            if !super::require_op(me, from, chan, ctx, db) {
                return;
            }
            match db.akick_del(chan, mask) {
                Ok(true) => ctx.notice(me, from.uid, format!("Removed \x02{mask}\x02 from \x02{chan}\x02's auto-kick list.")),
                Ok(false) => ctx.notice(me, from.uid, format!("\x02{mask}\x02 isn't on \x02{chan}\x02's auto-kick list.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("CLEAR") => {
            if !super::require_op(me, from, chan, ctx, db) {
                return;
            }
            // Snapshot the masks, then remove each (the read borrow ends first).
            let masks: Vec<String> = db.channel(chan).map_or_else(Vec::new, |info| info.akick.iter().map(|k| k.mask.clone()).collect());
            for mask in &masks {
                let _ = db.akick_del(chan, mask);
            }
            ctx.notice(me, from.uid, format!("Cleared \x02{}\x02 entr{} from \x02{chan}\x02's auto-kick list.", masks.len(), if masks.len() == 1 { "y" } else { "ies" }));
        }
        _ => ctx.notice(me, from.uid, "Syntax: AKICK <#channel> ADD <mask> [reason] | DEL <mask> | LIST | CLEAR"),
    }
}
