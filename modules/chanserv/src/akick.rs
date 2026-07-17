use echo_api::Store;
use echo_api::{Sender, ServiceCtx};

// AKICK <#channel> ADD <mask> [reason] | DEL <mask> | LIST | CLEAR
// A mask is a nick!user@host glob or any extban the ircd advertises (named or by
// letter). Extbans echo can evaluate itself (account, unauthed, realname, realmask,
// server, fingerprint, channel) get matched and kicked on join / ENFORCE; the rest
// are pushed to the channel as a ban for the ircd to enforce. The accepted set is
// narrowed by the `[extban] enabled` config.
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
            // Validate the mask: a host mask always passes; an extban must be one
            // this ircd offers, be a matching (not acting) kind, and be allowed by
            // the `[extban] enabled` config. Extbans echo's own table doesn't know
            // are resolved against the ircd's live set so a new matching extban
            // still works (the ircd enforces it).
            match echo_api::AkickMask::parse(mask) {
                echo_api::AkickMask::Host(_) => {}
                echo_api::AkickMask::Ext(eb, _) => {
                    if !db.extban_offered(eb.name) {
                        ctx.notice(me, from.uid, format!("This network's ircd doesn't offer the \x02{}\x02 extban.", eb.name));
                        return;
                    }
                    if !db.extban_enabled(eb.name) {
                        ctx.notice(me, from.uid, format!("The \x02{}\x02 extban isn't enabled on this network.", eb.name));
                        return;
                    }
                }
                echo_api::AkickMask::Unknown(token) => match db.extban_lookup(token) {
                    None => {
                        ctx.notice(me, from.uid, format!("\x02{token}\x02 isn't a host mask or an extban this network offers."));
                        return;
                    }
                    Some(cap) if cap.acting => {
                        ctx.notice(me, from.uid, format!("\x02{}\x02 is an acting extban; auto-kick needs a matching extban or a host mask.", cap.name));
                        return;
                    }
                    Some(cap) if !db.extban_enabled(&cap.name) => {
                        ctx.notice(me, from.uid, format!("The \x02{}\x02 extban isn't enabled on this network.", cap.name));
                        return;
                    }
                    Some(_) => {}
                },
            }
            if !super::require_op(me, from, chan, ctx, db) {
                return;
            }
            let reason = if args.len() > 4 { args[4..].join(" ") } else { "Auto-kicked".to_string() };
            match db.akick_add(chan, mask, &reason) {
                Ok(()) => {
                    // Extbans echo can't evaluate itself are pushed to the channel as
                    // a ban so the ircd enforces them; the ones echo matches are applied
                    // on join / ENFORCE and need no standing mode.
                    if echo_api::ircd_enforced(mask) {
                        ctx.channel_mode(me, chan, &format!("+b {mask}"));
                    }
                    ctx.notice(me, from.uid, format!("Added \x02{mask}\x02 to \x02{chan}\x02's auto-kick list."));
                }
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
                Ok(true) => {
                    // Lift the standing ban we set for an ircd-enforced extban.
                    if echo_api::ircd_enforced(mask) {
                        ctx.channel_mode(me, chan, &format!("-b {mask}"));
                    }
                    ctx.notice(me, from.uid, format!("Removed \x02{mask}\x02 from \x02{chan}\x02's auto-kick list."));
                }
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
                if echo_api::ircd_enforced(mask) {
                    ctx.channel_mode(me, chan, &format!("-b {mask}"));
                }
            }
            ctx.notice(me, from.uid, format!("Cleared \x02{}\x02 entr{} from \x02{chan}\x02's auto-kick list.", masks.len(), if masks.len() == 1 { "y" } else { "ies" }));
        }
        _ => ctx.notice(me, from.uid, "Syntax: AKICK <#channel> ADD <mask> [reason] | DEL <mask> | LIST | CLEAR"),
    }
}
