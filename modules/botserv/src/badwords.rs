use echo_api::{ChanError, Sender, ServiceCtx, Store};

// BADWORDS <#channel> ADD <regex> | DEL <regex> | LIST | CLEAR: manage the
// channel's badword patterns. Each entry is a regular expression, so a channel
// can match whatever it likes. Enable the kicker itself with
// KICK <#channel> BADWORDS ON. Founder-or-admin.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: BADWORDS <#channel> ADD|DEL|LIST|CLEAR [pattern]");
        return;
    };
    // LIST is readable by the founder/admin too; gate everything the same way.
    if !super::require_channel_admin(me, from, chan, ctx, db) {
        return;
    }
    match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => {
            if args.len() < 4 {
                ctx.notice(me, from.uid, "Syntax: BADWORDS <#channel> ADD <regex>");
                return;
            }
            let pattern = args[3..].join(" ");
            match db.badword_add(chan, &pattern) {
                Ok(true) => ctx.notice(me, from.uid, format!("Added badword pattern to \x02{chan}\x02: {pattern}")),
                Ok(false) => ctx.notice(me, from.uid, "That pattern is already on the list."),
                Err(ChanError::InvalidPattern) => ctx.notice(me, from.uid, format!("\x02{pattern}\x02 isn't a valid regular expression.")),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        }
        Some("DEL") => {
            if args.len() < 4 {
                ctx.notice(me, from.uid, "Syntax: BADWORDS <#channel> DEL <regex>");
                return;
            }
            let pattern = args[3..].join(" ");
            match db.badword_del(chan, &pattern) {
                Ok(true) => ctx.notice(me, from.uid, format!("Removed badword pattern from \x02{chan}\x02.")),
                Ok(false) => ctx.notice(me, from.uid, "That pattern isn't on the list."),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        }
        Some("CLEAR") => match db.badword_clear(chan) {
            Ok(n) => ctx.notice(me, from.uid, format!("Cleared \x02{n}\x02 badword pattern(s) from \x02{chan}\x02.")),
            Err(_) => reg_error(me, from, chan, ctx),
        },
        None | Some("LIST") => {
            let words = db.badwords(chan);
            if words.is_empty() {
                ctx.notice(me, from.uid, format!("\x02{chan}\x02 has no badword patterns."));
                return;
            }
            ctx.notice(me, from.uid, format!("Badword patterns for \x02{chan}\x02 ({}):", words.len()));
            for (i, w) in words.iter().enumerate() {
                ctx.notice(me, from.uid, format!("  {}. {w}", i + 1));
            }
        }
        Some(other) => ctx.notice(me, from.uid, format!("Unknown BADWORDS command \x02{other}\x02. Use ADD, DEL, LIST or CLEAR.")),
    }
}

fn reg_error(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, format!("Couldn't update \x02{chan}\x02 — please try again in a moment."));
}
