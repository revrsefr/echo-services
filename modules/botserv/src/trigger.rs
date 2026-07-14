use fedserv_api::{ChanError, Sender, ServiceCtx, Store};

// TRIGGER <#channel> ADD <regex>|<response> | DEL <num> | LIST | CLEAR: manage
// the channel's auto-responses. When a line matches <regex>, the assigned bot
// says <response> ($nick becomes the speaker's nick). Founder-or-admin.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: TRIGGER <#channel> ADD <regex>|<response> | DEL <num> | LIST | CLEAR");
        return;
    };
    if !super::require_channel_admin(me, from, chan, ctx, db) {
        return;
    }
    match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => {
            // "<regex>|<response>" with an optional trailing "|<cooldown-secs>".
            // $1..$9 in the response fill from regex capture groups; $nick is the
            // speaker.
            let rest = args[3..].join(" ");
            let Some((pattern, mut response)) = rest.split_once('|') else {
                ctx.notice(me, from.uid, "Syntax: TRIGGER <#channel> ADD <regex>|<response>[|<cooldown-secs>]");
                return;
            };
            // A numeric field after the last '|' is a cooldown, not part of the text.
            let mut cooldown = 0;
            if let Some((head, tail)) = response.rsplit_once('|') {
                if let Ok(secs) = tail.trim().parse::<u32>() {
                    cooldown = secs;
                    response = head;
                }
            }
            let (pattern, response) = (pattern.trim(), response.trim());
            if pattern.is_empty() || response.is_empty() {
                ctx.notice(me, from.uid, "Both a pattern and a response are required: ADD <regex>|<response>.");
                return;
            }
            match db.trigger_add(chan, pattern, response, cooldown) {
                Ok(true) => ctx.notice(me, from.uid, format!("Added a trigger to \x02{chan}\x02.")),
                Ok(false) => ctx.notice(me, from.uid, "That pattern already has a trigger."),
                Err(ChanError::InvalidPattern) => ctx.notice(me, from.uid, format!("\x02{pattern}\x02 isn't a valid regular expression.")),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        }
        Some("DEL") => {
            let Some(n) = args.get(3).and_then(|s| s.parse::<usize>().ok()) else {
                ctx.notice(me, from.uid, "Syntax: TRIGGER <#channel> DEL <num> (see LIST)");
                return;
            };
            match db.trigger_del(chan, n) {
                Ok(true) => ctx.notice(me, from.uid, format!("Trigger #\x02{n}\x02 removed from \x02{chan}\x02.")),
                Ok(false) => ctx.notice(me, from.uid, format!("\x02{chan}\x02 has no trigger #\x02{n}\x02.")),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        }
        Some("CLEAR") => match db.trigger_clear(chan) {
            Ok(n) => ctx.notice(me, from.uid, format!("Cleared \x02{n}\x02 trigger(s) from \x02{chan}\x02.")),
            Err(_) => reg_error(me, from, chan, ctx),
        },
        None | Some("LIST") => {
            let triggers = db.triggers(chan);
            if triggers.is_empty() {
                ctx.notice(me, from.uid, format!("\x02{chan}\x02 has no triggers."));
                return;
            }
            ctx.notice(me, from.uid, format!("Triggers for \x02{chan}\x02 ({}):", triggers.len()));
            for (i, t) in triggers.iter().enumerate() {
                let cd = if t.cooldown > 0 { format!(" (cooldown {}s)", t.cooldown) } else { String::new() };
                ctx.notice(me, from.uid, format!("  {}. {} \x02→\x02 {}{cd}", i + 1, t.pattern, t.response));
            }
        }
        Some(other) => ctx.notice(me, from.uid, format!("Unknown TRIGGER command \x02{other}\x02. Use ADD, DEL, LIST or CLEAR.")),
    }
}

fn reg_error(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, format!("Couldn't update \x02{chan}\x02 — please try again in a moment."));
}
