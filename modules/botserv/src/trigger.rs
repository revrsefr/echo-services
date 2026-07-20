use echo_api::{t, ChanError, Sender, ServiceCtx, Store};

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
                Ok(true) => ctx.notice(me, from.uid, t!(ctx, "Added a trigger to \x02{chan}\x02.", chan = chan)),
                Ok(false) => ctx.notice(me, from.uid, "That pattern already has a trigger."),
                Err(ChanError::InvalidPattern) => ctx.notice(me, from.uid, t!(ctx, "\x02{pattern}\x02 isn't a valid regular expression.", pattern = pattern)),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        }
        Some("DEL") => {
            let Some(n) = args.get(3).and_then(|s| s.parse::<usize>().ok()) else {
                ctx.notice(me, from.uid, "Syntax: TRIGGER <#channel> DEL <num> (see LIST)");
                return;
            };
            match db.trigger_del(chan, n) {
                Ok(true) => ctx.notice(me, from.uid, t!(ctx, "Trigger #\x02{n}\x02 removed from \x02{chan}\x02.", n = n, chan = chan)),
                Ok(false) => ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 has no trigger #\x02{n}\x02.", chan = chan, n = n)),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        }
        Some("CLEAR") => match db.trigger_clear(chan) {
            Ok(n) => ctx.notice(me, from.uid, echo_api::plural!(ctx, n, one = "Cleared \x02{n}\x02 trigger from \x02{chan}\x02.", other = "Cleared \x02{n}\x02 triggers from \x02{chan}\x02.", n = n, chan = chan)),
            Err(_) => reg_error(me, from, chan, ctx),
        },
        None | Some("LIST") => {
            let triggers = db.triggers(chan);
            if triggers.is_empty() {
                ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 has no triggers.", chan = chan));
                return;
            }
            ctx.notice(me, from.uid, t!(ctx, "Triggers for \x02{chan}\x02 ({count}):", chan = chan, count = triggers.len()));
            for (i, tr) in triggers.iter().enumerate() {
                let cd = if tr.cooldown > 0 { t!(ctx, " (cooldown {secs}s)", secs = tr.cooldown) } else { String::new() };
                ctx.notice(me, from.uid, t!(ctx, "  {num}. {pattern} \x02→\x02 {response}{cd}", num = i + 1, pattern = tr.pattern, response = tr.response, cd = cd));
            }
        }
        Some(other) => ctx.notice(me, from.uid, t!(ctx, "Unknown TRIGGER command \x02{other}\x02. Use ADD, DEL, LIST or CLEAR.", other = other)),
    }
}

fn reg_error(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, t!(ctx, "Couldn't update \x02{chan}\x02 — please try again in a moment.", chan = chan));
}
