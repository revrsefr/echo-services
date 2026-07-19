use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

// ENTRYMSG <#channel> [CLEAR | <text>]: message noticed to users as they join.
// With no argument, show the current message.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: ENTRYMSG <#channel> [CLEAR | <text>]");
        return;
    };
    match args.get(2) {
        None => match db.channel(chan) {
            None => ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 isn't registered.", chan = chan)),
            Some(info) if info.entrymsg.is_empty() => ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 has no entry message.", chan = chan)),
            Some(info) => ctx.notice(me, from.uid, t!(ctx, "Entry message for \x02{chan}\x02: {msg}", chan = chan, msg = info.entrymsg)),
        },
        Some(&kw) if kw.eq_ignore_ascii_case("CLEAR") => {
            if !super::require_op(me, from, chan, ctx, db) {
                return;
            }
            match db.set_entrymsg(chan, "") {
                Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Entry message for \x02{chan}\x02 cleared.", chan = chan)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some(_) => {
            if !super::require_op(me, from, chan, ctx, db) {
                return;
            }
            match db.set_entrymsg(chan, &args[2..].join(" ")) {
                Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Entry message for \x02{chan}\x02 updated.", chan = chan)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
    }
}
