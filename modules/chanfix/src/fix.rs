use echo_api::{NetView, Sender, ServiceCtx, Store};

// A channel with this many ops isn't opless and needs no fix.
const OP_THRESHOLD: usize = 3;
// The top score must reach this before a channel has enough history to fix.
const MIN_FIX_SCORE: u32 = 12;
// Reop identities scoring at least this fraction of the top score.
const FIX_STEP: f64 = 0.30;

// CHANFIX <#channel>: reop the channel's trusted regulars from accumulated
// op-time. Defers to ChanServ for any registered channel.
pub fn handle(me: &str, from: &Sender, chan: Option<&str>, ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let Some(chan) = chan else {
        ctx.notice(me, from.uid, "Syntax: CHANFIX <#channel>");
        return;
    };
    // Defer to ChanServ for anything it owns.
    if db.channel(chan).is_some() {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 is registered — use \x02ChanServ\x02 to manage it."));
        return;
    }
    if net.op_count(chan) >= OP_THRESHOLD {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 already has ops — nothing to fix."));
        return;
    }
    let scores = net.chanfix_scores(chan);
    let highscore = scores.first().map(|(_, s)| *s).unwrap_or(0);
    if highscore < MIN_FIX_SCORE {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 doesn't have enough op-time history to fix yet."));
        return;
    }
    let threshold = ((highscore as f64 * FIX_STEP) as u32).max(1);

    // Reop present members whose identity scores at or above the threshold and who
    // aren't already opped.
    let members: Vec<String> = net.channel_members(chan);
    let mut opped = 0;
    for uid in &members {
        if net.is_op(chan, uid) {
            continue;
        }
        let id = net.account_of(uid).or_else(|| net.host_of(uid));
        let qualifies = id.is_some_and(|i| scores.iter().any(|(sid, s)| sid.eq_ignore_ascii_case(i) && *s >= threshold));
        if qualifies {
            ctx.channel_mode(me, chan, &format!("+o {uid}"));
            opped += 1;
        }
    }
    if opped == 0 {
        ctx.notice(me, from.uid, format!("None of \x02{chan}\x02's trusted regulars are here right now."));
    } else {
        ctx.notice(me, from.uid, format!("Reopped \x02{opped}\x02 trusted regular(s) in \x02{chan}\x02."));
    }
}
