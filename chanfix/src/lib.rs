//! ChanFix helps recover an opless channel. The engine continuously scores
//! op-time per identity from live network state; ChanFix reads those scores to
//! reop the channel's trusted regulars. It **defers to ChanServ**: a registered
//! channel is ChanServ's job, so ChanFix refuses to touch one. Operator-only.
//!
//! SCORES <#channel> shows the standings; CHANFIX <#channel> performs the fix.

use fedserv_api::{NetView, Sender, Service, ServiceCtx, Store};

// A channel with this many ops isn't opless and needs no fix.
const OP_THRESHOLD: usize = 3;
// The top score must reach this before a channel has enough history to fix.
const MIN_FIX_SCORE: u32 = 12;
// Reop identities scoring at least this fraction of the top score.
const FIX_STEP: f64 = 0.30;

pub struct ChanFix {
    pub uid: String,
}

impl Service for ChanFix {
    fn nick(&self) -> &str {
        "ChanFix"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Channel Fixer"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        // The whole service is operator-only.
        if !from.privs.any() {
            ctx.notice(me, from.uid, "Access denied — ChanFix is for services operators.");
            return;
        }
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("SCORES") => scores(me, from, args.get(1).copied(), ctx, net),
            Some("CHANFIX") | Some("FIX") => fix(me, from, args.get(1).copied(), ctx, net, db),
            Some("HELP") | None => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02SCORES\x02 or \x02CHANFIX\x02 <#channel>.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "ChanFix recovers opless channels from accumulated op-time. \x02SCORES\x02 <#channel> shows the standings; \x02CHANFIX\x02 <#channel> reops its trusted regulars. It won't touch a ChanServ-registered channel.");
}

fn scores(me: &str, from: &Sender, chan: Option<&str>, ctx: &mut ServiceCtx, net: &dyn NetView) {
    let Some(chan) = chan else {
        ctx.notice(me, from.uid, "Syntax: SCORES <#channel>");
        return;
    };
    let scores = net.chanfix_scores(chan);
    if scores.is_empty() {
        ctx.notice(me, from.uid, format!("No op-time recorded for \x02{chan}\x02 yet."));
        return;
    }
    for (id, score) in scores.iter().take(15) {
        ctx.notice(me, from.uid, format!("  \x02{score}\x02  {id}"));
    }
    ctx.notice(me, from.uid, format!("Top {} of {} scored identit{} for \x02{chan}\x02.", scores.len().min(15), scores.len(), if scores.len() == 1 { "y" } else { "ies" }));
}

fn fix(me: &str, from: &Sender, chan: Option<&str>, ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
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
