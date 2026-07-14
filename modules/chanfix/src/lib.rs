//! ChanFix helps recover an opless channel. The engine continuously scores
//! op-time per identity from live network state; ChanFix reads those scores to
//! reop the channel's trusted regulars. It **defers to ChanServ**: a registered
//! channel is ChanServ's job, so ChanFix refuses to touch one. Operator-only.
//!
//! SCORES <#channel> shows the standings; CHANFIX <#channel> performs the fix.
//! `lib.rs` holds the dispatcher; each command lives in its own file.

use echo_api::{NetView, Sender, Service, ServiceCtx, Store};

#[path = "scores.rs"]
mod scores;
#[path = "fix.rs"]
mod fix;

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
            Some("SCORES") => scores::handle(me, from, args.get(1).copied(), ctx, net),
            Some("CHANFIX") | Some("FIX") => fix::handle(me, from, args.get(1).copied(), ctx, net, db),
            Some("HELP") | None => ctx.notice(me, from.uid, "ChanFix recovers opless channels from accumulated op-time. \x02SCORES\x02 <#channel> shows the standings; \x02CHANFIX\x02 <#channel> reops its trusted regulars. It won't touch a ChanServ-registered channel."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02SCORES\x02 or \x02CHANFIX\x02 <#channel>.")),
        }
    }
}
