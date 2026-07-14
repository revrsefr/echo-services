//! StatServ surfaces statistics: the shared, cross-service counter registry
//! (SERVER, operators only) and per-channel activity the bots have seen
//! (a #channel argument, for its founder). `lib.rs` holds the dispatcher; each
//! view lives in its own file.

use echo_api::{HelpEntry, NetView, Priv, Sender, Service, ServiceCtx, Store};

#[path = "global.rs"]
mod global;
#[path = "channel.rs"]
mod channel;

const BLURB: &str = "StatServ reports statistics: \x02SERVER\x02 for network-wide counters (operators), or a \x02#channel\x02 for its activity (founder).";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "SERVER", summary: "network-wide statistics", detail: "Syntax: \x02SERVER\x02\nShows network-wide counters. Operators only. Also \x02GLOBAL\x02." },
    HelpEntry { cmd: "CHANNEL", summary: "a channel's statistics", detail: "Syntax: \x02<#channel>\x02\nShows a channel's activity statistics. Available to the channel's founder." },
];

pub struct StatServ {
    pub uid: String,
}

impl Service for StatServ {
    fn nick(&self) -> &str {
        "StatServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Statistics Service"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().copied() {
            Some(chan) if chan.starts_with('#') => channel::handle(me, from, chan, ctx, net, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("SERVER") || cmd.eq_ignore_ascii_case("GLOBAL") => global::handle(me, from, ctx, net, db),
            Some(cmd) if cmd.eq_ignore_ascii_case("HELP") => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            None => echo_api::help(me, from, ctx, BLURB, TOPICS, None),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02SERVER\x02, a \x02#channel\x02, or \x02HELP\x02.")),
        }
    }
}

// Shared gate: the sender may see a channel's stats only as its founder or a
// services admin.
fn require_channel_admin(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, db: &dyn Store) -> bool {
    let Some(founder) = db.channel(chan).map(|c| c.founder) else {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
        return false;
    };
    if from.account != Some(founder.as_str()) && !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can see its stats."));
        return false;
    }
    true
}
