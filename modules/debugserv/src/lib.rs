//! DebugServ is the network's live observability feed. It sits in the staff log
//! channel and reports what the services layer is doing in real time —
//! authentication (IDENTIFY and every SASL mechanism, success and failure),
//! sessions (logout, nick enforcement, ghosting), and the account / channel /
//! operator lifecycle. The reporting itself lives in the engine (the only place
//! that sees every event); this module is DebugServ's identity plus a small
//! staff-facing command surface.
//!
//! Privacy note: the feed names who authenticates from where, so the log channel
//! it speaks in must be restricted to staff.

use echo_api::{help, HelpEntry, NetView, Priv, Sender, Service, ServiceCtx, Store};

const BLURB: &str = "DebugServ streams live services activity — authentication, sessions, and the account/channel/operator lifecycle — to the staff log channel.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry {
        cmd: "STATUS",
        summary: "what DebugServ is reporting",
        detail: "Syntax: \x02STATUS\x02\nSummarises the live feed DebugServ streams to the staff log channel. Operators only.",
    },
];

pub struct DebugServ {
    pub uid: String,
}

impl Service for DebugServ {
    fn nick(&self) -> &str {
        "DebugServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Services Activity Feed"
    }

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, _db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().copied() {
            Some(cmd) if cmd.eq_ignore_ascii_case("STATUS") => {
                if !from.privs.has(Priv::Auspex) && !from.privs.has(Priv::Admin) {
                    ctx.notice(me, from.uid, "Access denied — DebugServ is a staff tool.");
                    return;
                }
                ctx.notice(me, from.uid, "I stream live services activity to the staff log channel:");
                ctx.notice(me, from.uid, "  \x02AUTH\x02  — every IDENTIFY / SASL login attempt, success and failure");
                ctx.notice(me, from.uid, "  \x02SESS\x02  — logout, nick enforcement, ghosting");
                ctx.notice(me, from.uid, "  \x02ACCT/CHAN/OPER\x02 — account, channel, and enforcement changes");
            }
            Some(cmd) if cmd.eq_ignore_ascii_case("HELP") => help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            None => help(me, from, ctx, BLURB, TOPICS, None),
            Some(other) => ctx.notice(me, from.uid, format!("I don't take commands other than \x02STATUS\x02 or \x02HELP\x02 — I just report. ({other} ignored.)")),
        }
    }
}
