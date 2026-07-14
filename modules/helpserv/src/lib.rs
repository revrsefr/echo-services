//! HelpServ is a help desk. A user opens a ticket with REQUEST (or HELPME); it
//! joins a queue that — being event-sourced and surfaced by the engine's audit
//! feed — is announced to staff and shows up in OperServ LOGSEARCH, the same
//! trail as reports. Operators work the queue: LIST, VIEW, TAKE (claim), NEXT
//! (claim the oldest), and CLOSE. A user can CANCEL their own open ticket.
//!
//! `lib.rs` holds the dispatcher and the shared guard/claim helpers; each
//! command lives in its own file.

use echo_api::{HelpEntry, NetView, Sender, Service, ServiceCtx, Store};

#[path = "request.rs"]
mod request;
#[path = "cancel.rs"]
mod cancel;
#[path = "list.rs"]
mod list;
#[path = "view.rs"]
mod view;
#[path = "take.rs"]
mod take;
#[path = "next.rs"]
mod next;
#[path = "close.rs"]
mod close;

const BLURB: &str = "HelpServ is the help desk and the network's help index. Open a ticket with \x02REQUEST\x02; operators work the queue.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "REQUEST", summary: "open a help-desk ticket", detail: "Syntax: \x02REQUEST <message>\x02\nOpens a ticket for the staff. Also \x02HELPME\x02." },
    HelpEntry { cmd: "CANCEL", summary: "withdraw your ticket", detail: "Syntax: \x02CANCEL\x02\nWithdraws your own newest open ticket." },
    HelpEntry { cmd: "LIST", summary: "list the ticket queue", detail: "Syntax: \x02LIST [ALL]\x02\nOperators: list open tickets, or every ticket with ALL." },
    HelpEntry { cmd: "VIEW", summary: "read a ticket", detail: "Syntax: \x02VIEW <id>\x02\nOperators: read a ticket in full. Also \x02READ\x02." },
    HelpEntry { cmd: "TAKE", summary: "claim a ticket", detail: "Syntax: \x02TAKE <id>\x02\nOperators: claim a specific ticket. Also \x02ASSIGN\x02." },
    HelpEntry { cmd: "NEXT", summary: "claim the oldest ticket", detail: "Syntax: \x02NEXT\x02\nOperators: claim the oldest unassigned ticket." },
    HelpEntry { cmd: "CLOSE", summary: "resolve a ticket", detail: "Syntax: \x02CLOSE <id>\x02\nOperators: resolve a ticket. Also \x02RESOLVE\x02." },
];

pub struct HelpServ {
    pub uid: String,
}

impl Service for HelpServ {
    fn nick(&self) -> &str {
        "HelpServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Help Service"
    }

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REQUEST") | Some("HELPME") => request::handle(me, from, &args[1..], ctx, db),
            Some("CANCEL") => cancel::handle(me, from, ctx, db),
            Some("LIST") => list::handle(me, from, args.get(1).copied(), ctx, db),
            Some("VIEW") | Some("READ") => view::handle(me, from, args.get(1).copied(), ctx, db),
            Some("TAKE") | Some("ASSIGN") => take::handle(me, from, args.get(1).copied(), ctx, db),
            Some("NEXT") => next::handle(me, from, ctx, db),
            Some("CLOSE") | Some("RESOLVE") => close::handle(me, from, args.get(1).copied(), ctx, db),
            // HELP [service [command]]: bare HELP is HelpServ's own; HELP <service>
            // [command] fronts any other service's help through the shared renderer.
            Some("HELP") | None => match args.get(1).and_then(|&s| net.service_help(s)) {
                Some((blurb, topics)) => echo_api::help(me, from, ctx, blurb, topics, args.get(2).copied()),
                None => {
                    echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied());
                    if args.get(1).is_none() {
                        ctx.notice(me, from.uid, format!("For a service's own commands, type \x02HELP <service>\x02. Services: {}.", net.help_services().join(", ")));
                    }
                }
            },
            // Not a HelpServ command — maybe the name of a service to get help for.
            Some(_) => match net.service_help(args[0]) {
                Some((blurb, topics)) => echo_api::help(me, from, ctx, blurb, topics, args.get(1).copied()),
                None => ctx.notice(me, from.uid, format!("I don't know \x02{}\x02. Try \x02REQUEST\x02 <message>, \x02HELP\x02, or a service name (e.g. \x02NickServ\x02).", args[0])),
            },
        }
    }
}

// Working the help queue is operator-only.
fn require_oper(me: &str, from: &Sender, ctx: &mut ServiceCtx) -> bool {
    if from.privs.any() {
        return true;
    }
    ctx.notice(me, from.uid, "Access denied — working the help queue is for services operators.");
    false
}

// Claim ticket `id` for the calling operator (shared by TAKE and NEXT).
fn take_id(me: &str, from: &Sender, id: u64, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let handler = from.account.unwrap_or(from.nick);
    if db.help_take(id, handler) {
        let msg = db.help_ticket(id).map(|t| t.message).unwrap_or_default();
        ctx.notice(me, from.uid, format!("You took ticket \x02#{id}\x02: {msg}"));
    } else {
        ctx.notice(me, from.uid, format!("Ticket \x02#{id}\x02 isn't open (or doesn't exist)."));
    }
}
