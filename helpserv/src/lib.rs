//! HelpServ is a help desk. A user opens a ticket with REQUEST (or HELPME); it
//! joins a queue that — being event-sourced and surfaced by the engine's audit
//! feed — is announced to staff and shows up in OperServ LOGSEARCH, the same
//! trail as reports. Operators work the queue: LIST, VIEW, TAKE (claim), NEXT
//! (claim the oldest), and CLOSE. A user can CANCEL their own open ticket.

use fedserv_api::{human_time, NetView, Sender, Service, ServiceCtx, Store};

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

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REQUEST") | Some("HELPME") => request(me, from, &args[1..], ctx, db),
            Some("CANCEL") => cancel(me, from, ctx, db),
            Some("LIST") => list(me, from, args.get(1).copied(), ctx, db),
            Some("VIEW") | Some("READ") => view(me, from, args.get(1).copied(), ctx, db),
            Some("TAKE") | Some("ASSIGN") => take(me, from, args.get(1).copied(), ctx, db),
            Some("NEXT") => next(me, from, ctx, db),
            Some("CLOSE") | Some("RESOLVE") => close(me, from, args.get(1).copied(), ctx, db),
            Some("HELP") | None => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02REQUEST\x02 <message> or \x02HELP\x02.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "HelpServ is the help desk. \x02REQUEST\x02 <message> opens a ticket for the staff; \x02CANCEL\x02 withdraws yours. Operators: \x02LIST\x02 [ALL], \x02VIEW\x02 <id>, \x02TAKE\x02 <id>, \x02NEXT\x02, \x02CLOSE\x02 <id>.");
}

fn request(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let message = rest.join(" ");
    if message.trim().is_empty() {
        ctx.notice(me, from.uid, "Tell us what you need help with: REQUEST <message>");
        return;
    }
    let requester = from.account.unwrap_or(from.nick);
    match db.help_request(requester, &message) {
        Some(id) => ctx.notice(me, from.uid, format!("Thanks — your request (\x02#{id}\x02) is in the queue. A staff member will be with you.")),
        None => ctx.notice(me, from.uid, "You just opened a ticket — please wait a moment before opening another."),
    }
}

fn cancel(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let who = from.account.unwrap_or(from.nick);
    // Close the requester's own newest open ticket.
    let mine = db.help_tickets(true).into_iter().find(|t| t.requester.eq_ignore_ascii_case(who));
    match mine {
        Some(t) => {
            db.help_close(t.id);
            ctx.notice(me, from.uid, format!("Your request \x02#{}\x02 has been cancelled.", t.id));
        }
        None => ctx.notice(me, from.uid, "You have no open request to cancel."),
    }
}

fn require_oper(me: &str, from: &Sender, ctx: &mut ServiceCtx) -> bool {
    if from.privs.any() {
        return true;
    }
    ctx.notice(me, from.uid, "Access denied — working the help queue is for services operators.");
    false
}

fn list(me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    let open_only = !arg.is_some_and(|a| a.eq_ignore_ascii_case("ALL"));
    let tickets = db.help_tickets(open_only);
    if tickets.is_empty() {
        ctx.notice(me, from.uid, if open_only { "No open tickets." } else { "No tickets." });
        return;
    }
    for t in &tickets {
        let state = match (&t.handler, t.open) {
            (_, false) => " (closed)".to_string(),
            (Some(h), true) => format!(" (taken by {h})"),
            (None, true) => String::new(),
        };
        let short: String = t.message.chars().take(60).collect();
        ctx.notice(me, from.uid, format!("\x02#{}\x02 {} — {}{}", t.id, t.requester, short, state));
    }
    ctx.notice(me, from.uid, format!("{} ticket(s). \x02VIEW\x02 <id> for detail.", tickets.len()));
}

fn view(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    let Some(t) = id.and_then(|n| n.parse::<u64>().ok()).and_then(|n| db.help_ticket(n)) else {
        ctx.notice(me, from.uid, "No such ticket. Syntax: VIEW <id>");
        return;
    };
    let state = if !t.open { "closed" } else if t.handler.is_some() { "taken" } else { "open" };
    ctx.notice(me, from.uid, format!("Ticket \x02#{}\x02 ({state}):", t.id));
    ctx.notice(me, from.uid, format!("  From    : \x02{}\x02", t.requester));
    if let Some(h) = &t.handler {
        ctx.notice(me, from.uid, format!("  Handler : \x02{h}\x02"));
    }
    ctx.notice(me, from.uid, format!("  Opened  : {}", human_time(t.ts)));
    ctx.notice(me, from.uid, format!("  Message : {}", t.message));
}

fn take(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = id.and_then(|n| n.parse::<u64>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: TAKE <id>");
        return;
    };
    take_id(me, from, n, ctx, db);
}

fn next(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    match db.help_next_open() {
        Some(id) => take_id(me, from, id, ctx, db),
        None => ctx.notice(me, from.uid, "No unassigned tickets are waiting."),
    }
}

fn take_id(me: &str, from: &Sender, id: u64, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let handler = from.account.unwrap_or(from.nick);
    if db.help_take(id, handler) {
        let msg = db.help_ticket(id).map(|t| t.message).unwrap_or_default();
        ctx.notice(me, from.uid, format!("You took ticket \x02#{id}\x02: {msg}"));
    } else {
        ctx.notice(me, from.uid, format!("Ticket \x02#{id}\x02 isn't open (or doesn't exist)."));
    }
}

fn close(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = id.and_then(|n| n.parse::<u64>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: CLOSE <id>");
        return;
    };
    if db.help_close(n) {
        ctx.notice(me, from.uid, format!("Ticket \x02#{n}\x02 closed."));
    } else {
        ctx.notice(me, from.uid, format!("Ticket \x02#{n}\x02 isn't open (or doesn't exist)."));
    }
}
