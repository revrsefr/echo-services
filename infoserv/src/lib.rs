//! InfoServ manages the network information bulletins. Public bulletins are
//! shown to every user as they connect; oper bulletins are shown to operators
//! when they log in (both are displayed by the engine — the same hooks OperServ
//! once drove through its NEWS command). This is the dedicated front-end over
//! that one shared news store, so there aren't two ways to post the same thing.
//!
//! POST/LIST/DEL manage public bulletins; OPOST/OLIST/ODEL the oper ones.
//! Posting and deleting are admin-only; anyone may LIST the public bulletins,
//! and any operator may OLIST.

use fedserv_api::{NetView, Priv, Sender, Service, ServiceCtx, Store};

// The two bulletin kinds in the shared news store.
const PUBLIC: &str = "logon";
const OPER: &str = "oper";

pub struct InfoServ {
    pub uid: String,
}

impl Service for InfoServ {
    fn nick(&self) -> &str {
        "InfoServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Information Service"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("POST") | Some("ADD") => post(me, from, PUBLIC, &args[1..], ctx, db),
            Some("OPOST") | Some("OADD") => post(me, from, OPER, &args[1..], ctx, db),
            Some("DEL") | Some("REMOVE") => del(me, from, PUBLIC, args.get(1).copied(), ctx, db),
            Some("ODEL") => del(me, from, OPER, args.get(1).copied(), ctx, db),
            // Public bulletins are, well, public — anyone may list them.
            Some("LIST") | None => list(me, from, PUBLIC, false, ctx, db),
            // Oper bulletins are for operators only.
            Some("OLIST") => list(me, from, OPER, true, ctx, db),
            Some("HELP") => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02LIST\x02 or \x02HELP\x02.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "InfoServ holds the network's information bulletins. \x02LIST\x02 shows the public ones. Operators: \x02POST\x02 <message> / \x02DEL\x02 <number> (public, shown on connect), \x02OPOST\x02 / \x02OLIST\x02 / \x02ODEL\x02 (oper-only, shown on login).");
}

fn post(me: &str, from: &Sender, kind: &str, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — posting bulletins is for services operators.");
        return;
    }
    let message = rest.join(" ");
    if message.trim().is_empty() {
        ctx.notice(me, from.uid, format!("Syntax: {} <message>", if kind == OPER { "OPOST" } else { "POST" }));
        return;
    }
    let setter = from.account.unwrap_or(from.nick);
    db.news_add(kind, &message, setter);
    let which = if kind == OPER { "oper" } else { "public" };
    ctx.notice(me, from.uid, format!("Added a \x02{which}\x02 bulletin."));
}

fn del(me: &str, from: &Sender, kind: &str, num: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — that command is for services operators.");
        return;
    }
    let which = if kind == OPER { "oper" } else { "public" };
    let Some(n) = num.and_then(|n| n.parse::<usize>().ok()) else {
        ctx.notice(me, from.uid, format!("Syntax: {} <number>", if kind == OPER { "ODEL" } else { "DEL" }));
        return;
    };
    match db.news(kind).get(n.wrapping_sub(1)) {
        Some(item) if n >= 1 => {
            db.news_del(item.id);
            ctx.notice(me, from.uid, format!("Removed \x02{which}\x02 bulletin \x02{n}\x02."));
        }
        _ => ctx.notice(me, from.uid, format!("There's no \x02{which}\x02 bulletin \x02{n}\x02.")),
    }
}

fn list(me: &str, from: &Sender, kind: &str, oper_only: bool, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if oper_only && !from.privs.any() {
        ctx.notice(me, from.uid, "Access denied — oper bulletins are for services operators.");
        return;
    }
    let items = db.news(kind);
    let which = if kind == OPER { "oper" } else { "public" };
    if items.is_empty() {
        ctx.notice(me, from.uid, format!("There are no {which} bulletins."));
        return;
    }
    for (i, item) in items.iter().enumerate() {
        ctx.notice(me, from.uid, format!("{}. {} — by {}", i + 1, item.text, item.setter));
    }
    ctx.notice(me, from.uid, format!("End of {which} bulletins ({} shown).", items.len()));
}
