//! InfoServ manages the network information bulletins. Public bulletins are
//! shown to every user as they connect; oper bulletins are shown to operators
//! when they log in (both are displayed by the engine — the same hooks OperServ
//! once drove through its NEWS command). This is the dedicated front-end over
//! that one shared news store, so there aren't two ways to post the same thing.
//!
//! POST/LIST/DEL manage public bulletins; OPOST/OLIST/ODEL the oper ones.
//! Posting and deleting are admin-only; anyone may LIST the public bulletins,
//! and any operator may OLIST. `lib.rs` holds the dispatcher; each command
//! (parameterised by bulletin kind) lives in its own file.

use echo_api::{NetView, Sender, Service, ServiceCtx, Store};

#[path = "post.rs"]
mod post;
#[path = "del.rs"]
mod del;
#[path = "list.rs"]
mod list;

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
            Some("POST") | Some("ADD") => post::handle(me, from, PUBLIC, &args[1..], ctx, db),
            Some("OPOST") | Some("OADD") => post::handle(me, from, OPER, &args[1..], ctx, db),
            Some("DEL") | Some("REMOVE") => del::handle(me, from, PUBLIC, args.get(1).copied(), ctx, db),
            Some("ODEL") => del::handle(me, from, OPER, args.get(1).copied(), ctx, db),
            // Public bulletins are, well, public — anyone may list them.
            Some("LIST") | None => list::handle(me, from, PUBLIC, false, ctx, db),
            // Oper bulletins are for operators only.
            Some("OLIST") => list::handle(me, from, OPER, true, ctx, db),
            Some("HELP") => ctx.notice(me, from.uid, "InfoServ holds the network's information bulletins. \x02LIST\x02 shows the public ones. Operators: \x02POST\x02 <message> / \x02DEL\x02 <number> (public, shown on connect), \x02OPOST\x02 / \x02OLIST\x02 / \x02ODEL\x02 (oper-only, shown on login)."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02LIST\x02 or \x02HELP\x02.")),
        }
    }
}
