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

use echo_api::{t, HelpEntry, NetView, NewsKind, Sender, Service, ServiceCtx, Store};

#[path = "post.rs"]
mod post;
#[path = "del.rs"]
mod del;
#[path = "list.rs"]
mod list;

// The two bulletin kinds in the shared news store.
const PUBLIC: NewsKind = NewsKind::Logon;
const OPER: NewsKind = NewsKind::Oper;

const BLURB: &str = "InfoServ holds the network's information bulletins: public ones show on connect, oper ones on login.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "POST", summary: "post a public bulletin", detail: "Syntax: \x02POST <message>\x02\nAdds a public bulletin, shown to everyone on connect. Admin only. Also \x02ADD\x02." },
    HelpEntry { cmd: "LIST", summary: "show public bulletins", detail: "Syntax: \x02LIST\x02\nShows the public bulletins. Open to everyone." },
    HelpEntry { cmd: "DEL", summary: "remove a public bulletin", detail: "Syntax: \x02DEL <number>\x02\nRemoves a public bulletin by its listed number. Admin only. Also \x02REMOVE\x02." },
    HelpEntry { cmd: "OPOST", summary: "post an oper bulletin", detail: "Syntax: \x02OPOST <message>\x02\nAdds an oper bulletin, shown to operators on login. Admin only." },
    HelpEntry { cmd: "OLIST", summary: "show oper bulletins", detail: "Syntax: \x02OLIST\x02\nShows the oper bulletins. Operators only." },
    HelpEntry { cmd: "ODEL", summary: "remove an oper bulletin", detail: "Syntax: \x02ODEL <number>\x02\nRemoves an oper bulletin by its listed number. Admin only." },
];

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

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
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
            Some("HELP") => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            Some(other) => ctx.notice(me, from.uid, t!(ctx, "I don't know \x02{other}\x02. Try \x02LIST\x02 or \x02HELP\x02.", other = other)),
        }
    }
}
