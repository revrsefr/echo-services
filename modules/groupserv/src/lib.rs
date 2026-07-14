//! GroupServ manages user groups — a `!name` owning a set of member accounts.
//! A group's real purpose is the interconnection: a channel can grant access to
//! a `!group` (via ChanServ FLAGS/ACCESS), and every member then inherits that
//! channel access. Members carry group-access flags (the same flag primitive
//! ChanServ uses): F founder, f manage members, i invite, c channel-access,
//! s set, m memo. Managing members needs the founder or the `f` flag.
//!
//! `lib.rs` holds the dispatcher and the two shared guards; each command lives
//! in its own file.

use echo_api::{HelpEntry, NetView, Sender, Service, ServiceCtx, Store};

#[path = "register.rs"]
mod register;
#[path = "drop.rs"]
mod drop;
#[path = "info.rs"]
mod info;
#[path = "list.rs"]
mod list;
#[path = "add.rs"]
mod add;
#[path = "del.rs"]
mod del;
#[path = "flags.rs"]
mod flags;

const BLURB: &str = "GroupServ manages user groups: a \x02!name\x02 owning member accounts. A channel can grant access to a group, and every member then inherits it.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "REGISTER", summary: "create a group you found", detail: "Syntax: \x02REGISTER <!group>\x02\nCreates a group with you as founder. A group name starts with '!', e.g. !staff." },
    HelpEntry { cmd: "DROP", summary: "delete a group you founded", detail: "Syntax: \x02DROP <!group>\x02\nDeletes a group. Founder only." },
    HelpEntry { cmd: "INFO", summary: "show a group's founder and size", detail: "Syntax: \x02INFO <!group>\x02\nShows a group's founder and member count." },
    HelpEntry { cmd: "LIST", summary: "list groups you belong to", detail: "Syntax: \x02LIST\x02\nLists the groups you belong to. Operators see every group." },
    HelpEntry { cmd: "ADD", summary: "add a member", detail: "Syntax: \x02ADD <!group> <account>\x02\nAdds a plain member. Needs the founder or the 'f' flag." },
    HelpEntry { cmd: "DEL", summary: "remove a member", detail: "Syntax: \x02DEL <!group> <account>\x02\nRemoves a member. Needs the founder or the 'f' flag." },
    HelpEntry { cmd: "FLAGS", summary: "view or change group flags", detail: "Syntax: \x02FLAGS <!group> [account [+/-flags]]\x02\nLists, shows, or changes group-access flags (F founder, f manage, i invite, c channel-access, s set, m memo). Changing needs the founder or the 'f' flag." },
];

pub struct GroupServ {
    pub uid: String,
}

impl Service for GroupServ {
    fn nick(&self) -> &str {
        "GroupServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Group Service"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REGISTER") => register::handle(me, from, args.get(1).copied(), ctx, db),
            Some("DROP") => drop::handle(me, from, args.get(1).copied(), ctx, db),
            Some("INFO") => info::handle(me, from, args.get(1).copied(), ctx, db),
            Some("LIST") => list::handle(me, from, ctx, db),
            Some("ADD") => add::handle(me, from, args.get(1).copied(), args.get(2).copied(), ctx, db),
            Some("DEL") => del::handle(me, from, args.get(1).copied(), args.get(2).copied(), ctx, db),
            Some("FLAGS") => flags::handle(me, from, args.get(1).copied(), args.get(2).copied(), args.get(3).copied(), ctx, db),
            Some("HELP") | None => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}

// The caller must be logged in; returns their account.
fn account<'a>(me: &str, from: &'a Sender, ctx: &mut ServiceCtx) -> Option<&'a str> {
    match from.account {
        Some(a) => Some(a),
        None => {
            ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
            None
        }
    }
}

// Whether `who` may manage `group` (founder, or holds the F/f flag).
fn can_manage(group: &echo_api::GroupView, who: &str) -> bool {
    group.founder.eq_ignore_ascii_case(who)
        || group.members.iter().any(|m| m.account.eq_ignore_ascii_case(who) && (m.flags.contains('F') || m.flags.contains('f')))
}
