//! GroupServ manages user groups — a `!name` owning a set of member accounts.
//! A group's real purpose is the interconnection: a channel can grant access to
//! a `!group` (via ChanServ FLAGS/ACCESS), and every member then inherits that
//! channel access. Members carry group-access flags (the same flag primitive
//! ChanServ uses): F founder, f manage members, i invite, c channel-access,
//! s set, m memo. Managing members needs the founder or the `f` flag.
//!
//! `lib.rs` holds the dispatcher and the two shared guards; each command lives
//! in its own file.

use echo_api::{NetView, Sender, Service, ServiceCtx, Store};

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
            Some("HELP") | None => ctx.notice(me, from.uid, "GroupServ manages user groups. \x02REGISTER\x02 <!group>, \x02DROP\x02 <!group>, \x02INFO\x02 <!group>, \x02LIST\x02, \x02ADD\x02/\x02DEL\x02 <!group> <account>, \x02FLAGS\x02 <!group> [account [+/-flags]]. Grant a group channel access with ChanServ \x02FLAGS #chan !group +o\x02 — every member then inherits it."),
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
