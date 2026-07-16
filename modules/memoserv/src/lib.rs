//! MemoServ delivers short messages ("memos") to registered accounts whether or
//! not they are online — they read them next time they identify. Memos are typed
//! and event-logged on the account, so they persist and federate like any other
//! account data. `lib.rs` holds the dispatcher; each command lives in its own
//! file, matching NickServ/ChanServ.

use echo_api::{HelpEntry, NetView, Sender, Service, ServiceCtx, Store};

#[path = "send.rs"]
mod send;
#[path = "list.rs"]
mod list;
#[path = "read.rs"]
mod read;
#[path = "del.rs"]
mod del;
#[path = "cancel.rs"]
mod cancel;
#[path = "check.rs"]
mod check;
#[path = "info.rs"]
mod info;
#[path = "sendall.rs"]
mod sendall;
#[path = "ignore.rs"]
mod ignore;

const BLURB: &str = "MemoServ delivers messages to registered users, online or not. You must be identified to use it.";

// A full mailbox rejects new memos, so nobody can be flooded.
pub(crate) const MAX_MEMOS: usize = 30;

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "SEND", summary: "leave a memo for an account", detail: "Syntax: \x02SEND <nick> <text>\x02\nLeaves a memo on a registered account's mailbox." },
    HelpEntry { cmd: "LIST", summary: "list your memos", detail: "Syntax: \x02LIST\x02\nLists the memos in your mailbox." },
    HelpEntry { cmd: "READ", summary: "read a memo", detail: "Syntax: \x02READ <num>|NEW|ALL\x02\nReads a memo by number, your unread ones, or all of them." },
    HelpEntry { cmd: "DEL", summary: "delete a memo", detail: "Syntax: \x02DEL <num>|ALL\x02\nDeletes a memo by number, or your whole mailbox." },
    HelpEntry { cmd: "CANCEL", summary: "recall a memo you sent", detail: "Syntax: \x02CANCEL <nick>\x02\nRecalls the last memo you sent them, as long as they haven't read it yet." },
    HelpEntry { cmd: "CHECK", summary: "see if a memo was read", detail: "Syntax: \x02CHECK <nick>\x02\nReports whether the last memo you sent them has been read." },
    HelpEntry { cmd: "INFO", summary: "your mailbox summary", detail: "Syntax: \x02INFO\x02\nShows how many memos you have, how many are unread, and your capacity." },
    HelpEntry { cmd: "SENDALL", summary: "memo every account (admin)", detail: "Syntax: \x02SENDALL <text>\x02\nLeaves a memo on every registered account. Requires the admin privilege." },
    HelpEntry { cmd: "IGNORE", summary: "block memos from an account", detail: "Syntax: \x02IGNORE ADD <nick> | DEL <nick> | LIST\x02\nMemos from an ignored account are silently dropped." },
];

pub struct MemoServ {
    pub uid: String,
}

impl Service for MemoServ {
    fn nick(&self) -> &str {
        "MemoServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Memo Services"
    }

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        let cmd = args.first().map(|s| s.to_ascii_uppercase());
        if matches!(cmd.as_deref(), Some("HELP") | None) {
            echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied());
            return;
        }
        // Everything else needs you to be identified (memos are per-account).
        let Some(account) = from.account else {
            ctx.notice(me, from.uid, "You must identify to NickServ before using MemoServ.");
            return;
        };
        match cmd.as_deref() {
            Some("SEND") => send::handle(me, from, account, args, ctx, db),
            Some("LIST") => list::handle(me, from, account, ctx, db),
            Some("READ") => read::handle(me, from, account, args, ctx, db),
            Some("DEL") | Some("DELETE") => del::handle(me, from, account, args, ctx, db),
            Some("CANCEL") => cancel::handle(me, from, account, args, ctx, db),
            Some("CHECK") => check::handle(me, from, account, args, ctx, db),
            Some("INFO") => info::handle(me, from, account, ctx, db),
            Some("SENDALL") => sendall::handle(me, from, account, args, ctx, db),
            Some("IGNORE") => ignore::handle(me, from, account, args, ctx, db),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
            None => {}
        }
    }
}
