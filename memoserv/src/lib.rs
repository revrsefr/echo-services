//! MemoServ delivers short messages ("memos") to registered accounts whether or
//! not they are online — they read them next time they identify. Memos are typed
//! and event-logged on the account, so they persist and federate like any other
//! account data (no Anope-style flat-file serialization).

use fedserv_api::{human_time, NetView, Sender, ServiceCtx, Store};

// A full mailbox rejects new memos, so nobody can be flooded.
const MAX_MEMOS: usize = 30;

pub struct MemoServ {
    pub uid: String,
}

impl fedserv_api::Service for MemoServ {
    fn nick(&self) -> &str {
        "MemoServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Memo Services"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        let cmd = args.first().map(|s| s.to_ascii_uppercase());
        if matches!(cmd.as_deref(), Some("HELP") | None) {
            ctx.notice(me, from.uid, "MemoServ delivers messages to registered users, online or not. Commands: \x02SEND\x02 <nick> <text>, \x02LIST\x02, \x02READ\x02 <num>|NEW|ALL, \x02DEL\x02 <num>|ALL.");
            return;
        }
        // Everything else needs you to be identified (memos are per-account).
        let Some(account) = from.account else {
            ctx.notice(me, from.uid, "You must identify to NickServ before using MemoServ.");
            return;
        };
        match cmd.as_deref() {
            Some("SEND") => send(me, from, account, args, ctx, db),
            Some("LIST") => list(me, from, account, ctx, db),
            Some("READ") => read(me, from, account, args, ctx, db),
            Some("DEL") | Some("DELETE") => del(me, from, account, args, ctx, db),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
            None => {}
        }
    }
}

fn send(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if args.len() < 3 {
        ctx.notice(me, from.uid, "Syntax: SEND <nick> <text>");
        return;
    }
    let target = args[1];
    let text = args[2..].join(" ");
    let Some(dest) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };
    if db.memo_list(&dest).len() >= MAX_MEMOS {
        ctx.notice(me, from.uid, format!("\x02{target}\x02's mailbox is full — they'll need to clear some memos first."));
        return;
    }
    match db.memo_send(&dest, account, &text) {
        Ok(()) => ctx.notice(me, from.uid, format!("Memo sent to \x02{target}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn list(me: &str, from: &Sender, account: &str, ctx: &mut ServiceCtx, db: &dyn Store) {
    let memos = db.memo_list(account);
    if memos.is_empty() {
        ctx.notice(me, from.uid, "You have no memos.");
        return;
    }
    let unread = memos.iter().filter(|m| !m.read).count();
    ctx.notice(me, from.uid, format!("Your memos ({} total, {unread} new). \x02*\x02 marks unread:", memos.len()));
    for (i, m) in memos.iter().enumerate() {
        let flag = if m.read { ' ' } else { '*' };
        ctx.notice(me, from.uid, format!("  {}{flag} from \x02{}\x02 ({}): {}", i + 1, m.from, human_time(m.ts), preview(&m.text)));
    }
}

fn read(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("NEW") | Some("ALL") => {
            let only_new = args[1].eq_ignore_ascii_case("new");
            let targets: Vec<usize> = db
                .memo_list(account)
                .iter()
                .enumerate()
                .filter(|(_, m)| !only_new || !m.read)
                .map(|(i, _)| i)
                .collect();
            if targets.is_empty() {
                ctx.notice(me, from.uid, if only_new { "You have no new memos." } else { "You have no memos." });
                return;
            }
            for i in targets {
                if let Some(m) = db.memo_read(account, i) {
                    show(me, from, i, &m, ctx);
                }
            }
        }
        Some(numstr) => {
            let Some(n) = numstr.parse::<usize>().ok().filter(|n| *n >= 1) else {
                ctx.notice(me, from.uid, "Syntax: READ <num>|NEW|ALL");
                return;
            };
            match db.memo_read(account, n - 1) {
                Some(m) => show(me, from, n - 1, &m, ctx),
                None => ctx.notice(me, from.uid, format!("You have no memo #\x02{n}\x02.")),
            }
        }
        None => ctx.notice(me, from.uid, "Syntax: READ <num>|NEW|ALL"),
    }
}

fn del(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ALL") => {
            let count = db.memo_list(account).len();
            // Delete from the end so earlier indices stay valid as we go.
            for i in (0..count).rev() {
                db.memo_del(account, i);
            }
            ctx.notice(me, from.uid, format!("Deleted all \x02{count}\x02 memo(s)."));
        }
        Some(numstr) => {
            let Some(n) = numstr.parse::<usize>().ok().filter(|n| *n >= 1) else {
                ctx.notice(me, from.uid, "Syntax: DEL <num>|ALL");
                return;
            };
            if db.memo_del(account, n - 1) {
                ctx.notice(me, from.uid, format!("Memo #\x02{n}\x02 deleted."));
            } else {
                ctx.notice(me, from.uid, format!("You have no memo #\x02{n}\x02."));
            }
        }
        None => ctx.notice(me, from.uid, "Syntax: DEL <num>|ALL"),
    }
}

fn show(me: &str, from: &Sender, index: usize, m: &fedserv_api::MemoView, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, format!("Memo #\x02{}\x02 from \x02{}\x02 ({}):", index + 1, m.from, human_time(m.ts)));
    ctx.notice(me, from.uid, format!("  {}", m.text));
}

// First line / first 80 chars, for LIST.
fn preview(text: &str) -> String {
    let line = text.lines().next().unwrap_or("");
    if line.chars().count() > 80 {
        format!("{}…", line.chars().take(80).collect::<String>())
    } else {
        line.to_string()
    }
}
