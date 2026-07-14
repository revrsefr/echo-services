//! ReportServ lets any user file an abuse report against a nick or channel.
//! Filing is rate-limited; the report is stored and — because it's an event —
//! the engine's audit feed automatically announces it to the staff channel and
//! records it in the searchable action log (OperServ LOGSEARCH), so a report is
//! tied into the same trail as everything else. Operators review the queue with
//! LIST / VIEW / CLOSE / DEL.
//!
//! `lib.rs` holds the dispatcher and the shared oper guard; each command lives
//! in its own file.

use echo_api::{NetView, Sender, Service, ServiceCtx, Store};

#[path = "report.rs"]
mod report;
#[path = "list.rs"]
mod list;
#[path = "view.rs"]
mod view;
#[path = "close.rs"]
mod close;
#[path = "del.rs"]
mod del;

pub struct ReportServ {
    pub uid: String,
}

impl Service for ReportServ {
    fn nick(&self) -> &str {
        "ReportServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Report Service"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REPORT") => report::handle(me, from, &args[1..], ctx, db),
            Some("LIST") => list::handle(me, from, args.get(1).copied(), ctx, db),
            Some("VIEW") | Some("READ") => view::handle(me, from, args.get(1).copied(), ctx, db),
            Some("CLOSE") | Some("RESOLVE") => close::handle(me, from, args.get(1).copied(), ctx, db),
            Some("DEL") | Some("REMOVE") => del::handle(me, from, args.get(1).copied(), ctx, db),
            Some("HELP") | None => ctx.notice(me, from.uid, "ReportServ takes abuse reports. \x02REPORT\x02 <nick|#channel> <reason> tells the staff about a problem. Operators review with \x02LIST\x02 [ALL], \x02VIEW\x02 <id>, \x02CLOSE\x02 <id>, \x02DEL\x02 <id>."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02REPORT\x02 <nick|#channel> <reason> or \x02HELP\x02.")),
        }
    }
}

// Reviewing the queue is for operators only.
fn require_oper(me: &str, from: &Sender, ctx: &mut ServiceCtx) -> bool {
    if from.privs.any() {
        return true;
    }
    ctx.notice(me, from.uid, "Access denied — reviewing reports is for services operators.");
    false
}
