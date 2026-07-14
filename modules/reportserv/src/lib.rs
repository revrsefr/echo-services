//! ReportServ lets any user file an abuse report against a nick or channel.
//! Filing is rate-limited; the report is stored and — because it's an event —
//! the engine's audit feed automatically announces it to the staff channel and
//! records it in the searchable action log (OperServ LOGSEARCH), so a report is
//! tied into the same trail as everything else. Operators review the queue with
//! LIST / VIEW / CLOSE / DEL.
//!
//! `lib.rs` holds the dispatcher and the shared oper guard; each command lives
//! in its own file.

use echo_api::{HelpEntry, NetView, Sender, Service, ServiceCtx, Store};

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

const BLURB: &str = "ReportServ takes abuse reports. Anyone can \x02REPORT\x02; operators review the queue.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "REPORT", summary: "file an abuse report", detail: "Syntax: \x02REPORT <nick|#channel> <reason>\x02\nTells the staff about a problem. Rate-limited." },
    HelpEntry { cmd: "LIST", summary: "list reports", detail: "Syntax: \x02LIST [ALL]\x02\nOperators: list open reports, or every report with ALL." },
    HelpEntry { cmd: "VIEW", summary: "read a report", detail: "Syntax: \x02VIEW <id>\x02\nOperators: read a report in full. Also \x02READ\x02." },
    HelpEntry { cmd: "CLOSE", summary: "resolve a report", detail: "Syntax: \x02CLOSE <id>\x02\nOperators: mark a report resolved. Also \x02RESOLVE\x02." },
    HelpEntry { cmd: "DEL", summary: "delete a report", detail: "Syntax: \x02DEL <id>\x02\nOperators: delete a report outright. Also \x02REMOVE\x02." },
];

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

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REPORT") => report::handle(me, from, &args[1..], ctx, db),
            Some("LIST") => list::handle(me, from, args.get(1).copied(), ctx, db),
            Some("VIEW") | Some("READ") => view::handle(me, from, args.get(1).copied(), ctx, db),
            Some("CLOSE") | Some("RESOLVE") => close::handle(me, from, args.get(1).copied(), ctx, db),
            Some("DEL") | Some("REMOVE") => del::handle(me, from, args.get(1).copied(), ctx, db),
            Some("HELP") | None => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02REPORT\x02 <nick|#channel> <reason> or \x02HELP\x02.")),
        }
    }
}

// Reviewing the queue is for operators only.
fn require_oper(me: &str, from: &Sender, ctx: &mut ServiceCtx) -> bool {
    echo_api::require_oper(me, from, ctx, None, "reviewing reports")
}
