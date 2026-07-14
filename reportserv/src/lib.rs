//! ReportServ lets any user file an abuse report against a nick or channel.
//! Filing is rate-limited; the report is stored and — because it's an event —
//! the engine's audit feed automatically announces it to the staff channel and
//! records it in the searchable action log (OperServ LOGSEARCH), so a report is
//! tied into the same trail as everything else. Operators review the queue with
//! LIST / VIEW / CLOSE / DEL.

use fedserv_api::{human_time, NetView, Sender, Service, ServiceCtx, Store};

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
            Some("REPORT") => report(me, from, &args[1..], ctx, db),
            Some("LIST") => list(me, from, args.get(1).copied(), ctx, db),
            Some("VIEW") | Some("READ") => view(me, from, args.get(1).copied(), ctx, db),
            Some("CLOSE") | Some("RESOLVE") => close(me, from, args.get(1).copied(), ctx, db),
            Some("DEL") | Some("REMOVE") => del(me, from, args.get(1).copied(), ctx, db),
            Some("HELP") | None => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02REPORT\x02 <nick|#channel> <reason> or \x02HELP\x02.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "ReportServ takes abuse reports. \x02REPORT\x02 <nick|#channel> <reason> tells the staff about a problem. Operators review with \x02LIST\x02 [ALL], \x02VIEW\x02 <id>, \x02CLOSE\x02 <id>, \x02DEL\x02 <id>.");
}

fn report(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some((&target, reason_words)) = rest.split_first() else {
        ctx.notice(me, from.uid, "Syntax: REPORT <nick|#channel> <reason>");
        return;
    };
    if reason_words.is_empty() {
        ctx.notice(me, from.uid, "Please say what the problem is: REPORT <nick|#channel> <reason>");
        return;
    }
    let reason = reason_words.join(" ");
    let reporter = from.account.unwrap_or(from.nick);
    match db.report_file(reporter, target, &reason) {
        Some(id) => ctx.notice(me, from.uid, format!("Thanks — your report (\x02#{id}\x02) about \x02{target}\x02 has been sent to the staff.")),
        None => ctx.notice(me, from.uid, "You just filed a report — please wait a moment before filing another."),
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

fn list(me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    let open_only = !arg.is_some_and(|a| a.eq_ignore_ascii_case("ALL"));
    let reports = db.reports(open_only);
    if reports.is_empty() {
        ctx.notice(me, from.uid, if open_only { "No open reports." } else { "No reports." });
        return;
    }
    for r in &reports {
        let flag = if r.open { "" } else { " (closed)" };
        let short: String = r.reason.chars().take(60).collect();
        ctx.notice(me, from.uid, format!("\x02#{}\x02 {} → \x02{}\x02: {}{}", r.id, r.reporter, r.target, short, flag));
    }
    ctx.notice(me, from.uid, format!("{} report(s). \x02VIEW\x02 <id> for detail.", reports.len()));
}

fn view(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    let Some(r) = id.and_then(|n| n.parse::<u64>().ok()).and_then(|n| db.report(n)) else {
        ctx.notice(me, from.uid, "No such report. Syntax: VIEW <id>");
        return;
    };
    ctx.notice(me, from.uid, format!("Report \x02#{}\x02 ({}):", r.id, if r.open { "open" } else { "closed" }));
    ctx.notice(me, from.uid, format!("  By       : \x02{}\x02", r.reporter));
    ctx.notice(me, from.uid, format!("  About    : \x02{}\x02", r.target));
    ctx.notice(me, from.uid, format!("  Filed    : {}", human_time(r.ts)));
    ctx.notice(me, from.uid, format!("  Reason   : {}", r.reason));
}

fn close(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = id.and_then(|n| n.parse::<u64>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: CLOSE <id>");
        return;
    };
    if db.report_close(n) {
        ctx.notice(me, from.uid, format!("Report \x02#{n}\x02 closed."));
    } else {
        ctx.notice(me, from.uid, format!("Report \x02#{n}\x02 isn't open (or doesn't exist)."));
    }
}

fn del(me: &str, from: &Sender, id: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = id.and_then(|n| n.parse::<u64>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: DEL <id>");
        return;
    };
    if db.report_del(n) {
        ctx.notice(me, from.uid, format!("Report \x02#{n}\x02 deleted."));
    } else {
        ctx.notice(me, from.uid, format!("There's no report \x02#{n}\x02."));
    }
}
