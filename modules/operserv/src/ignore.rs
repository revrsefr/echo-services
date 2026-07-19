use echo_api::{parse_duration, Priv, Sender, ServiceCtx, Store};
use std::time::{SystemTime, UNIX_EPOCH};

// IGNORE ADD [+expiry] <mask> [reason] | DEL <mask> | LIST: services silently
// drop commands from a matching user. A mask with an '@' matches nick!*@host
// (ident isn't tracked); a bare mask matches the nick. Admin-only, node-local.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Oper) {
        ctx.notice(me, from.uid, "Access denied — IGNORE needs the \x02operator\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => add(me, from, &args[2..], ctx, db),
        Some("DEL") | Some("REMOVE") => del(me, from, args.get(2).copied(), ctx, db),
        Some("LIST") | Some("VIEW") => list(me, from, ctx, db),
        _ => ctx.notice(me, from.uid, "Syntax: IGNORE ADD [+expiry] <mask> [reason] | IGNORE DEL <mask> | IGNORE LIST"),
    }
}

fn add(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let mut rest = rest;
    let duration = rest.first().and_then(|t| t.strip_prefix('+')).and_then(parse_duration);
    if duration.is_some() {
        rest = &rest[1..];
    }
    let Some((&mask, reason_words)) = rest.split_first() else {
        ctx.notice(me, from.uid, "Syntax: IGNORE ADD [+expiry] <mask> [reason]");
        return;
    };
    if mask.is_empty() || mask.chars().all(|c| c == '*' || c == '?') {
        ctx.notice(me, from.uid, "That mask is too wide.");
        return;
    }
    let reason = if reason_words.is_empty() { "No reason given".to_string() } else { reason_words.join(" ") };
    let expires = duration.map(|secs| now() + secs);
    db.ignore_add(mask, &reason, expires);
    let expiry = if expires.is_some() { " (temporary)" } else { "" };
    ctx.notice(me, from.uid, format!("Now ignoring \x02{mask}\x02{expiry}."));
}

fn del(me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(mask) = arg else {
        ctx.notice(me, from.uid, "Syntax: IGNORE DEL <mask>");
        return;
    };
    if db.ignore_del(mask) {
        ctx.notice(me, from.uid, format!("No longer ignoring \x02{mask}\x02."));
    } else {
        ctx.notice(me, from.uid, format!("\x02{mask}\x02 isn't on the ignore list."));
    }
}

fn list(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let ignores = db.ignores();
    if ignores.is_empty() {
        ctx.notice(me, from.uid, "The services ignore list is empty.");
        return;
    }
    for (i, ig) in ignores.iter().enumerate() {
        let expiry = match ig.expires {
            Some(e) => format!(", expires in {}", human_secs(e.saturating_sub(now()))),
            None => String::new(),
        };
        ctx.notice(me, from.uid, format!("{}. \x02{}\x02 — {}{}", i + 1, ig.mask, ig.reason, expiry));
    }
    ctx.notice(me, from.uid, format!("End of ignore list ({} shown).", ignores.len()));
}

fn human_secs(secs: u64) -> String {
    match secs {
        0 => "moments".to_string(),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
