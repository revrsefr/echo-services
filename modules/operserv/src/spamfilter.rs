use echo_api::{parse_duration, Priv, Sender, ServiceCtx, Store};
use std::time::{SystemTime, UNIX_EPOCH};

// Default filter flags: apply to privmsg/notice/part/quit, exempt opers, match on
// colour-stripped text. (m_filter's `*`.)
const DEFAULT_FLAGS: &str = "*";

// SPAMFILTER ADD <action> [+expiry] <regex> <reason> | DEL <regex|number> | LIST [pattern]
// Content spam filters echo persists and pushes to the ircd's m_filter (re-asserted
// at each burst, so they outlive an ircd restart). The pattern is a regular
// expression (the ircd's filter engine), e.g. `.*free.*bitcoin.*`. `action` is what
// happens on a match: gline / zline / block / silent / kill / shun / warn / none.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — SPAMFILTER needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => add(me, from, &args[2..], ctx, db),
        Some("DEL") | Some("REMOVE") => del(me, from, args.get(2).copied(), ctx, db),
        Some("LIST") | Some("VIEW") => list(me, from, args.get(2).copied(), ctx, db),
        _ => ctx.notice(me, from.uid, "Syntax: SPAMFILTER ADD <action> [+expiry] <pattern> <reason> | DEL <pattern|number> | LIST [pattern]"),
    }
}

fn add(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some((&action, rest)) = rest.split_first() else {
        ctx.notice(me, from.uid, "Syntax: SPAMFILTER ADD <action> [+expiry] <pattern> <reason>");
        return;
    };
    if !echo_api::is_filter_action(action) {
        ctx.notice(me, from.uid, format!("\x02{action}\x02 isn't a filter action. Use one of: {}.", echo_api::FILTER_ACTIONS.join(", ")));
        return;
    }
    // An optional leading +duration, then the pattern (one glob token), then reason.
    let mut rest = rest;
    let duration = rest.first().and_then(|t| t.strip_prefix('+')).and_then(parse_duration);
    if duration.is_some() {
        rest = &rest[1..];
    }
    let Some((&pattern, reason_words)) = rest.split_first() else {
        ctx.notice(me, from.uid, "Syntax: SPAMFILTER ADD <action> [+expiry] <pattern> <reason>");
        return;
    };
    if reason_words.is_empty() {
        ctx.notice(me, from.uid, "Please give a reason.");
        return;
    }
    // A regex of only wildcards/quantifiers (e.g. `.*`) would match everything.
    if pattern.chars().all(|c| ".*+?".contains(c)) {
        ctx.notice(me, from.uid, "That pattern is too wide — it would match almost everything.");
        return;
    }
    let reason = reason_words.join(" ");
    let setter = from.account.unwrap_or(from.nick);
    let expires = duration.map(|secs| now() + secs);
    match db.filter_add(pattern, action, DEFAULT_FLAGS, setter, &reason, expires) {
        Ok(fresh) => {
            ctx.filter_push(echo_api::encode_filter(pattern, action, DEFAULT_FLAGS, duration.unwrap_or(0), &reason));
            let word = if fresh { "added" } else { "updated" };
            let expiry = if expires.is_some() { " (temporary)" } else { "" };
            ctx.notice(me, from.uid, format!("Spam filter {word}: \x02{pattern}\x02 ({}){expiry}.", action.to_ascii_lowercase()));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn del(me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(arg) = arg else {
        ctx.notice(me, from.uid, "Syntax: SPAMFILTER DEL <pattern|number>");
        return;
    };
    // A number targets the nth filter in the list; otherwise it's the pattern.
    let pattern = match arg.parse::<usize>() {
        Ok(n) if n >= 1 => match db.filters().get(n - 1) {
            Some(f) => f.pattern.clone(),
            None => {
                ctx.notice(me, from.uid, format!("There's no spam filter number \x02{n}\x02."));
                return;
            }
        },
        _ => arg.to_string(),
    };
    match db.filter_del(&pattern) {
        Ok(true) => ctx.notice(me, from.uid, format!("Spam filter \x02{pattern}\x02 removed. It stops being re-applied, but stays live on the ircd until the next services relink or a manual \x02/FILTER\x02 removal.")),
        Ok(false) => ctx.notice(me, from.uid, format!("No spam filter matches \x02{pattern}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn list(me: &str, from: &Sender, pattern: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let pat = pattern.map(|p| p.to_ascii_lowercase());
    let mut shown = 0;
    for (i, f) in db.filters().iter().enumerate() {
        if let Some(p) = &pat {
            if !f.pattern.to_ascii_lowercase().contains(p.as_str()) {
                continue;
            }
        }
        let expiry = match f.expires {
            Some(e) => format!(", expires in {}", human_secs(e.saturating_sub(now()))),
            None => String::new(),
        };
        ctx.notice(me, from.uid, format!("{}. \x02{}\x02 [{}] by {} — {}{}", i + 1, f.pattern, f.action, f.setter, f.reason, expiry));
        shown += 1;
    }
    if shown == 0 {
        ctx.notice(me, from.uid, "No matching spam filters.");
    } else {
        ctx.notice(me, from.uid, format!("End of spam-filter list ({shown} shown)."));
    }
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
