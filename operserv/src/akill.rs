use fedserv_api::{parse_duration, Priv, Sender, ServiceCtx, Store};
use std::time::{SystemTime, UNIX_EPOCH};

// AKILL ADD [+expiry] <user@host> <reason> | DEL <user@host|number> | LIST
// [pattern]: manage network bans. Admin-only — a network ban is the heaviest
// hammer services hold.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — AKILL needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => add(me, from, &args[2..], ctx, db),
        Some("DEL") | Some("REMOVE") => del(me, from, args.get(2).copied(), ctx, db),
        Some("LIST") | Some("VIEW") => list(me, from, args.get(2).copied(), ctx, db),
        _ => ctx.notice(me, from.uid, "Syntax: AKILL ADD [+expiry] <user@host> <reason> | AKILL DEL <user@host|number> | AKILL LIST [pattern]"),
    }
}

fn add(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    // An optional leading +duration, then the mask, then a free-text reason.
    let mut rest = rest;
    let duration = rest.first().and_then(|t| t.strip_prefix('+')).and_then(parse_duration);
    if duration.is_some() {
        rest = &rest[1..];
    }
    let Some((&raw_mask, reason_words)) = rest.split_first() else {
        ctx.notice(me, from.uid, "Syntax: AKILL ADD [+expiry] <user@host> <reason>");
        return;
    };
    let Some(mask) = normalize_mask(raw_mask) else {
        ctx.notice(me, from.uid, format!("\x02{raw_mask}\x02 isn't a valid \x02user@host\x02 mask."));
        return;
    };
    if reason_words.is_empty() {
        ctx.notice(me, from.uid, "Please give a reason: AKILL ADD [+expiry] <user@host> <reason>");
        return;
    }
    let reason = reason_words.join(" ");
    // Refuse a mask so broad it would ban most of the network.
    if too_wide(&mask) {
        ctx.notice(me, from.uid, "That mask is too wide — it would ban almost everyone.");
        return;
    }
    let setter = from.account.unwrap_or(from.nick);
    let expires = duration.map(|secs| now() + secs);
    match db.akill_add(&mask, setter, &reason, expires) {
        Ok(fresh) => {
            // The ircd applies the G-line to matching users already online and to
            // future connections; duration 0 = permanent.
            ctx.add_line("G", &mask, from.nick, duration.unwrap_or(0), &reason);
            let word = if fresh { "added" } else { "updated" };
            let expiry = if expires.is_some() { " (temporary)" } else { "" };
            ctx.notice(me, from.uid, format!("AKILL {word} for \x02{mask}\x02{expiry}."));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn del(me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(arg) = arg else {
        ctx.notice(me, from.uid, "Syntax: AKILL DEL <user@host|number>");
        return;
    };
    // A number targets the entry at that position in AKILL LIST; otherwise it's a
    // literal mask.
    let mask = match arg.parse::<usize>() {
        Ok(n) if n >= 1 => match db.akills().get(n - 1) {
            Some(a) => a.mask.clone(),
            None => {
                ctx.notice(me, from.uid, format!("There's no AKILL number \x02{n}\x02."));
                return;
            }
        },
        _ => normalize_mask(arg).unwrap_or_else(|| arg.to_string()),
    };
    match db.akill_del(&mask) {
        Ok(true) => {
            ctx.del_line("G", &mask);
            ctx.notice(me, from.uid, format!("AKILL for \x02{mask}\x02 removed."));
        }
        Ok(false) => ctx.notice(me, from.uid, format!("No AKILL matches \x02{mask}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn list(me: &str, from: &Sender, pattern: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let pat = pattern.map(|p| p.to_ascii_lowercase());
    let akills = db.akills();
    let mut shown = 0;
    for (i, a) in akills.iter().enumerate() {
        if let Some(p) = &pat {
            if !a.mask.to_ascii_lowercase().contains(p.as_str()) {
                continue;
            }
        }
        let expiry = match a.expires {
            Some(e) => format!(", expires in {}", human_secs(e.saturating_sub(now()))),
            None => String::new(),
        };
        ctx.notice(me, from.uid, format!("{}. \x02{}\x02 by {} — {}{}", i + 1, a.mask, a.setter, a.reason, expiry));
        shown += 1;
    }
    if shown == 0 {
        ctx.notice(me, from.uid, "No matching network bans.");
    } else {
        ctx.notice(me, from.uid, format!("End of AKILL list ({shown} shown)."));
    }
}

// Reduce an input to a `user@host` mask: drop any `nick!` prefix, require a
// single `@` with non-empty sides. Returns None if it isn't shaped like a mask.
fn normalize_mask(input: &str) -> Option<String> {
    let body = input.rsplit('!').next().unwrap_or(input);
    let (user, host) = body.split_once('@')?;
    if user.is_empty() || host.is_empty() || host.contains('@') {
        return None;
    }
    Some(format!("{}@{}", user.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

// A mask whose user and host are both pure wildcard would catch nearly everyone.
fn too_wide(mask: &str) -> bool {
    let Some((user, host)) = mask.split_once('@') else { return true };
    let trivial = |s: &str| s.chars().all(|c| c == '*' || c == '?' || c == '.');
    trivial(user) && trivial(host)
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
