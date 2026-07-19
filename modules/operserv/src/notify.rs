use echo_api::{human_time, parse_duration, Priv, Sender, ServiceCtx, Store};
use std::time::{SystemTime, UNIX_EPOCH};

// The event letters a watch can carry, in help order.
const ALL_FLAGS: &str = "cdjkmnoptusS";

// NOTIFY ADD +expiry <flags|*> <mask> <reason> | DEL <mask|number> |
//        LIST [pattern] | VIEW [pattern] | CLEAR
// An oper watch list: users matching a mask have their flagged events announced
// to the staff feed. Admin-only, like the rest of the ban family.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Oper) {
        ctx.notice(me, from.uid, "Access denied — NOTIFY needs the \x02operator\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => add(me, from, &args[2..], ctx, db),
        Some("DEL") | Some("REMOVE") => del(me, from, args.get(2).copied(), ctx, db),
        Some("LIST") => list(me, from, false, args.get(2).copied(), ctx, db),
        Some("VIEW") => list(me, from, true, args.get(2).copied(), ctx, db),
        Some("CLEAR") => match db.notify_clear() {
            Ok(0) => ctx.notice(me, from.uid, "The notify list is already empty."),
            Ok(n) => ctx.notice(me, from.uid, format!("Cleared \x02{n}\x02 notify watch(es).")),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        },
        _ => ctx.notice(me, from.uid, SYNTAX),
    }
}

fn add(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    // Grammar: +expiry  flags|*  mask  reason…
    let Some(exp_tok) = rest.first() else {
        ctx.notice(me, from.uid, SYNTAX);
        return;
    };
    let Some(dur) = exp_tok.strip_prefix('+') else {
        ctx.notice(me, from.uid, "The expiry comes first, e.g. \x02+30d\x02 (or \x02+0\x02 for permanent).");
        return;
    };
    let expires = match dur {
        "0" | "" => None,
        d => match parse_duration(d) {
            Some(0) => None,
            Some(secs) => Some(now() + secs),
            None => {
                ctx.notice(me, from.uid, format!("\x02{d}\x02 isn't a valid expiry — try 30d, 12h, 45m, or 0."));
                return;
            }
        },
    };
    let Some(&flags_tok) = rest.get(1) else {
        ctx.notice(me, from.uid, SYNTAX);
        return;
    };
    let flags = if flags_tok == "*" {
        ALL_FLAGS.to_string()
    } else if flags_tok.chars().all(|c| ALL_FLAGS.contains(c)) && !flags_tok.is_empty() {
        flags_tok.to_string()
    } else {
        ctx.notice(me, from.uid, format!("Unknown flag(s). Valid: \x02{ALL_FLAGS}\x02 (or \x02*\x02 for all). {FLAG_LEGEND}"));
        return;
    };
    let Some(&mask) = rest.get(2) else {
        ctx.notice(me, from.uid, SYNTAX);
        return;
    };
    if rest.len() < 4 {
        ctx.notice(me, from.uid, "Please give a reason.");
        return;
    }
    if !valid_mask(mask) {
        ctx.notice(me, from.uid, "Mask must be a \x02#channel\x02, a \x02nick!user@host\x02 pattern, or a bare nick glob — and no spaces.");
        return;
    }
    // No too-wide guard here: NOTIFY only observes, so a deliberately broad watch
    // like "#*" (every channel) or "*" (every user) is a valid monitoring choice —
    // scope it with flags and rely on `[log] notify_exclude` to keep relay noise out.
    let reason = rest[3..].join(" ");
    let setter = from.account.unwrap_or(from.nick);
    match db.notify_add(mask, &flags, &reason, setter, expires) {
        Ok(true) => ctx.notice(me, from.uid, format!("Now watching \x02{mask}\x02 [{flags}].")),
        Ok(false) => ctx.notice(me, from.uid, format!("Updated the watch on \x02{mask}\x02 [{flags}].")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn del(me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(arg) = arg else {
        ctx.notice(me, from.uid, "Syntax: NOTIFY DEL <mask|number>");
        return;
    };
    // A number targets the nth entry in LIST order; anything else is a mask.
    let mask = match arg.parse::<usize>() {
        Ok(n) if n >= 1 => match db.notifies().get(n - 1) {
            Some(v) => v.mask.clone(),
            None => {
                ctx.notice(me, from.uid, format!("There's no notify number \x02{n}\x02."));
                return;
            }
        },
        _ => arg.to_string(),
    };
    match db.notify_del(&mask) {
        Ok(true) => ctx.notice(me, from.uid, format!("Stopped watching \x02{mask}\x02.")),
        Ok(false) => ctx.notice(me, from.uid, format!("No watch matches \x02{mask}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn list(me: &str, from: &Sender, verbose: bool, pattern: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let entries = db.notifies();
    if entries.is_empty() {
        ctx.notice(me, from.uid, "The notify list is empty.");
        return;
    }
    let pat = pattern.map(|p| p.to_ascii_lowercase());
    let mut shown = 0;
    for (i, n) in entries.iter().enumerate() {
        if let Some(p) = &pat {
            if !n.mask.to_ascii_lowercase().contains(p.as_str()) {
                continue;
            }
        }
        let expiry = match n.expires {
            Some(e) => format!(", expires in {}", human_secs(e.saturating_sub(now()))),
            None => String::new(),
        };
        if verbose {
            ctx.notice(me, from.uid, format!("{}. \x02{}\x02 [{}] by {} ({}){} — {}", i + 1, n.mask, n.flags, n.setter, human_time(n.ts), expiry, n.reason));
        } else {
            ctx.notice(me, from.uid, format!("{}. \x02{}\x02 [{}] — {}{}", i + 1, n.mask, n.flags, n.reason, expiry));
        }
        shown += 1;
    }
    if shown == 0 {
        ctx.notice(me, from.uid, "No matching notify entries.");
    } else {
        ctx.notice(me, from.uid, format!("End of notify list ({shown} shown)."));
    }
}

// A mask is usable if it's a channel, a hostmask/extban, or a bare nick glob —
// and carries no whitespace (the wire splits on spaces).
fn valid_mask(mask: &str) -> bool {
    !mask.is_empty() && !mask.contains(char::is_whitespace)
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

const FLAG_LEGEND: &str = "c=connect d=disconnect o=oper-up j=join p=part k=kick m=chan-mode t=topic n=nick u=user-mode s=service-cmd S=SET";
const SYNTAX: &str = "Syntax: NOTIFY ADD +<expiry> <flags|*> <mask> <reason> | NOTIFY DEL <mask|number> | NOTIFY LIST [pattern] | NOTIFY VIEW [pattern] | NOTIFY CLEAR";
