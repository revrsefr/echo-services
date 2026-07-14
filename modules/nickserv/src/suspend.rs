use echo_api::{parse_duration, NetView, Priv, Sender, ServiceCtx, Store};
use std::time::{SystemTime, UNIX_EPOCH};

// SUSPEND <account> [+expiry] [reason] / UNSUSPEND <account>: freeze or unfreeze
// an account. Its data is kept but it can't be logged into. Oper-only
// (Priv::Suspend). `suspending` selects SUSPEND vs UNSUSPEND.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store, suspending: bool) {
    if !from.privs.has(Priv::Suspend) {
        ctx.notice(me, from.uid, "Access denied — that command is for services operators.");
        return;
    }
    let Some(&target) = args.get(1) else {
        let syntax = if suspending { "Syntax: SUSPEND <account> [+expiry] [reason]" } else { "Syntax: UNSUSPEND <account>" };
        ctx.notice(me, from.uid, syntax);
        return;
    };
    let Some(account) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };

    if !suspending {
        match db.unsuspend_account(&account) {
            Ok(true) => ctx.notice(me, from.uid, format!("\x02{account}\x02 is no longer suspended.")),
            Ok(false) => ctx.notice(me, from.uid, format!("\x02{account}\x02 isn't suspended.")),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        }
        return;
    }

    // Optional leading +expiry (e.g. +30d), then a free-text reason.
    let mut rest = &args[2..];
    let expires = rest.first().and_then(|t| t.strip_prefix('+')).and_then(parse_duration).map(|secs| now_unix() + secs);
    if expires.is_some() {
        rest = &rest[1..];
    }
    let reason = if rest.is_empty() { "No reason given.".to_string() } else { rest.join(" ") };
    let by = from.account.unwrap_or(from.nick);
    match db.suspend_account(&account, by, &reason, expires) {
        Ok(()) => {
            // Log out every session currently identified to the account.
            for uid in net.uids_logged_into(&account) {
                ctx.logout(&uid);
            }
            let expiry = if expires.is_some() { " (with expiry)" } else { "" };
            ctx.notice(me, from.uid, format!("\x02{account}\x02 is now suspended{expiry}."));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
