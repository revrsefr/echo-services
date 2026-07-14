use fedserv_api::{parse_duration, NetView, Priv, Sender, ServiceCtx, Store};
use std::time::{SystemTime, UNIX_EPOCH};

// SUSPEND <#channel> [+expiry] [reason] / UNSUSPEND <#channel>: freeze or unfreeze
// a channel. Its data is kept but it can't be managed while suspended. Oper-only
// (Priv::Suspend). `suspending` selects SUSPEND vs UNSUSPEND.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store, suspending: bool) {
    if !from.privs.has(Priv::Suspend) {
        ctx.notice(me, from.uid, "Access denied — that command is for services operators.");
        return;
    }
    let Some(&chan) = args.get(1) else {
        let syntax = if suspending { "Syntax: SUSPEND <#channel> [+expiry] [reason]" } else { "Syntax: UNSUSPEND <#channel>" };
        ctx.notice(me, from.uid, syntax);
        return;
    };
    if db.channel(chan).is_none() {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
        return;
    }

    if !suspending {
        match db.unsuspend_channel(chan) {
            Ok(true) => ctx.notice(me, from.uid, format!("\x02{chan}\x02 is no longer suspended.")),
            Ok(false) => ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't suspended.")),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        }
        return;
    }

    let mut rest = &args[2..];
    let expires = rest.first().and_then(|t| t.strip_prefix('+')).and_then(parse_duration).map(|secs| now_unix() + secs);
    if expires.is_some() {
        rest = &rest[1..];
    }
    let reason = if rest.is_empty() { "This channel has been suspended.".to_string() } else { rest.join(" ") };
    let by = from.account.unwrap_or(from.nick);
    match db.suspend_channel(chan, by, &reason, expires) {
        Ok(()) => {
            // Clear the channel: kick everyone currently in it.
            for uid in net.channel_members(chan) {
                ctx.kick(me, chan, &uid, &reason);
            }
            let expiry = if expires.is_some() { " (with expiry)" } else { "" };
            ctx.notice(me, from.uid, format!("\x02{chan}\x02 is now suspended{expiry}."));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
