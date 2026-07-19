use echo_api::Store;
use echo_api::{Sender, ServiceCtx};

// GROUP <account> <password>: link your current nick to an existing account, so
// you can identify to it under this nick too.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(&account), Some(&password)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: GROUP <account> <password>");
        return;
    };
    // Throttle + record the attempt like IDENTIFY, or GROUP is an unthrottled
    // password-guessing oracle against any account (and each ~1s verify blocks the
    // engine). Also feeds the auth audit feed.
    if let Some(secs) = db.auth_lockout(account) {
        ctx.notice(me, from.uid, format!("Too many failed attempts. Please wait {secs}s and try again."));
        return;
    }
    let Some(canonical) = db.authenticate(account, password).map(str::to_string) else {
        db.note_auth(account, false);
        ctx.auth_report(false, Some(account), "NickServ GROUP", from.uid, Some("bad password"));
        ctx.notice(me, from.uid, "Invalid account or password.");
        return;
    };
    db.note_auth(account, true);
    if db.account(from.nick).is_some() {
        ctx.notice(me, from.uid, format!("\x02{}\x02 is itself a registered account.", from.nick));
        return;
    }
    // Guard the namespace like REGISTER does: grouping RESERVES from.nick (SET KILL
    // enforces it), so a look-alike or FORBIDden nick must not be groupable, and one
    // account can't squat an unbounded number of nicks (each grows the log forever).
    if db.confusable_check_enabled() {
        if let Some(reason) = echo_api::confusable_reason(from.nick) {
            ctx.notice(me, from.uid, reason);
            return;
        }
    }
    if db.is_forbidden(echo_api::ForbidKind::Nick, from.nick).is_some() {
        ctx.notice(me, from.uid, format!("The nick \x02{}\x02 is reserved and can't be grouped.", from.nick));
        return;
    }
    const MAX_GROUPED: usize = 25;
    if db.grouped_nicks(&canonical).len() >= MAX_GROUPED {
        ctx.notice(me, from.uid, format!("\x02{canonical}\x02 already has the maximum of {MAX_GROUPED} grouped nicks."));
        return;
    }
    match db.group_nick(from.nick, &canonical) {
        Ok(()) => ctx.notice(me, from.uid, format!("Your nick \x02{}\x02 is now grouped to \x02{canonical}\x02.", from.nick)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
