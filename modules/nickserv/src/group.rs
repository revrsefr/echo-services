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
    match db.group_nick(from.nick, &canonical) {
        Ok(()) => ctx.notice(me, from.uid, format!("Your nick \x02{}\x02 is now grouped to \x02{canonical}\x02.", from.nick)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
