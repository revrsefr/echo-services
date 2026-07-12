use crate::engine::db::Db;
use crate::engine::service::{Sender, ServiceCtx};

// GROUP <account> <password>: link your current nick to an existing account, so
// you can identify to it under this nick too.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut Db) {
    let (Some(&account), Some(&password)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: GROUP <account> <password>");
        return;
    };
    let Some(canonical) = db.authenticate(account, password).map(str::to_string) else {
        ctx.notice(me, from.uid, "Invalid account or password.");
        return;
    };
    if db.account(from.nick).is_some() {
        ctx.notice(me, from.uid, format!("\x02{}\x02 is itself a registered account.", from.nick));
        return;
    }
    match db.group_nick(from.nick, &canonical) {
        Ok(()) => ctx.notice(me, from.uid, format!("Your nick \x02{}\x02 is now grouped to \x02{canonical}\x02.", from.nick)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
