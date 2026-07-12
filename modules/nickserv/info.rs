use crate::engine::db::{human_time, Db};
use crate::engine::service::{Sender, ServiceCtx};

// INFO [account]: show an account's registration details. The email is shown
// only to the account's own owner.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &Db) {
    let name = args.get(1).copied().unwrap_or(from.nick);
    let Some(acct) = db.account(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    ctx.notice(me, from.uid, format!("Information for \x02{}\x02:", acct.name));
    ctx.notice(me, from.uid, format!("  Registered : {}", human_time(acct.ts)));
    if from.account == Some(acct.name.as_str()) {
        match &acct.email {
            Some(email) if acct.verified => ctx.notice(me, from.uid, format!("  Email      : {email}")),
            Some(email) => ctx.notice(me, from.uid, format!("  Email      : {email} (unconfirmed)")),
            None => ctx.notice(me, from.uid, "  Email      : (none set)"),
        }
    }
}
