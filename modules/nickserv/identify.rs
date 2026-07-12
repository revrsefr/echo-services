use crate::engine::db::Db;
use crate::engine::service::{Sender, ServiceCtx};

// IDENTIFY [account] <password>: log in. The account defaults to the current
// nick, so both the bare-password and account+password forms work.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &Db) {
    let (account_name, password) = match (args.get(1), args.get(2)) {
        (Some(account), Some(password)) => (*account, *password),
        (Some(password), None) => (from.nick, *password),
        _ => {
            ctx.notice(me, from.uid, "Syntax: IDENTIFY [account] <password>");
            return;
        }
    };
    // Distinguish an unregistered account from a wrong password.
    if !db.exists(account_name) {
        ctx.notice(me, from.uid, format!("\x02{account_name}\x02 isn't registered."));
        return;
    }
    match db.authenticate(account_name, password) {
        Some(account) => {
            // Already identified to this account: don't re-fire the login.
            if from.account == Some(account) {
                ctx.notice(me, from.uid, format!("You're already identified as \x02{}\x02.", account));
                return;
            }
            let account = account.to_string();
            ctx.login(from.uid, &account);
            ctx.notice(me, from.uid, format!("You're now identified as \x02{}\x02. Welcome back!", account));
        }
        None => ctx.notice(me, from.uid, "Invalid password. Please try again."),
    }
}
