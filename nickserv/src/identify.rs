use fedserv_api::{human_time, Store};
use fedserv_api::{Sender, ServiceCtx};

// IDENTIFY [account] <password>: log in. The account defaults to the current
// nick, so both the bare-password and account+password forms work.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
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
    // A suspended account can't be logged into (checked before the password so it
    // doesn't reveal whether the password was right). Tell them who, when and why,
    // and when it lifts, so they know what happened and who to reach.
    if let Some(acc) = db.resolve_account(account_name).map(str::to_string) {
        if db.is_suspended(&acc) {
            if let Some(s) = db.suspension(&acc) {
                let mut msg = format!("\x02{acc}\x02 is suspended, so you can't log in to it right now. It was suspended by \x02{}\x02 on {}", s.by, human_time(s.ts));
                if s.reason.trim().is_empty() {
                    msg.push('.');
                } else {
                    msg.push_str(&format!(" — reason: {}", s.reason));
                }
                if let Some(exp) = s.expires {
                    msg.push_str(&format!(" The suspension is due to lift on {}.", human_time(exp)));
                }
                msg.push_str(" If you think this is a mistake, please contact the network staff.");
                ctx.notice(me, from.uid, msg);
            }
            return;
        }
    }
    // Refuse while throttled, so a password can't be brute-forced.
    if let Some(secs) = db.auth_lockout(account_name) {
        ctx.notice(me, from.uid, format!("Too many failed attempts. Please wait {secs}s and try again."));
        return;
    }
    // Take the result as owned so the account-store borrow ends before note_auth.
    match db.authenticate(account_name, password).map(str::to_string) {
        Some(account) => {
            db.note_auth(account_name, true);
            // Already identified to this account: don't re-fire the login.
            if from.account == Some(account.as_str()) {
                ctx.notice(me, from.uid, format!("You're already identified as \x02{}\x02.", account));
                return;
            }
            ctx.login(from.uid, &account);
            ctx.notice(me, from.uid, format!("You're now identified as \x02{}\x02. Welcome back!", account));
            // Apply the account's auto-join list (AJOIN).
            for entry in db.ajoin_list(&account) {
                ctx.force_join(from.uid, &entry.channel, &entry.key);
            }
        }
        None => {
            db.note_auth(account_name, false);
            ctx.notice(me, from.uid, "Invalid password. Please try again.");
        }
    }
}
