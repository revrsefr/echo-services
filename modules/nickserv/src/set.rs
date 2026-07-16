use echo_api::Store;
use echo_api::{Sender, ServiceCtx};

// SET PASSWORD <newpassword> | SET EMAIL [address]: change your account settings.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let sub = args.get(1).map(|s| s.to_ascii_uppercase());
    // Credential/identity fields are owned by the website in external mode.
    if db.external_accounts() && matches!(sub.as_deref(), Some("PASSWORD" | "PASS" | "EMAIL")) {
        ctx.notice(me, from.uid, "That's managed on the website — change it there.");
        return;
    }
    match sub.as_deref() {
        Some("PASSWORD") | Some("PASS") => {
            let Some(&password) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: SET PASSWORD <newpassword>");
                return;
            };
            if let Err(reason) = crate::password::validate_password(password, account) {
                ctx.notice(me, from.uid, reason);
                return;
            }
            // The link layer derives the new password off-thread, then commits it.
            ctx.defer_password(account, password, me, from.uid);
        }
        Some("EMAIL") => {
            let email = args.get(2).map(|s| s.to_string());
            let cleared = email.is_none();
            match db.set_email(account, email) {
                Ok(()) if cleared => ctx.notice(me, from.uid, format!("Email for \x02{account}\x02 cleared.")),
                Ok(()) => ctx.notice(me, from.uid, format!("Email for \x02{account}\x02 updated.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("AUTOOP") => {
            let Some(on) = args.get(2).and_then(|s| parse_toggle(s)) else {
                let state = if db.account_wants_autoop(account) { "ON" } else { "OFF" };
                ctx.notice(me, from.uid, format!("AUTOOP is \x02{state}\x02. Syntax: SET AUTOOP {{ON|OFF}}"));
                return;
            };
            match db.set_account_autoop(account, on) {
                Ok(()) if on => ctx.notice(me, from.uid, "You will be auto-opped where you have channel access."),
                Ok(()) => ctx.notice(me, from.uid, "You will no longer be auto-opped; op yourself with \x02/msg ChanServ UP\x02."),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("GREET") => {
            // A bot shows this when you join a greet-enabled channel; no arg clears it.
            let greet = if args.len() > 2 { args[2..].join(" ") } else { String::new() };
            let cleared = greet.is_empty();
            match db.set_greet(account, &greet) {
                Ok(()) if cleared => ctx.notice(me, from.uid, "Your greet has been cleared."),
                Ok(()) => ctx.notice(me, from.uid, format!("Your greet is now: {greet}")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: SET PASSWORD <newpassword> | SET EMAIL [address] | SET GREET [message] | SET AUTOOP {ON|OFF}"),
    }
}

fn parse_toggle(s: &str) -> Option<bool> {
    match s.to_ascii_uppercase().as_str() {
        "ON" | "TRUE" | "YES" => Some(true),
        "OFF" | "FALSE" | "NO" => Some(false),
        _ => None,
    }
}
