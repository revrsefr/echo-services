use echo_api::{Priv, Sender, ServiceCtx, Store};

// SASET <account> <option> [value]: the operator counterpart of SET, editing
// another account's settings. Oper-only (Priv::Admin). Mirrors the self-service
// SET options that make sense to change on someone else's behalf.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — that command is for services operators.");
        return;
    }
    let (Some(&target), sub) = (args.get(1), args.get(2).map(|s| s.to_ascii_uppercase())) else {
        ctx.notice(me, from.uid, "Syntax: SASET <account> PASSWORD <newpassword> | EMAIL [address] | GREET [message]");
        return;
    };
    let Some(account) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };
    // Credential/identity fields are owned by the website in external mode.
    if db.external_accounts() && matches!(sub.as_deref(), Some("PASSWORD" | "PASS" | "EMAIL")) {
        ctx.notice(me, from.uid, "That's managed on the website — change it there.");
        return;
    }
    match sub.as_deref() {
        Some("PASSWORD") | Some("PASS") => {
            let Some(&password) = args.get(3) else {
                ctx.notice(me, from.uid, "Syntax: SASET <account> PASSWORD <newpassword>");
                return;
            };
            if let Err(reason) = crate::password::validate_password(password, &account) {
                ctx.notice(me, from.uid, reason);
                return;
            }
            // The link layer derives the new password off-thread, then commits it.
            ctx.defer_password(account, password, me, from.uid);
        }
        Some("EMAIL") => {
            let email = args.get(3).map(|s| s.to_string());
            let cleared = email.is_none();
            match db.set_email(&account, email) {
                Ok(()) if cleared => ctx.notice(me, from.uid, format!("Email for \x02{account}\x02 cleared.")),
                Ok(()) => ctx.notice(me, from.uid, format!("Email for \x02{account}\x02 updated.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("GREET") => {
            let greet = if args.len() > 3 { args[3..].join(" ") } else { String::new() };
            let cleared = greet.is_empty();
            match db.set_greet(&account, &greet) {
                Ok(()) if cleared => ctx.notice(me, from.uid, format!("Greet for \x02{account}\x02 cleared.")),
                Ok(()) => ctx.notice(me, from.uid, format!("Greet for \x02{account}\x02 is now: {greet}")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: SASET <account> PASSWORD <newpassword> | EMAIL [address] | GREET [message]"),
    }
}
