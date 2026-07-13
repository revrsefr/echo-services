use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};

// SET PASSWORD <newpassword> | SET EMAIL [address]: change your account settings.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("PASSWORD") | Some("PASS") => {
            let Some(&password) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: SET PASSWORD <newpassword>");
                return;
            };
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
        _ => ctx.notice(me, from.uid, "Syntax: SET PASSWORD <newpassword> | SET EMAIL [address]"),
    }
}
