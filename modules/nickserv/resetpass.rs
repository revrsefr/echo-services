use crate::engine::db::Db;
use crate::engine::service::{Sender, ServiceCtx};

// RESETPASS <account>: email a reset code to the address on file.
// RESETPASS <account> <code> <newpassword>: complete the reset with that code.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut Db) {
    if !db.email_enabled() {
        ctx.notice(me, from.uid, "Password reset by email isn't available here.");
        return;
    }
    match (args.get(1), args.get(2), args.get(3)) {
        (Some(&name), None, None) => {
            let Some(canonical) = db.resolve_account(name).map(str::to_string) else {
                ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
                return;
            };
            let Some(email) = db.account(&canonical).and_then(|a| a.email.clone()) else {
                ctx.notice(me, from.uid, "That account has no email on file, so it can't be reset.");
                return;
            };
            let code = db.issue_reset_code(&canonical);
            ctx.send_email(
                email,
                format!("Password reset for {canonical}"),
                format!("Your password reset code for {canonical} is: {code}\nIt expires in 15 minutes. Reset with:\n  /msg NickServ RESETPASS {canonical} {code} <newpassword>"),
            );
            ctx.notice(me, from.uid, format!("A reset code has been emailed to the address on file for \x02{canonical}\x02."));
        }
        (Some(&name), Some(&code), Some(&newpass)) => {
            let Some(canonical) = db.resolve_account(name).map(str::to_string) else {
                ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
                return;
            };
            if !db.take_reset_code(&canonical, code) {
                ctx.notice(me, from.uid, "Invalid or expired reset code.");
                return;
            }
            ctx.defer_password(&canonical, newpass, me, from.uid);
        }
        _ => ctx.notice(me, from.uid, "Syntax: RESETPASS <account> [<code> <newpassword>]"),
    }
}
