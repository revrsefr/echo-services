use echo_api::{CodeKind, Store};
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

// RESETPASS <account>: email a reset code to the address on file.
// RESETPASS <account> <code> <newpassword>: complete the reset with that code.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !db.email_enabled() {
        ctx.notice(me, from.uid, "Password reset by email isn't available here.");
        return;
    }
    match (args.get(1), args.get(2), args.get(3)) {
        (Some(&name), None, None) => {
            let Some(canonical) = db.resolve_account(name).map(str::to_string) else {
                ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 isn't registered.", name = name));
                return;
            };
            let Some(email) = db.account(&canonical).and_then(|a| a.email.clone()) else {
                ctx.notice(me, from.uid, "That account has no email on file, so it can't be reset.");
                return;
            };
            let wait = db.code_issue_wait(&canonical);
            if wait > 0 {
                ctx.notice(me, from.uid, t!(ctx, "A code was just sent — please wait \x02{wait}\x02s before requesting another.", wait = wait));
                return;
            }
            let code = db.issue_code(&canonical, CodeKind::Reset);
            let lang = db.language_of(&canonical).unwrap_or_else(|| db.default_language());
            let mail = echo_api::email::reset(db.email_brand(), db.email_accent(), db.email_logo(), &canonical, &code, &lang);
            ctx.send_email(email, mail.subject, mail.text, Some(mail.html));
            ctx.notice(me, from.uid, t!(ctx, "A reset code has been emailed to the address on file for \x02{canonical}\x02.", canonical = canonical));
        }
        (Some(&name), Some(&code), Some(&newpass)) => {
            let Some(canonical) = db.resolve_account(name).map(str::to_string) else {
                ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 isn't registered.", name = name));
                return;
            };
            if !db.take_code(&canonical, CodeKind::Reset, code) {
                ctx.notice(me, from.uid, "Invalid or expired reset code.");
                return;
            }
            ctx.defer_password(&canonical, newpass, me, from.uid);
        }
        _ => ctx.notice(me, from.uid, "Syntax: RESETPASS <account> [<code> <newpassword>]"),
    }
}
