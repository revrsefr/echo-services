use fedserv_api::{CodeKind, Store};
use fedserv_api::{Sender, ServiceCtx};

// CONFIRM <code>: confirm your account's email with the code you were emailed.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&code) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: CONFIRM <code>");
        return;
    };
    let Some(account) = from.account.map(str::to_string).or_else(|| db.resolve_account(from.nick).map(str::to_string)) else {
        ctx.notice(me, from.uid, "You don't have an account to confirm.");
        return;
    };
    if db.is_verified(&account) {
        ctx.notice(me, from.uid, format!("\x02{account}\x02 is already confirmed."));
        return;
    }
    if !db.take_code(&account, CodeKind::Confirm, code) {
        ctx.notice(me, from.uid, "Invalid or expired confirmation code.");
        return;
    }
    match db.verify_account(&account) {
        Ok(()) => ctx.notice(me, from.uid, format!("\x02{account}\x02 is now confirmed. Thanks!")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
