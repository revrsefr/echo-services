use echo_api::{Priv, RegReply, Sender, ServiceCtx, Store};

// SAREGISTER <account> <password> [email]: an operator creates an account for someone
// directly. The account is active immediately — no email confirmation and no vouch
// wait — so staff can hand out ready-to-use logins. Admin privilege (like SASET/DROP);
// the requester is NOT logged into the new account. Blocked in website-managed
// (external accounts) mode.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — that command is for services operators.");
        return;
    }
    if db.external_accounts() {
        ctx.notice(me, from.uid, "Accounts are managed on the website — create it there.");
        return;
    }
    let (Some(&account), Some(&password)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: SAREGISTER <account> <password> [email]");
        return;
    };
    if let Err(reason) = crate::password::validate_password(password, account) {
        ctx.notice(me, from.uid, reason);
        return;
    }
    // Refuse a look-alike / mixed-script account name, same as the self-service path.
    if db.confusable_check_enabled() {
        if let Some(reason) = echo_api::confusable_reason(account) {
            ctx.notice(me, from.uid, reason);
            return;
        }
    }
    let email = args.get(3).map(|s| s.to_string());
    if let Some(addr) = &email {
        if !echo_api::valid_email(addr) {
            ctx.notice(me, from.uid, "That doesn't look like a valid email address.");
            return;
        }
    }
    ctx.alert("SAREGISTER", &format!("created account {account}"));
    // The engine derives the password off-thread, commits the account as verified,
    // and NOTICEs the operator via the Admin reply (see engine::reg_reply).
    ctx.defer_register(
        account,
        password,
        email,
        RegReply::Admin {
            agent: me.to_string(),
            uid: from.uid.to_string(),
        },
    );
}
