use echo_api::{Priv, Sender, ServiceCtx, Store};

// GETEMAIL <email>: list accounts registered with a matching email. Oper-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &dyn Store) {
    if !from.privs.has(Priv::Auspex) {
        ctx.notice(me, from.uid, "Access denied — GETEMAIL needs the \x02auspex\x02 privilege.");
        return;
    }
    let Some(&pattern) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: GETEMAIL <email>");
        return;
    };
    let accounts = db.accounts_by_email(pattern);
    if accounts.is_empty() {
        ctx.notice(me, from.uid, format!("No accounts use an email matching \x02{pattern}\x02."));
        return;
    }
    ctx.notice(me, from.uid, format!("Accounts with email matching \x02{pattern}\x02: {}", accounts.join(", ")));
}
