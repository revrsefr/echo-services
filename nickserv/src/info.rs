use fedserv_api::{human_time, Priv, Store};
use fedserv_api::{Sender, ServiceCtx};

// INFO [account]: show an account's registration details. The email and other
// private fields are shown to the account's own owner, or to an oper with the
// auspex privilege.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &dyn Store) {
    let name = args.get(1).copied().unwrap_or(from.nick);
    let Some(acct) = db.account(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    ctx.notice(me, from.uid, format!("Information for \x02{}\x02:", acct.name));
    ctx.notice(me, from.uid, format!("  Registered : {}", human_time(acct.ts)));
    let is_owner = from.account == Some(acct.name.as_str());
    if is_owner || from.privs.has(Priv::Auspex) {
        if let Some(s) = db.suspension(&acct.name) {
            ctx.notice(me, from.uid, format!("  Suspended  : by \x02{}\x02 — {}", s.by, s.reason));
        }
        match &acct.email {
            Some(email) if acct.verified => ctx.notice(me, from.uid, format!("  Email      : {email}")),
            Some(email) => ctx.notice(me, from.uid, format!("  Email      : {email} (unconfirmed)")),
            None => ctx.notice(me, from.uid, "  Email      : (none set)"),
        }
        let ajoin = db.ajoin_list(&acct.name);
        if !ajoin.is_empty() {
            ctx.notice(me, from.uid, format!("  Auto-join  : {} channel(s) — see \x02AJOIN LIST\x02", ajoin.len()));
        }
    }
}
