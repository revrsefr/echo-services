use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};

// GLIST: list the nicks grouped to your account.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let mut nicks = db.grouped_nicks(account);
    nicks.sort();
    ctx.notice(me, from.uid, format!("Nicks grouped to \x02{account}\x02:"));
    ctx.notice(me, from.uid, format!("  \x02{account}\x02 (main)"));
    for n in nicks {
        ctx.notice(me, from.uid, format!("  \x02{n}\x02"));
    }
}
