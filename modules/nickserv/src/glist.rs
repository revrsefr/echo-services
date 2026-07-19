use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

// GLIST: list the nicks grouped to your account.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let mut nicks = db.grouped_nicks(account);
    nicks.sort();
    ctx.notice(me, from.uid, t!(ctx, "Nicks grouped to \x02{account}\x02:", account = account));
    ctx.notice(me, from.uid, t!(ctx, "  \x02{account}\x02 (main)", account = account));
    for n in nicks {
        ctx.notice(me, from.uid, t!(ctx, "  \x02{n}\x02", n = n));
    }
}
