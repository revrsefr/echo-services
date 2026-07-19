use echo_api::{access_role, Sender, ServiceCtx, Store};
use echo_api::t;

// ALIST: list the channels the sender's account founds or has access on.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let mut rows: Vec<(String, &str)> = Vec::new();
    for c in db.channels() {
        if c.founder.eq_ignore_ascii_case(account) {
            rows.push((c.name.clone(), "founder"));
        } else if let Some(a) = c.access.iter().find(|a| a.account.eq_ignore_ascii_case(account)) {
            // Classify by resolved capability, not the raw level string, so a role
            // set via granular FLAGS reads under the same tier XOP would show.
            rows.push((c.name.clone(), access_role(&a.level).label()));
        }
    }
    if rows.is_empty() {
        ctx.notice(me, from.uid, "You have access on no channels.");
        return;
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    ctx.notice(me, from.uid, t!(ctx, "Channels you have access on ({count}):", count = rows.len()));
    for (chan, role) in rows {
        ctx.notice(me, from.uid, t!(ctx, "  \x02{chan}\x02 ({role})", chan = chan, role = role));
    }
}
