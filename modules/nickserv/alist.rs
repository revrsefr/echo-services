use crate::engine::db::Db;
use crate::engine::service::{Sender, ServiceCtx};

// ALIST: list the channels the sender's account founds or has access on.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &Db) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let mut rows: Vec<(String, &str)> = Vec::new();
    for c in db.channels() {
        if c.founder.eq_ignore_ascii_case(account) {
            rows.push((c.name.clone(), "founder"));
        } else if let Some(a) = c.access.iter().find(|a| a.account.eq_ignore_ascii_case(account)) {
            rows.push((c.name.clone(), if a.level == "voice" { "voice" } else { "op" }));
        }
    }
    if rows.is_empty() {
        ctx.notice(me, from.uid, "You have access on no channels.");
        return;
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    ctx.notice(me, from.uid, format!("Channels you have access on ({}):", rows.len()));
    for (chan, role) in rows {
        ctx.notice(me, from.uid, format!("  \x02{chan}\x02 ({role})"));
    }
}
