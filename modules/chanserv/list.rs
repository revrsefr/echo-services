use crate::engine::db::Db;
use crate::engine::service::{Sender, ServiceCtx};

// LIST: show all registered channels.
pub fn handle(me: &str, from: &Sender, _args: &[&str], ctx: &mut ServiceCtx, db: &Db) {
    let mut names: Vec<&str> = db.channels().map(|c| c.name.as_str()).collect();
    if names.is_empty() {
        ctx.notice(me, from.uid, "No channels are registered.");
        return;
    }
    names.sort_unstable();
    ctx.notice(me, from.uid, format!("Registered channels ({}):", names.len()));
    for n in names {
        ctx.notice(me, from.uid, format!("  \x02{n}\x02"));
    }
}
