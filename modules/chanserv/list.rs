use crate::engine::db::Store;
use crate::engine::service::{Sender, ServiceCtx};

// LIST: show all registered channels.
pub fn handle(me: &str, from: &Sender, _args: &[&str], ctx: &mut ServiceCtx, db: &dyn Store) {
    let mut names: Vec<String> = db.channels().into_iter().map(|c| c.name).collect();
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
