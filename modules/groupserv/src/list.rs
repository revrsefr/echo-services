use echo_api::{t, Sender, ServiceCtx, Store};

// LIST: operators see every group; others see the ones they belong to.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let names = if from.privs.any() {
        db.groups()
    } else if let Some(acc) = from.account {
        db.groups_of(acc)
    } else {
        Vec::new()
    };
    if names.is_empty() {
        ctx.notice(me, from.uid, "No groups to show.");
        return;
    }
    for n in &names {
        ctx.notice(me, from.uid, t!(ctx, "  \x02{n}\x02", n = n));
    }
    ctx.notice(me, from.uid, echo_api::plural!(ctx, names.len(), one = "End of list ({count} group).", other = "End of list ({count} groups).", count = names.len()));
}
