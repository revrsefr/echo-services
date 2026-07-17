use echo_api::{level_caps, Sender, ServiceCtx, Store};

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
            // Resolve the entry's capabilities rather than string-matching the
            // level, so a role set via granular FLAGS (e.g. "v") reads correctly
            // and isn't mislabelled "op".
            let caps = level_caps(&a.level);
            let role = if caps.op {
                "op"
            } else if caps.auto == Some("+v") {
                "voice"
            } else if caps.auto == Some("+h") {
                "halfop"
            } else {
                "access"
            };
            rows.push((c.name.clone(), role));
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
