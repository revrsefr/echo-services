use fedserv_api::{Sender, ServiceCtx, Store};

// INFO <!group>: show a group's founder and member count.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: INFO <!group>");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    ctx.notice(me, from.uid, format!("Information for \x02{}\x02:", g.name));
    ctx.notice(me, from.uid, format!("  Founder : \x02{}\x02", g.founder));
    ctx.notice(me, from.uid, format!("  Members : {}", g.members.len()));
}
