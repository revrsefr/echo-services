use echo_api::{t, Sender, ServiceCtx, Store};

// INFO <!group>: show a group's founder and member count.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: INFO <!group>");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 isn't registered.", name = name));
        return;
    };
    ctx.notice(me, from.uid, t!(ctx, "Information for \x02{name}\x02:", name = g.name));
    ctx.notice(me, from.uid, t!(ctx, "  Founder : \x02{founder}\x02", founder = g.founder));
    ctx.notice(me, from.uid, t!(ctx, "  Members : {count}", count = g.members.len()));
}
