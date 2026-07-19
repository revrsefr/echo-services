use echo_api::{t, Sender, ServiceCtx, Store};

// DROP <!group>: delete a group. Founder only.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = super::account(me, from, ctx) else { return };
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: DROP <!group>");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 isn't registered.", name = name));
        return;
    };
    if !g.founder.eq_ignore_ascii_case(acc) {
        ctx.notice(me, from.uid, t!(ctx, "Only \x02{name}\x02's founder can drop it.", name = name));
        return;
    }
    match db.group_drop(name) {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Group \x02{name}\x02 has been dropped.", name = name)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
