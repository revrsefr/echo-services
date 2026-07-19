use echo_api::{t, Sender, ServiceCtx, Store};

// DEL <!group> <account>: remove a member. Needs founder or the `f` flag.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, target: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = super::account(me, from, ctx) else { return };
    let (Some(name), Some(target)) = (name, target) else {
        ctx.notice(me, from.uid, "Syntax: DEL <!group> <account>");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 isn't registered.", name = name));
        return;
    };
    if !super::can_manage(&g, acc) {
        ctx.notice(me, from.uid, t!(ctx, "You need the founder or the \x02f\x02 flag to manage \x02{name}\x02.", name = name));
        return;
    }
    match db.group_del_member(name, target) {
        Ok(true) => ctx.notice(me, from.uid, t!(ctx, "Removed \x02{target}\x02 from \x02{name}\x02.", target = target, name = name)),
        Ok(false) => ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 isn't in \x02{name}\x02.", target = target, name = name)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
