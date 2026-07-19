use echo_api::{t, Sender, ServiceCtx, Store};

// ADD <!group> <account>: add a plain member (no flags). Needs founder or `f`.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, target: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = super::account(me, from, ctx) else { return };
    let (Some(name), Some(target)) = (name, target) else {
        ctx.notice(me, from.uid, "Syntax: ADD <!group> <account>");
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
    let Some(canonical) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 isn't registered.", target = target));
        return;
    };
    match db.group_set_flags(name, &canonical, "") {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Added \x02{canonical}\x02 to \x02{name}\x02.", canonical = canonical, name = name)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
