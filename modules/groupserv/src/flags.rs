use echo_api::{t, GroupFlags, Sender, ServiceCtx, Store, GROUP_FLAGS};

// FLAGS <!group> [account [+/-flags]]: list, show, or change group-access flags.
// Listing/showing is open; changing needs the founder or the `f` flag.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, target: Option<&str>, delta: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = super::account(me, from, ctx) else { return };
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: FLAGS <!group> [account [+/-flags]]");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 isn't registered.", name = name));
        return;
    };
    // List.
    let Some(target) = target else {
        ctx.notice(me, from.uid, t!(ctx, "Flags for \x02{name}\x02:", name = g.name));
        ctx.notice(me, from.uid, t!(ctx, "  \x02{founder}\x02 (founder): \x02F\x02", founder = g.founder));
        for m in &g.members {
            ctx.notice(me, from.uid, t!(ctx, "  \x02{account}\x02: \x02{flags}\x02", account = m.account, flags = if m.flags.is_empty() { "(member)" } else { &m.flags }));
        }
        return;
    };
    let current = g.members.iter().find(|m| m.account.eq_ignore_ascii_case(target)).map(|m| m.flags.clone());
    // Show one.
    let Some(delta) = delta else {
        match current {
            Some(f) => ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 in \x02{name}\x02: \x02{flags}\x02", target = target, name = name, flags = if f.is_empty() { "(member)" } else { &f })),
            None => ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 isn't in \x02{name}\x02.", target = target, name = name)),
        }
        return;
    };
    // Change — needs founder or f flag.
    if !super::can_manage(&g, acc) {
        ctx.notice(me, from.uid, t!(ctx, "You need the founder or the \x02f\x02 flag to change \x02{name}\x02.", name = name));
        return;
    }
    let Some(canonical) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 isn't registered.", target = target));
        return;
    };
    let updated = match GroupFlags::parse(current.as_deref().unwrap_or("")).apply_delta(delta) {
        Ok(f) => f,
        Err(bad) => {
            ctx.notice(me, from.uid, t!(ctx, "\x02{bad}\x02 isn't a valid group flag. Valid: \x02{valid}\x02.", bad = bad, valid = GROUP_FLAGS));
            return;
        }
    };
    let letters = updated.to_letters();
    match db.group_set_flags(name, &canonical, &letters) {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "\x02{canonical}\x02 in \x02{name}\x02 now holds \x02{flags}\x02.", canonical = canonical, name = name, flags = if letters.is_empty() { "(member)" } else { &letters })),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
