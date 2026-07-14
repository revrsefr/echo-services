use fedserv_api::{apply_flags, Sender, ServiceCtx, Store, GROUP_FLAGS};

// FLAGS <!group> [account [+/-flags]]: list, show, or change group-access flags.
// Listing/showing is open; changing needs the founder or the `f` flag.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, target: Option<&str>, delta: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = super::account(me, from, ctx) else { return };
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: FLAGS <!group> [account [+/-flags]]");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    // List.
    let Some(target) = target else {
        ctx.notice(me, from.uid, format!("Flags for \x02{}\x02:", g.name));
        ctx.notice(me, from.uid, format!("  \x02{}\x02 (founder): \x02F\x02", g.founder));
        for m in &g.members {
            ctx.notice(me, from.uid, format!("  \x02{}\x02: \x02{}\x02", m.account, if m.flags.is_empty() { "(member)" } else { &m.flags }));
        }
        return;
    };
    let current = g.members.iter().find(|m| m.account.eq_ignore_ascii_case(target)).map(|m| m.flags.clone());
    // Show one.
    let Some(delta) = delta else {
        match current {
            Some(f) => ctx.notice(me, from.uid, format!("\x02{target}\x02 in \x02{name}\x02: \x02{}\x02", if f.is_empty() { "(member)" } else { &f })),
            None => ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't in \x02{name}\x02.")),
        }
        return;
    };
    // Change — needs founder or f flag.
    if !super::can_manage(&g, acc) {
        ctx.notice(me, from.uid, format!("You need the founder or the \x02f\x02 flag to change \x02{name}\x02."));
        return;
    }
    let Some(canonical) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };
    let updated = match apply_flags(current.as_deref().unwrap_or(""), delta, GROUP_FLAGS) {
        Ok(f) => f,
        Err(bad) => {
            ctx.notice(me, from.uid, format!("\x02{bad}\x02 isn't a valid group flag. Valid: \x02{GROUP_FLAGS}\x02."));
            return;
        }
    };
    match db.group_set_flags(name, &canonical, &updated) {
        Ok(()) => ctx.notice(me, from.uid, format!("\x02{canonical}\x02 in \x02{name}\x02 now holds \x02{}\x02.", if updated.is_empty() { "(member)" } else { &updated })),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
