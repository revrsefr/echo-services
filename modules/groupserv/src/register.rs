use echo_api::{t, Sender, ServiceCtx, Store};

// REGISTER <!group>: create a group with you as its founder.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = super::account(me, from, ctx) else { return };
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: REGISTER <!group>");
        return;
    };
    if !name.starts_with('!') || name.len() < 2 {
        ctx.notice(me, from.uid, "A group name starts with \x02!\x02, e.g. \x02!staff\x02.");
        return;
    }
    // Honour the registration freeze staff raise during a spam wave, like
    // NickServ/ChanServ REGISTER — otherwise the group namespace stays open.
    if db.registrations_frozen() {
        ctx.notice(me, from.uid, "Group registration is temporarily disabled. Please try again later.");
        return;
    }
    // Guard the group namespace like NickServ/ChanServ REGISTER: a look-alike group
    // name (!аdmin) could impersonate a real one that opers grant channel access to.
    if db.confusable_check_enabled() {
        if let Some(reason) = echo_api::confusable_reason(name) {
            ctx.notice(me, from.uid, reason);
            return;
        }
    }
    // Cap groups per founder so the append-only log can't be grown without bound
    // (mirrors NickServ's grouped-nick and AJOIN caps).
    const MAX_GROUPS: usize = 25;
    if db.groups_founded(acc) >= MAX_GROUPS {
        ctx.notice(me, from.uid, t!(ctx, "You've reached the maximum of {max} registered groups.", max = MAX_GROUPS));
        return;
    }
    let acc = acc.to_string();
    match db.group_register(name, &acc) {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Group \x02{name}\x02 registered — you're the founder.", name = name)),
        Err(echo_api::ChanError::Exists) => ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 is already registered.", name = name)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
