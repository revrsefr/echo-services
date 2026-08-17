use echo_api::NetView;
use echo_api::Store;
use echo_api::t;
use echo_api::{ChanError, ForbidKind, Sender, ServiceCtx};

// RENAME <#old> <#new>: move a registered channel to a new name, keeping all its
// settings and — on the ircd — its live membership, modes and topic. Founder
// only. The new name must be a free, allowed channel name that nobody's sitting
// in, so the ircd's in-place rename can't collide.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let (Some(&old), Some(&new)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: RENAME <#channel> <#newname>");
        return;
    };
    if !new.starts_with('#') {
        ctx.notice(me, from.uid, "Channel names start with \x02#\x02.");
        return;
    }
    // Founder-only, and never a suspended or unregistered channel — the shared
    // guard covers all three (with already-translated replies).
    if !crate::require_founder(me, from, old, ctx, &*db) {
        return;
    }
    let case_only = old.eq_ignore_ascii_case(new);
    // The target must be free: not registered, and not a channel people are in
    // (the ircd refuses to rename onto an occupied name). A case-only change is
    // the same channel, so neither check applies to it.
    if !case_only {
        if db.channel(new).is_some() {
            ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 is already registered.", name = new));
            return;
        }
        if !net.channel_members(new).is_empty() {
            ctx.notice(me, from.uid, t!(ctx, "\x02{new}\x02 is already in use. Pick another name.", new = new));
            return;
        }
    }
    if let Some(reason) = db.is_forbidden(ForbidKind::Chan, new) {
        ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 can't be registered: {reason}", chan = new, reason = reason));
        return;
    }
    // Refuse a look-alike / mixed-script target, as REGISTER does.
    if db.confusable_check_enabled() {
        if let Some(reason) = echo_api::confusable_reason(new) {
            ctx.alert("RENAME", format!("tried to rename \x02{old}\x02 to the look-alike \x02{new}\x02 (blocked)"));
            ctx.notice(me, from.uid, reason);
            return;
        }
    }
    match db.rename_channel(old, new) {
        Ok(()) => {
            // Move the live channel on the ircd (members/modes/topic intact).
            ctx.rename_channel(me, old, new, "Channel renamed by founder");
            ctx.count("chanserv.rename");
            ctx.notice(me, from.uid, t!(ctx, "\x02{old}\x02 has been renamed to \x02{new}\x02.", old = old, new = new));
        }
        Err(ChanError::Exists) => ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 is already registered.", name = new)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
