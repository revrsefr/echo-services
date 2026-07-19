use echo_api::{Flags, Sender, ServiceCtx, Store, ACCESS_FLAGS};
use echo_api::t;

// FLAGS <#channel> [account [+/-flags]]: the granular access model. With no
// account, list the access entries and their flags; with an account, show or
// change its flags. Letters: f full o auto-op O op h auto-halfop v auto-voice
// t topic i invite a access-list s settings g greet. Viewing needs op access;
// changing needs the founder or the \x02a\x02 flag. Every stored level — a tier
// preset ("op"/"sop"/…) or a raw flag string — resolves through `Flags`.
pub fn handle(me: &str, from: &Sender, chan: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(info) = db.channel(chan) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 isn't registered.", chan = chan));
        return;
    };
    let is_founder = from.account == Some(info.founder.as_str());
    let caps = info.caps_of(from.account);

    // FLAGS <#chan> — list.
    let Some(&target) = args.get(2) else {
        if !is_founder && !caps.op {
            ctx.notice(me, from.uid, t!(ctx, "You need access to \x02{chan}\x02 to view its flags.", chan = chan));
            return;
        }
        ctx.notice(me, from.uid, t!(ctx, "Access flags for \x02{chan}\x02:", chan = chan));
        ctx.notice(me, from.uid, t!(ctx, "  \x02{founder}\x02 (founder): \x02f\x02", founder = info.founder));
        for a in &info.access {
            ctx.notice(me, from.uid, t!(ctx, "  \x02{account}\x02: \x02{flags}\x02", account = a.account, flags = Flags::from_level(&a.level).to_letters()));
        }
        ctx.notice(me, from.uid, t!(ctx, "End of flags ({count} entr{suffix}).", count = info.access.len() + 1, suffix = if info.access.is_empty() { "y" } else { "ies" }));
        return;
    };

    let entry = info.access.iter().find(|a| a.account.eq_ignore_ascii_case(target)).map(|a| a.level.clone());

    // FLAGS <#chan> <account> — show one.
    let Some(&delta) = args.get(3) else {
        match entry.as_deref().map(|l| Flags::from_level(l).to_letters()) {
            Some(f) if !f.is_empty() => ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 on \x02{chan}\x02: \x02{flags}\x02", target = target, chan = chan, flags = f)),
            _ => ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 has no access to \x02{chan}\x02.", target = target, chan = chan)),
        }
        return;
    };

    // FLAGS <#chan> <account> <+/-flags> — modify.
    if !is_founder && !caps.access {
        ctx.notice(me, from.uid, t!(ctx, "You need the founder or the \x02a\x02 flag to change access on \x02{chan}\x02.", chan = chan));
        return;
    }
    if super::suspended_block(me, from, chan, ctx, db) {
        return; // a staff-suspended channel is frozen: no flag changes either
    }
    if info.founder.eq_ignore_ascii_case(target) {
        ctx.notice(me, from.uid, "The founder's access is set with \x02SET FOUNDER\x02, not flags.");
        return;
    }
    let updated = match Flags::from_level(entry.as_deref().unwrap_or("")).apply_delta(delta) {
        Ok(f) => f,
        Err(bad) => {
            ctx.notice(me, from.uid, t!(ctx, "\x02{bad}\x02 isn't a valid flag. Valid flags: \x02{valid}\x02.", bad = bad, valid = ACCESS_FLAGS));
            return;
        }
    };
    // The `a` flag delegates access-list management, but only the founder may grant
    // `f` (founder/co-founder) — otherwise a delegate could mint a founder-equivalent
    // entry (Rank::Founder) and seize the channel.
    if !is_founder && updated.has(echo_api::Flag::Founder) {
        ctx.notice(me, from.uid, t!(ctx, "Only the founder can grant the \x02f\x02 flag on \x02{chan}\x02.", chan = chan));
        return;
    }
    if updated.is_empty() {
        match db.access_del(chan, target) {
            Ok(true) => ctx.notice(me, from.uid, t!(ctx, "Cleared \x02{target}\x02's access to \x02{chan}\x02.", target = target, chan = chan)),
            _ => ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 had no access to \x02{chan}\x02.", target = target, chan = chan)),
        }
        return;
    }
    let letters = updated.to_letters();
    match db.access_add(chan, target, &letters) {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 on \x02{chan}\x02 now holds \x02{letters}\x02.", target = target, chan = chan, letters = letters)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
