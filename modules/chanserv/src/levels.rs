use echo_api::Store;
use echo_api::{AccessRole, LevelCap, Sender, ServiceCtx};
use echo_api::t;

// LEVELS <#channel> [SET <capability> <tier> | RESET <capability>]
// Tune which access tier holds each channel capability (OP, TOPIC, INVITE, ACCESS).
// Additive — it grants a capability to a lower tier, so it can never lock anyone
// out. Founder only. With no sub-command it shows the current matrix.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: LEVELS <#channel> [SET <capability> <tier> | RESET <capability>]");
        return;
    };
    match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
        None | Some("LIST") | Some("VIEW") => list(me, from, chan, ctx, db),
        Some("SET") => set(me, from, chan, &args[3..], ctx, db),
        Some("RESET") | Some("DEL") => reset(me, from, chan, args.get(3).copied(), ctx, db),
        _ => ctx.notice(me, from.uid, "Syntax: LEVELS <#channel> [SET <capability> <tier> | RESET <capability>]"),
    }
}

fn list(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(info) = db.channel(chan) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 isn't registered.", chan = chan));
        return;
    };
    ctx.notice(me, from.uid, t!(ctx, "Access levels for \x02{name}\x02 (capability → minimum tier):", name = info.name));
    for cap in LevelCap::ALL {
        let (tier, tag) = match info.levels.iter().find(|(c, _)| *c == cap) {
            Some((_, role)) => (*role, "  (custom)"),
            None => (cap.default_role(), ""),
        };
        ctx.notice(me, from.uid, t!(ctx, "  \x02{cap}\x02 — {tier}{tag}", cap = cap.name(), tier = tier_word(tier), tag = tag));
    }
    ctx.notice(me, from.uid, "Founder: \x02LEVELS <#chan> SET <capability> <tier>\x02 grants it to that tier and above; \x02RESET\x02 restores the default.");
}

fn set(me: &str, from: &Sender, chan: &str, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_founder(me, from, chan, ctx, db) {
        return;
    }
    let (Some(&cap_s), Some(&tier_s)) = (rest.first(), rest.get(1)) else {
        ctx.notice(me, from.uid, "Syntax: LEVELS <#channel> SET <capability> <tier>");
        return;
    };
    let Some(cap) = LevelCap::parse(cap_s) else {
        ctx.notice(me, from.uid, "Unknown capability. One of: \x02OP\x02, \x02TOPIC\x02, \x02INVITE\x02, \x02ACCESS\x02.");
        return;
    };
    let role = match AccessRole::parse(tier_s) {
        Some(AccessRole::Founder) => {
            ctx.notice(me, from.uid, "Granting to \x02FOUNDER\x02 is redundant. Pick \x02VOP\x02, \x02HOP\x02, \x02AOP\x02, or \x02SOP\x02.");
            return;
        }
        Some(r) => r,
        None => {
            ctx.notice(me, from.uid, "Unknown tier. One of: \x02VOP\x02, \x02HOP\x02, \x02AOP\x02, \x02SOP\x02.");
            return;
        }
    };
    match db.level_set(chan, cap.name(), tier_word(role)) {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "\x02{cap}\x02 on \x02{chan}\x02 is now held by \x02{tier}\x02 and above.", cap = cap.name(), chan = chan, tier = tier_word(role))),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn reset(me: &str, from: &Sender, chan: &str, cap_arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_founder(me, from, chan, ctx, db) {
        return;
    }
    let Some(cap_s) = cap_arg else {
        ctx.notice(me, from.uid, "Syntax: LEVELS <#channel> RESET <capability>");
        return;
    };
    let Some(cap) = LevelCap::parse(cap_s) else {
        ctx.notice(me, from.uid, "Unknown capability. One of: \x02OP\x02, \x02TOPIC\x02, \x02INVITE\x02, \x02ACCESS\x02.");
        return;
    };
    match db.level_reset(chan, cap.name()) {
        Ok(true) => ctx.notice(me, from.uid, t!(ctx, "\x02{cap}\x02 on \x02{chan}\x02 is back to its default tier (\x02{tier}\x02).", cap = cap.name(), chan = chan, tier = tier_word(cap.default_role()))),
        Ok(false) => ctx.notice(me, from.uid, t!(ctx, "\x02{cap}\x02 on \x02{chan}\x02 has no custom level.", cap = cap.name(), chan = chan)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

// The tier word for display / storage (SOP/AOP/HOP/VOP; founder falls back to its label).
fn tier_word(role: AccessRole) -> &'static str {
    role.xop_word().unwrap_or("FOUNDER")
}
