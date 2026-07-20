use echo_api::{human_time, t, ForbidKind, Priv, Sender, ServiceCtx, Store};

// FORBID ADD <NICK|CHAN|EMAIL> <mask> <reason> | DEL <NICK|CHAN|EMAIL> <mask> | LIST
// Bans a nick, channel, or email pattern from being registered. Admin-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — FORBID needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => {
            let (Some(kind), Some(&mask)) = (args.get(2).and_then(|k| ForbidKind::from_name(k)), args.get(3)) else {
                ctx.notice(me, from.uid, "Syntax: FORBID ADD <NICK|CHAN|EMAIL> <mask> <reason>");
                return;
            };
            if args.len() < 5 {
                ctx.notice(me, from.uid, "Please give a reason.");
                return;
            }
            let reason = args[4..].join(" ");
            let setter = from.account.unwrap_or(from.nick);
            let label = kind.wire().to_lowercase();
            let ok = match db.forbid_add(kind, mask, setter, &reason) {
                Ok(true) => { ctx.notice(me, from.uid, t!(ctx, "Forbade {label} \x02{mask}\x02.", label = label, mask = mask)); true }
                Ok(false) => { ctx.notice(me, from.uid, t!(ctx, "Updated the forbid on {label} \x02{mask}\x02.", label = label, mask = mask)); true }
                Err(_) => { ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."); false }
            };
            // A forbidden NICK is Q-lined so it can't even be USED, not only registered.
            if ok && matches!(kind, ForbidKind::Nick) {
                ctx.add_line(echo_api::XlineKind::Qline, mask, setter, 0, &reason);
            }
        }
        Some("DEL") | Some("REMOVE") => {
            let (Some(kind), Some(&mask)) = (args.get(2).and_then(|k| ForbidKind::from_name(k)), args.get(3)) else {
                ctx.notice(me, from.uid, "Syntax: FORBID DEL <NICK|CHAN|EMAIL> <mask>");
                return;
            };
            let label = kind.wire().to_lowercase();
            match db.forbid_del(kind, mask) {
                Ok(true) => {
                    ctx.notice(me, from.uid, t!(ctx, "Removed the forbid on {label} \x02{mask}\x02.", label = label, mask = mask));
                    if matches!(kind, ForbidKind::Nick) {
                        ctx.del_line(echo_api::XlineKind::Qline, mask);
                    }
                }
                Ok(false) => ctx.notice(me, from.uid, t!(ctx, "No forbid on {label} \x02{mask}\x02.", label = label, mask = mask)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("LIST") | Some("VIEW") => {
            let forbids = db.forbids();
            if forbids.is_empty() {
                ctx.notice(me, from.uid, "The forbid list is empty.");
                return;
            }
            ctx.notice(me, from.uid, "Registration bans:");
            for f in forbids.iter().take(echo_api::LIST_CAP) {
                ctx.notice(me, from.uid, t!(ctx, "  [{kind}] \x02{mask}\x02 by {setter} ({when}) — {reason}", kind = f.kind.wire(), mask = f.mask, setter = f.setter, when = human_time(f.ts), reason = f.reason));
            }
            if forbids.len() > echo_api::LIST_CAP {
                ctx.notice(me, from.uid, t!(ctx, "… and \x02{more}\x02 more; showing the first {cap}.", more = forbids.len() - echo_api::LIST_CAP, cap = echo_api::LIST_CAP));
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: FORBID ADD <NICK|CHAN|EMAIL> <mask> <reason> | DEL <NICK|CHAN|EMAIL> <mask> | LIST"),
    }
}
