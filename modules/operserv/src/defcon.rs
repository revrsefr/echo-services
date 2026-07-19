use echo_api::{t, Priv, Sender, ServiceCtx, Store};

// DEFCON [1-5]: read or set the network defence level. 5 is normal; each lower
// level adds a restriction — 4 freezes channel registrations, 3 freezes all
// registrations, 2 also caps everyone to one session, 1 is a full lockdown that
// turns away new connections. Changing it announces the level to the network.
// Admin-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — DEFCON needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1) {
        None => {
            let desc = describe(ctx, db.defcon());
            ctx.notice(me, from.uid, t!(ctx, "The network is at \x02DEFCON {level}\x02 — {desc}.", level = db.defcon(), desc = desc));
        }
        Some(&arg) => match arg.parse::<u8>() {
            Ok(level) if (1..=5).contains(&level) => {
                db.set_defcon(level);
                let desc = describe(ctx, level);
                ctx.notice(me, from.uid, t!(ctx, "DEFCON set to \x02{level}\x02 — {desc}.", level = level, desc = desc));
                // Let everyone know the posture changed.
                let msg = if level == 5 {
                    "The network is back to normal operations (DEFCON 5).".to_string()
                } else {
                    format!("Network defence level is now \x02DEFCON {level}\x02: {}.", describe(ctx, level))
                };
                ctx.global(me, msg);
            }
            _ => ctx.notice(me, from.uid, "Syntax: DEFCON [1-5] (5 = normal, 1 = lockdown)"),
        },
    }
}

fn describe(ctx: &ServiceCtx, level: u8) -> String {
    match level {
        5 => t!(ctx, "normal operations"),
        4 => t!(ctx, "channel registrations frozen"),
        3 => t!(ctx, "all registrations frozen"),
        2 => t!(ctx, "registrations frozen and sessions capped to one per host"),
        _ => t!(ctx, "full lockdown, no new connections"),
    }
}
