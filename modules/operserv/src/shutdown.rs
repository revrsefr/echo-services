use echo_api::{t, Priv, Sender, ServiceCtx};

// SHUTDOWN / RESTART [reason]: stop the services process. `restart` selects
// which — a restart exits so a supervisor respawns us, a shutdown stays down.
// Admin-only, and the heaviest command services have. Announced network-wide
// first so users know why services vanished.
pub fn handle(me: &str, from: &Sender, restart: bool, args: &[&str], ctx: &mut ServiceCtx) {
    let cmd = if restart { "RESTART" } else { "SHUTDOWN" };
    if !from.privs.has(Priv::Root) {
        ctx.notice(me, from.uid, t!(ctx, "Access denied — {cmd} needs the \x02root\x02 privilege.", cmd = cmd));
        return;
    }
    let reason = if args.len() > 1 { args[1..].join(" ") } else { format!("Services {}", if restart { "restarting" } else { "shutting down" }) };
    let by = from.account.unwrap_or(from.nick);
    ctx.global(me, format!("[\x02Network\x02] Services are {} ({reason}).", if restart { "restarting" } else { "going down" }));
    ctx.notice(me, from.uid, if restart { "Services are restarting." } else { "Services are shutting down." });
    // The action is last, so the notices above are flushed before we exit.
    ctx.shutdown(restart, format!("{cmd} by {by}: {reason}"));
}
