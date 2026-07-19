use echo_api::{Priv, Sender, ServiceCtx};

// REHASH: re-read config.toml and apply the settings that are safe to change
// while linked (opers, standard-replies, services channel, service oper-type,
// expiry, session limits) without restarting — so no relink and no user
// disruption. Admin-only. Server identity, service umodes and the keycard
// endpoint still need a RESTART. The engine does the re-read off the command
// path and notices the outcome (or a parse error, keeping the old config).
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    if !from.privs.has(Priv::Root) {
        ctx.notice(me, from.uid, "Access denied — REHASH needs the \x02root\x02 privilege.");
        return;
    }
    ctx.rehash(me, from.uid);
}
