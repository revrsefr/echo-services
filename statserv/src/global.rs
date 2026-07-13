use fedserv_api::{NetView, Priv, Sender, ServiceCtx, Store};

// SERVER: the shared, cross-service counter registry plus a couple of live
// gauges. Operators only (Priv::Auspex), since it is network-wide.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    if !from.privs.has(Priv::Auspex) {
        ctx.notice(me, from.uid, "Network statistics are for services operators.");
        return;
    }
    ctx.notice(me, from.uid, "Network statistics:");
    ctx.notice(me, from.uid, format!("  channels.total: {}", db.channels().len()));
    ctx.notice(me, from.uid, format!("  bots.total: {}", db.bots().len()));
    let counters = net.stat_counters();
    if counters.is_empty() {
        ctx.notice(me, from.uid, "  (no activity counters yet)");
        return;
    }
    for (key, value) in counters {
        ctx.notice(me, from.uid, format!("  {key}: {value}"));
    }
}
