use echo_api::{t, NetView, Priv, Sender, ServiceCtx, Store};

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
    // The generic service counters. GameServ's ranked-ladder counters
    // (`game.<type>.<w|l|d>.<account>`) live in the same registry but would flood
    // this list, so they are summarised in the GAMES section instead.
    for (key, value) in &counters {
        if key.starts_with("game.") {
            continue;
        }
        ctx.notice(me, from.uid, format!("  {key}: {value}"));
    }
    // GAMES: per game type, ranked games played and distinct players.
    let mut header = false;
    for ty in ["chess", "c4", "ttt"] {
        let prefix = format!("game.{ty}.");
        let (mut wins, mut draws) = (0u64, 0u64);
        let mut players = std::collections::BTreeSet::new();
        for (key, value) in &counters {
            let Some(rest) = key.strip_prefix(&prefix) else { continue };
            let Some((kind, account)) = rest.split_once('.') else { continue };
            players.insert(account);
            match kind {
                "w" => wins += value,
                "d" => draws += value,
                _ => {}
            }
        }
        // Each decisive game records one win; each draw records `d` for both sides.
        let games = wins + draws / 2;
        if games > 0 {
            if !header {
                ctx.notice(me, from.uid, "  games:");
                header = true;
            }
            ctx.notice(me, from.uid, t!(ctx, "    {ty}: {games} games, {n} players", ty = ty, games = games, n = players.len()));
        }
    }
}
