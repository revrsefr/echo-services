use echo_api::{Priv, Sender, ServiceCtx, Store};

// BOTLIST: show the bots a channel founder can assign. Available to everyone,
// unlike \x02BOT LIST\x02 (operator bot administration). Private bots are hidden
// from ordinary users but shown, flagged, to operators.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    let is_oper = from.privs.has(Priv::Admin);
    let bots: Vec<_> = db.bots().into_iter().filter(|b| is_oper || !b.private).collect();
    if bots.is_empty() {
        ctx.notice(me, from.uid, "No bots are available.");
        return;
    }
    ctx.notice(me, from.uid, format!("Available bots ({}):", bots.len()));
    for b in &bots {
        let flag = if b.private { " \x02[private]\x02" } else { "" };
        ctx.notice(me, from.uid, format!("  \x02{}\x02 ({}@{}){flag}", b.nick, b.user, b.host));
    }
    ctx.notice(me, from.uid, "Assign one with \x02ASSIGN <#channel> <bot>\x02.");
}
