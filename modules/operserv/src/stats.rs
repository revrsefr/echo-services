use echo_api::{Priv, Sender, ServiceCtx, Store, XlineKind};

// STATS: an at-a-glance summary of the enforcement state OperServ holds — how
// many network bans of each kind and how many services ignores are live.
// Read-only, so any operator may run it (the module is already oper-gated).
pub fn handle(me: &str, from: &Sender, db: &mut dyn Store, ctx: &mut ServiceCtx) {
    if !from.privs.has(Priv::Oper) {
        ctx.notice(me, from.uid, "Access denied — STATS needs the \x02operator\x02 privilege.");
        return;
    }
    let akills = db.akills();
    let glines = akills.iter().filter(|a| a.kind == XlineKind::Gline).count();
    let qlines = akills.iter().filter(|a| a.kind == XlineKind::Qline).count();
    let rlines = akills.iter().filter(|a| a.kind == XlineKind::Rline).count();
    let ignores = db.ignores().len();
    ctx.notice(me, from.uid, format!("Live network bans: \x02{glines}\x02 AKILL, \x02{qlines}\x02 SQLINE, \x02{rlines}\x02 SNLINE. Services ignores: \x02{ignores}\x02."));
}
