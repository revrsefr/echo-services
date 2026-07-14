use fedserv_api::{Sender, ServiceCtx, Store};

// STATS: an at-a-glance summary of the enforcement state OperServ holds — how
// many network bans of each kind and how many services ignores are live.
// Read-only, so any operator may run it (the module is already oper-gated).
pub fn handle(me: &str, from: &Sender, db: &mut dyn Store, ctx: &mut ServiceCtx) {
    let akills = db.akills();
    let glines = akills.iter().filter(|a| a.kind == "G").count();
    let qlines = akills.iter().filter(|a| a.kind == "Q").count();
    let ignores = db.ignores().len();
    ctx.notice(me, from.uid, format!("Live network bans: \x02{glines}\x02 AKILL, \x02{qlines}\x02 SQLINE. Services ignores: \x02{ignores}\x02."));
}
