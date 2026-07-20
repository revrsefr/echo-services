use echo_api::{AuthThen, NetView, Sender, ServiceCtx, Store};

use super::{ghost, identify};

// LOGIN <nick> <password>: identify to the account owning <nick> and, on success,
// reclaim the nick — freeing any ghost holding it and moving you onto it. A
// one-shot IDENTIFY + RECOVER for someone who connected under a guest nick.
#[allow(clippy::too_many_arguments)]
pub fn handle(me: &str, guest_nick: &str, guest_seq: &mut u32, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let (Some(&nick), Some(&password)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: LOGIN <nick> <password>");
        return;
    };
    // Already identified to this account: don't burn a needless ~1s re-verify — just
    // reclaim the nick, exactly like RECOVER (which needs no password for an owner).
    if from.account.is_some() && db.resolve_account(nick) == from.account {
        ghost::handle(me, guest_nick, guest_seq, from, args, ctx, net, db, true);
        return;
    }
    let Some((account, verifier)) = identify::precheck(me, from, "LOGIN", nick, ctx, db) else {
        return;
    };
    ctx.defer_authenticate(
        verifier,
        password,
        AuthThen::Login {
            uid: from.uid.to_string(),
            agent: me.to_string(),
            name: nick.to_string(),
            account,
            nick: nick.to_string(),
        },
    );
}
