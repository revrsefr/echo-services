use echo_api::{AuthThen, Sender, ServiceCtx, Store};

use super::identify;

// LOGIN <nick> <password>: identify to the account owning <nick> and, on success,
// reclaim the nick — freeing any ghost holding it and moving you onto it. A
// one-shot IDENTIFY + RECOVER for someone who connected under a guest nick.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(&nick), Some(&password)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: LOGIN <nick> <password>");
        return;
    };
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
