use echo_api::{Sender, ServiceCtx, Store};
use echo_api::RegReply;

// REGISTER <password> [email]: register the sender's current nick. The engine
// derives the password off-thread, commits, and answers.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(password) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: REGISTER <password> [email]");
        return;
    };
    if let Err(reason) = crate::password::validate_password(password, from.nick) {
        ctx.notice(me, from.uid, reason);
        return;
    }
    // Refuse a look-alike / mixed-script nick before it can be used to impersonate,
    // unless the guard is turned off.
    if db.confusable_check_enabled() {
        if let Some(reason) = echo_api::confusable_reason(from.nick) {
            ctx.notice(me, from.uid, reason);
            return;
        }
    }
    let email = args.get(2).map(|s| s.to_string());
    ctx.defer_register(from.nick, *password, email, RegReply::NickServ {
        agent: me.to_string(),
        uid: from.uid.to_string(),
        nick: from.nick.to_string(),
    });
}
