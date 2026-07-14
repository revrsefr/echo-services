use fedserv_api::{Sender, ServiceCtx};
use fedserv_api::RegReply;

// REGISTER <password> [email]: register the sender's current nick. The engine
// derives the password off-thread, commits, and answers.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx) {
    let Some(password) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: REGISTER <password> [email]");
        return;
    };
    if let Err(reason) = crate::password::validate_password(password, from.nick) {
        ctx.notice(me, from.uid, reason);
        return;
    }
    let email = args.get(2).map(|s| s.to_string());
    ctx.defer_register(from.nick, *password, email, RegReply::NickServ {
        agent: me.to_string(),
        uid: from.uid.to_string(),
        nick: from.nick.to_string(),
    });
}
