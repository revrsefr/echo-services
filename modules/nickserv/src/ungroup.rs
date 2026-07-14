use echo_api::Store;
use echo_api::{Sender, ServiceCtx};

// UNGROUP [nick]: remove a nick grouped to your account (defaults to your current nick).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let nick = args.get(1).copied().unwrap_or(from.nick);
    if nick.eq_ignore_ascii_case(account) {
        ctx.notice(me, from.uid, "You can't ungroup your main account name.");
        return;
    }
    if db.resolve_account(nick).is_none_or(|a| !a.eq_ignore_ascii_case(account)) {
        ctx.notice(me, from.uid, format!("\x02{nick}\x02 isn't grouped to your account."));
        return;
    }
    match db.ungroup_nick(nick) {
        Ok(true) => ctx.notice(me, from.uid, format!("\x02{nick}\x02 is no longer grouped to \x02{account}\x02.")),
        Ok(false) => ctx.notice(me, from.uid, format!("\x02{nick}\x02 isn't a grouped nick.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
