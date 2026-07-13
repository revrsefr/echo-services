use fedserv_api::{NetView, Sender, ServiceCtx, Store};

// ACTIVATE <account> / REJECT <account>: approve a pending vhost request (setting
// and applying it) or turn it down. Operators only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store, activate: bool) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(&account) = args.get(1) else {
        let syntax = if activate { "Syntax: ACTIVATE <account>" } else { "Syntax: REJECT <account>" };
        ctx.notice(me, from.uid, syntax);
        return;
    };
    let host = match db.take_vhost_request(account) {
        Ok(Some(h)) => h,
        Ok(None) => {
            ctx.notice(me, from.uid, format!("\x02{account}\x02 has no pending vhost request."));
            return;
        }
        Err(_) => {
            ctx.notice(me, from.uid, format!("\x02{account}\x02 isn't registered."));
            return;
        }
    };
    if !activate {
        ctx.notice(me, from.uid, format!("Rejected \x02{account}\x02's vhost request."));
        return;
    }
    match db.set_vhost(account, &host, from.nick, None) {
        Ok(()) => {
            for uid in net.uids_logged_into(account) {
                ctx.apply_vhost(&uid, &host);
            }
            ctx.notice(me, from.uid, format!("Activated vhost \x02{host}\x02 for \x02{account}\x02."));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
