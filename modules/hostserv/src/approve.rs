use echo_api::{t, NetView, Sender, ServiceCtx, Store};

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
            ctx.notice(me, from.uid, t!(ctx, "\x02{account}\x02 has no pending vhost request.", account = account));
            return;
        }
        Err(_) => {
            ctx.notice(me, from.uid, t!(ctx, "\x02{account}\x02 isn't registered.", account = account));
            return;
        }
    };
    if !activate {
        ctx.notice(me, from.uid, t!(ctx, "Rejected \x02{account}\x02's vhost request.", account = account));
        return;
    }
    // Re-check the requested host now (another account may have taken it since).
    let host = match super::prepare_vhost(&host, account, db, ctx) {
        Ok(h) => h,
        Err(msg) => {
            ctx.notice(me, from.uid, t!(ctx, "Can't activate: {msg}", msg = msg));
            return;
        }
    };
    // The forbidden list may have grown since the request was filed; a user's
    // request must still obey it (an operator's own SET is a deliberate override).
    if db.vhost_is_forbidden(&host) {
        ctx.notice(me, from.uid, t!(ctx, "Can't activate: \x02{host}\x02 is on the forbidden list.", host = host));
        return;
    }
    match db.set_vhost(account, &host, from.nick, None) {
        Ok(()) => {
            for uid in net.uids_logged_into(account) {
                ctx.apply_vhost(&uid, &host);
            }
            ctx.notice(me, from.uid, t!(ctx, "Activated vhost \x02{host}\x02 for \x02{account}\x02.", host = host, account = account));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
