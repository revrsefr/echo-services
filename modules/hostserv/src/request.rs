use echo_api::{t, Sender, ServiceCtx, Store};

// REQUEST <host>: ask for a vhost, to be approved by an operator.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to identify to NickServ first.");
        return;
    };
    let Some(&host) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: REQUEST <host>");
        return;
    };
    let host = match super::prepare_vhost(host, account, db, ctx) {
        Ok(h) => h,
        Err(msg) => {
            ctx.notice(me, from.uid, msg);
            return;
        }
    };
    if db.vhost_is_forbidden(&host) {
        ctx.notice(me, from.uid, t!(ctx, "\x02{host}\x02 isn't allowed here. Please choose another.", host = host));
        return;
    }
    let wait = db.vhost_request_wait(account);
    if wait > 0 {
        ctx.notice(me, from.uid, t!(ctx, "Please wait \x02{wait}\x02s before requesting another vhost.", wait = wait));
        return;
    }
    match db.request_vhost(account, &host) {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Requested vhost \x02{host}\x02 — an operator will review it.", host = host)),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
