use fedserv_api::{Sender, ServiceCtx, Store};

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
    if !super::valid_vhost(host) {
        ctx.notice(me, from.uid, format!("\x02{host}\x02 isn't a valid host (letters, digits, hyphens and dots)."));
        return;
    }
    if db.vhost_is_forbidden(host) {
        ctx.notice(me, from.uid, format!("\x02{host}\x02 isn't allowed here. Please choose another."));
        return;
    }
    match db.request_vhost(account, host) {
        Ok(()) => ctx.notice(me, from.uid, format!("Requested vhost \x02{host}\x02 — an operator will review it.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
