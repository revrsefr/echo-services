use fedserv_api::{Sender, ServiceCtx, Store};

// TAKE <number>: assign yourself the vhost offered at that position on the menu.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to identify to NickServ first.");
        return;
    };
    let Some(n) = args.get(1).and_then(|s| s.parse::<usize>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: TAKE <number> (see OFFERLIST)");
        return;
    };
    let Some(offer) = n.checked_sub(1).and_then(|i| db.vhost_offers().into_iter().nth(i)) else {
        ctx.notice(me, from.uid, format!("There's no offer #\x02{n}\x02. See \x02OFFERLIST\x02."));
        return;
    };
    let host = match super::prepare_vhost(&offer, account, db) {
        Ok(h) => h,
        Err(msg) => {
            ctx.notice(me, from.uid, msg);
            return;
        }
    };
    match db.set_vhost(account, &host, "offer", None) {
        Ok(()) => {
            ctx.apply_vhost(from.uid, &host);
            ctx.notice(me, from.uid, format!("You now have the vhost \x02{host}\x02."));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
