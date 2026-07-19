use echo_api::{t, Sender, ServiceCtx, Store};

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
        ctx.notice(me, from.uid, t!(ctx, "There's no offer #\x02{n}\x02. See \x02OFFERLIST\x02.", n = n));
        return;
    };
    let host = match super::prepare_vhost(&offer, account, db, ctx) {
        Ok(h) => h,
        Err(msg) => {
            ctx.notice(me, from.uid, msg);
            return;
        }
    };
    // A menu offer can outlive a later FORBID; re-check at grant time like the
    // request/approve/default paths, or a stale offer bypasses the impersonation guard.
    if db.vhost_is_forbidden(&host) {
        ctx.notice(me, from.uid, t!(ctx, "\x02{host}\x02 isn't allowed here. Please choose another.", host = host));
        return;
    }
    match db.set_vhost(account, &host, "offer", None) {
        Ok(()) => {
            ctx.apply_vhost(from.uid, &host);
            ctx.notice(me, from.uid, t!(ctx, "You now have the vhost \x02{host}\x02.", host = host));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
