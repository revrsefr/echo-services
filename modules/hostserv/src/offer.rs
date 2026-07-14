use echo_api::{Sender, ServiceCtx, Store};

// OFFER <host>: add a vhost to the self-serve menu (operators).
pub fn add(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(&host) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: OFFER <host>");
        return;
    };
    if !super::valid_vhost(host) {
        ctx.notice(me, from.uid, format!("\x02{host}\x02 isn't a valid host."));
        return;
    }
    match db.vhost_offer_add(host) {
        Ok(true) => ctx.notice(me, from.uid, format!("\x02{host}\x02 is now on the vhost menu.")),
        Ok(false) => ctx.notice(me, from.uid, "That vhost is already on the menu."),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

// OFFERLIST: show the self-serve vhost menu (anyone).
pub fn list(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    let offers = db.vhost_offers();
    if offers.is_empty() {
        ctx.notice(me, from.uid, "No vhosts are on offer.");
        return;
    }
    ctx.notice(me, from.uid, format!("Vhosts on offer ({}):", offers.len()));
    for (i, host) in offers.iter().enumerate() {
        ctx.notice(me, from.uid, format!("  {}. {host}", i + 1));
    }
    ctx.notice(me, from.uid, "Take one with \x02TAKE\x02 <number>.");
}

// OFFERDEL <number>: remove an offer from the menu (operators).
pub fn del(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = args.get(1).and_then(|s| s.parse::<usize>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: OFFERDEL <number> (see OFFERLIST)");
        return;
    };
    match db.vhost_offer_del(n) {
        Ok(Some(host)) => ctx.notice(me, from.uid, format!("Removed \x02{host}\x02 from the menu.")),
        Ok(None) => ctx.notice(me, from.uid, format!("There's no offer #\x02{n}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
