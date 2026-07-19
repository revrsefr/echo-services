use echo_api::{NetView, Sender, ServiceCtx, Store};

// OFF: restore your normal host for this session (the vhost stays assigned and
// re-applies next time you identify).
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to identify to NickServ first.");
        return;
    };
    let Some(vhost) = db.vhost(account) else {
        ctx.notice(me, from.uid, "You have no vhost assigned.");
        return;
    };
    match net.host_of(from.uid) {
        Some(host) => {
            let host = host.to_string();
            ctx.set_host(from.uid, &host);
            // An `ident@host` vhost spoofed the ident too; restore the real one, or
            // the user keeps the vhost's username for the rest of the session.
            if vhost.host.contains('@') {
                if let Some(ident) = net.ident_of(from.uid) {
                    let ident = ident.to_string();
                    ctx.set_ident(from.uid, &ident);
                }
            }
            ctx.notice(me, from.uid, "Your vhost is off; your normal host is restored.");
        }
        None => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
