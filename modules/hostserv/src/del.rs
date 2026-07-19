use echo_api::{t, NetView, Sender, ServiceCtx, Store};

// DEL <account>: remove an account's vhost, restoring the normal host on any
// online sessions. Operators only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(&account) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: DEL <account>");
        return;
    };
    // Note whether the vhost spoofed the ident (`ident@host`) before removing it,
    // so online sessions get their real ident back too, not just their host.
    let had_ident = db.vhost(account).is_some_and(|v| v.host.contains('@'));
    match db.del_vhost(account) {
        Ok(true) => {
            for uid in net.uids_logged_into(account) {
                if let Some(host) = net.host_of(&uid) {
                    let host = host.to_string();
                    ctx.set_host(&uid, &host);
                }
                if had_ident {
                    if let Some(ident) = net.ident_of(&uid) {
                        let ident = ident.to_string();
                        ctx.set_ident(&uid, &ident);
                    }
                }
            }
            ctx.notice(me, from.uid, t!(ctx, "Vhost for \x02{account}\x02 removed.", account = account));
        }
        Ok(false) => ctx.notice(me, from.uid, t!(ctx, "\x02{account}\x02 has no vhost.", account = account)),
        Err(_) => ctx.notice(me, from.uid, t!(ctx, "\x02{account}\x02 isn't registered.", account = account)),
    }
}
