use echo_api::{NetView, Sender, ServiceCtx, Store};

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
    match db.del_vhost(account) {
        Ok(true) => {
            for uid in net.uids_logged_into(account) {
                if let Some(host) = net.host_of(&uid) {
                    let host = host.to_string();
                    ctx.set_host(&uid, &host);
                }
            }
            ctx.notice(me, from.uid, format!("Vhost for \x02{account}\x02 removed."));
        }
        Ok(false) => ctx.notice(me, from.uid, format!("\x02{account}\x02 has no vhost.")),
        Err(_) => ctx.notice(me, from.uid, format!("\x02{account}\x02 isn't registered.")),
    }
}
