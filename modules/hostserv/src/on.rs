use fedserv_api::{Sender, ServiceCtx, Store};

// ON: activate the vhost assigned to your account.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to identify to NickServ first.");
        return;
    };
    match db.vhost(account) {
        Some(v) => {
            ctx.apply_vhost(from.uid, &v.host);
            ctx.notice(me, from.uid, format!("Your vhost \x02{}\x02 is now active.", v.host));
        }
        None => ctx.notice(me, from.uid, "You have no vhost assigned."),
    }
}
