use fedserv_api::{Sender, ServiceCtx, Store};

// DEFAULT: give yourself the auto-vhost from the network template, with your
// account name substituted for $account.
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to identify to NickServ first.");
        return;
    };
    let Some(template) = db.vhost_template() else {
        ctx.notice(me, from.uid, "This network has no auto-vhost template.");
        return;
    };
    // Sanitise the account into a host-safe label (lowercase, alphanumerics only).
    let label: String = account.to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if label.is_empty() {
        ctx.notice(me, from.uid, "Your account name has no usable characters for a vhost.");
        return;
    }
    let host = template.replace("$account", &label);
    if !super::valid_vhost(&host) || db.vhost_is_forbidden(&host) {
        ctx.notice(me, from.uid, "Sorry, a vhost couldn't be generated for your account.");
        return;
    }
    match db.set_vhost(account, &host, "template") {
        Ok(()) => {
            ctx.apply_vhost(from.uid, &host);
            ctx.notice(me, from.uid, format!("You now have the vhost \x02{host}\x02."));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
