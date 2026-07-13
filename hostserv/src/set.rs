use fedserv_api::{parse_duration, NetView, Sender, ServiceCtx, Store};

// SET <account> <host> [duration]: assign a vhost to an account, applying it at
// once to online sessions. An optional duration (e.g. 30d) makes it temporary.
// Operators only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let (Some(&account), Some(&host)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: SET <account> <host> [duration]");
        return;
    };
    if !super::valid_vhost(host) {
        ctx.notice(me, from.uid, format!("\x02{host}\x02 isn't a valid host (letters, digits, hyphens and dots)."));
        return;
    }
    if db.account(account).is_none() {
        ctx.notice(me, from.uid, format!("\x02{account}\x02 isn't registered."));
        return;
    }
    let ttl = args.get(3).and_then(|s| parse_duration(s));
    match db.set_vhost(account, host, from.nick, ttl) {
        Ok(()) => {
            for uid in net.uids_logged_into(account) {
                ctx.apply_vhost(&uid, host);
            }
            let when = args.get(3).filter(|_| ttl.is_some()).map(|d| format!(" (expires in {d})")).unwrap_or_default();
            ctx.notice(me, from.uid, format!("Vhost \x02{host}\x02 assigned to \x02{account}\x02{when}."));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
