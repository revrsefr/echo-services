use echo_api::{NetView, Sender, ServiceCtx, Store};

// LOGOUT: log out and rename to a guest nick (prefix + a per-logout sequence).
pub fn handle(me: &str, guest_nick: &str, guest_seq: &mut u32, from: &Sender, ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    if from.account.is_none() {
        ctx.notice(me, from.uid, "You're not logged in.");
        return;
    }
    let guest = echo_api::next_guest_nick(guest_nick, guest_seq, net, db);
    ctx.logout(from.uid);
    ctx.force_nick(from.uid, &guest);
    ctx.notice(me, from.uid, format!("You're now logged out. Your nick is now \x02{}\x02.", guest));
}
