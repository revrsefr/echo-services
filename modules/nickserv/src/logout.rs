use echo_api::{Sender, ServiceCtx};

// LOGOUT: log out and rename to a guest nick (prefix + a per-logout sequence).
pub fn handle(me: &str, guest_nick: &str, guest_seq: &mut u32, from: &Sender, ctx: &mut ServiceCtx) {
    if from.account.is_none() {
        ctx.notice(me, from.uid, "You're not logged in.");
        return;
    }
    let guest = format!("{guest_nick}{guest_seq}");
    *guest_seq = guest_seq.wrapping_add(1);
    ctx.logout(from.uid);
    ctx.force_nick(from.uid, &guest);
    ctx.notice(me, from.uid, format!("You're now logged out. Your nick is now \x02{}\x02.", guest));
}
