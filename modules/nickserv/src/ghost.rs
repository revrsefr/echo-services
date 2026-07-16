use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;

// GHOST/RECOVER <nick> [password]: rename off a session using a nick you own,
// either by being identified to its account or giving that account's password.
// GHOST just frees the nick; RECOVER (`regain`) also puts the caller back onto
// it. Every argument is a distinct input the guest-rename needs, so the count is
// inherent.
#[allow(clippy::too_many_arguments)]
pub fn handle(me: &str, guest_nick: &str, guest_seq: &mut u32, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store, regain: bool) {
    let cmd = if regain { "RECOVER" } else { "GHOST" };
    let Some(&target) = args.get(1) else {
        ctx.notice(me, from.uid, format!("Syntax: {cmd} <nick> [password]"));
        return;
    };
    let Some(account) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };
    let owns = from.account == Some(account.as_str()) || args.get(2).is_some_and(|pw| db.authenticate(target, pw).is_some());
    if !owns {
        ctx.notice(me, from.uid, format!("Access denied. Identify to \x02{account}\x02 or give its password."));
        return;
    }
    // Free the nick if someone else is holding it.
    match net.uid_by_nick(target).map(str::to_string) {
        Some(ghost) if ghost == from.uid => {
            ctx.notice(me, from.uid, "That's you.");
            return;
        }
        Some(ghost) => {
            let guest = format!("{guest_nick}{guest_seq}");
            *guest_seq = guest_seq.wrapping_add(1);
            ctx.force_nick(&ghost, &guest);
            ctx.notice(me, from.uid, format!("\x02{target}\x02 has been freed."));
        }
        None if !regain => {
            ctx.notice(me, from.uid, format!("Nobody is using \x02{target}\x02."));
            return;
        }
        None => {} // already free — RECOVER will simply regain it
    }
    // RECOVER puts the caller back onto the nick (queued after any guest-rename).
    if regain {
        ctx.force_nick(from.uid, target);
        ctx.notice(me, from.uid, format!("You have regained \x02{target}\x02."));
    }
}
