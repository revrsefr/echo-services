use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;

// GHOST/RECOVER <nick> [password]: rename off a session using a nick you own,
// either by being identified to its account or giving that account's password.
// Every argument is a distinct input the guest-rename needs (the guest nick and
// its sequence counter among them), so the count is inherent.
#[allow(clippy::too_many_arguments)]
pub fn handle(me: &str, guest_nick: &str, guest_seq: &mut u32, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(&target) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: GHOST <nick> [password]");
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
    let Some(ghost) = net.uid_by_nick(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("Nobody is using \x02{target}\x02."));
        return;
    };
    if ghost == from.uid {
        ctx.notice(me, from.uid, "That's you.");
        return;
    }
    let guest = format!("{guest_nick}{guest_seq}");
    *guest_seq = guest_seq.wrapping_add(1);
    ctx.force_nick(&ghost, &guest);
    ctx.notice(me, from.uid, format!("\x02{target}\x02 has been freed."));
}
