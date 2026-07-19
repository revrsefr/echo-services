use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;
use echo_api::t;

// GHOST/RECOVER <nick> [password]: rename off a session using a nick you own,
// either by being identified to its account or giving that account's password.
// GHOST just frees the nick; RECOVER (`regain`) also puts the caller back onto
// it. Every argument is a distinct input the guest-rename needs, so the count is
// inherent.
#[allow(clippy::too_many_arguments)]
pub fn handle(me: &str, guest_nick: &str, guest_seq: &mut u32, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store, regain: bool) {
    let cmd = if regain { "RECOVER" } else { "GHOST" };
    let Some(&target) = args.get(1) else {
        ctx.notice(me, from.uid, t!(ctx, "Syntax: {cmd} <nick> [password]", cmd = cmd));
        return;
    };
    let Some(account) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 isn't registered.", target = target));
        return;
    };
    // Ownership by an identified session, or by password — throttled and recorded
    // like IDENTIFY so GHOST can't be an unthrottled guessing oracle against any
    // registered nick, and each ~1s verify can't be spammed to stall the engine.
    let owns = if from.account == Some(account.as_str()) {
        true
    } else if let Some(&pw) = args.get(2) {
        if let Some(secs) = db.auth_lockout(&account) {
            ctx.notice(me, from.uid, t!(ctx, "Too many failed attempts. Please wait {secs}s and try again.", secs = secs));
            return;
        }
        let ok = db.authenticate(&account, pw).is_some();
        db.note_auth(&account, ok);
        if !ok {
            ctx.auth_report(false, Some(&account), "NickServ GHOST", from.uid, Some("bad password"));
        }
        ok
    } else {
        false
    };
    if !owns {
        ctx.notice(me, from.uid, t!(ctx, "Access denied. Identify to \x02{account}\x02 or give its password.", account = account));
        return;
    }
    // Free the nick if someone else is holding it.
    match net.uid_by_nick(target).map(str::to_string) {
        Some(ghost) if ghost == from.uid => {
            ctx.notice(me, from.uid, "That's you.");
            return;
        }
        Some(ghost) => {
            let guest = echo_api::next_guest_nick(guest_nick, guest_seq, net, &*db);
            ctx.force_nick(&ghost, &guest);
            ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 has been freed.", target = target));
        }
        None if !regain => {
            ctx.notice(me, from.uid, t!(ctx, "Nobody is using \x02{target}\x02.", target = target));
            return;
        }
        None => {} // already free — RECOVER will simply regain it
    }
    // RECOVER puts the caller back onto the nick (queued after any guest-rename).
    if regain {
        ctx.force_nick(from.uid, target);
        ctx.notice(me, from.uid, t!(ctx, "You have regained \x02{target}\x02.", target = target));
    }
}
