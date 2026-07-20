use echo_api::{Sender, ServiceCtx, Store};
use echo_api::t;

// VOUCH <nick>: confirm a pending (invite-only) account so it becomes active. Any
// identified member may vouch; the action is announced to staff so a bad account
// can be traced back to whoever vouched for it.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !db.registration_vouch() {
        ctx.notice(me, from.uid, "Vouching isn't enabled on this network.");
        return;
    }
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You must be identified to vouch for someone.");
        return;
    };
    // Only an already-confirmed member may vouch, or the invite gate is trivially
    // bypassed by registering a second account and self-vouching.
    if !db.is_verified(account) {
        ctx.notice(me, from.uid, "Only confirmed members can vouch for others.");
        return;
    }
    let Some(&target) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: VOUCH <nick>");
        return;
    };
    let Some(tacct) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 isn't registered.", target = target));
        return;
    };
    if tacct.eq_ignore_ascii_case(account) {
        ctx.notice(me, from.uid, "You can't vouch for yourself.");
        return;
    }
    if db.is_verified(&tacct) {
        ctx.notice(me, from.uid, t!(ctx, "\x02{account}\x02 is already confirmed.", account = tacct));
        return;
    }
    match db.verify_account(&tacct) {
        Ok(()) => {
            ctx.notice(me, from.uid, t!(ctx, "You vouched for \x02{account}\x02; their account is now active.", account = tacct));
            ctx.alert("REGISTER", format!("vouched for \x02{tacct}\x02"));
        }
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
