use echo_api::{t, Sender, ServiceCtx, Store};

// CANCEL <nick>: recall the last unread memo you sent to <nick>. A memo the
// recipient has already read can't be recalled.
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&target) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: CANCEL <nick>");
        return;
    };
    let Some(dest) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 isn't registered.", target = target));
        return;
    };
    if db.memo_cancel(&dest, account) {
        ctx.notice(me, from.uid, t!(ctx, "Your last unread memo to \x02{target}\x02 has been cancelled.", target = target));
    } else {
        ctx.notice(me, from.uid, t!(ctx, "You have no unread memo to \x02{target}\x02 to cancel.", target = target));
    }
}
