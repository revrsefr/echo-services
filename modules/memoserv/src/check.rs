use echo_api::{human_time, t, Sender, ServiceCtx, Store};

// CHECK <nick>: has the last memo you sent to <nick> been read yet?
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&target) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: CHECK <nick>");
        return;
    };
    let Some(dest) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{target}\x02 isn't registered.", target = target));
        return;
    };
    match db.memo_check(&dest, account) {
        Some((true, ts)) => ctx.notice(me, from.uid, t!(ctx, "Your last memo to \x02{target}\x02 (sent {when}) has been \x02read\x02.", target = target, when = human_time(ts))),
        Some((false, ts)) => ctx.notice(me, from.uid, t!(ctx, "Your last memo to \x02{target}\x02 (sent {when}) has \x02not\x02 been read yet.", target = target, when = human_time(ts))),
        None => ctx.notice(me, from.uid, t!(ctx, "You have no memo on record to \x02{target}\x02.", target = target)),
    }
}
