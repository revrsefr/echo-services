use echo_api::Store;
use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;
use echo_api::t;

// DROP <password>: delete your account. Re-authenticates as confirmation, releases
// and drops the channels you found, and logs you out.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let Some(&password) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: DROP <password>");
        return;
    };
    // Throttle the confirmation verify like IDENTIFY so the ~1s check can't be
    // spammed to stall the engine, and record the attempt.
    if let Some(secs) = db.auth_lockout(account) {
        ctx.notice(me, from.uid, t!(ctx, "Too many failed attempts. Please wait {secs}s and try again.", secs = secs));
        return;
    }
    if db.authenticate(account, password).is_none() {
        db.note_auth(account, false);
        ctx.notice(me, from.uid, "Invalid password.");
        return;
    }
    db.note_auth(account, true);
    // A channel with a successor is inherited; the rest are dropped and released.
    let (inherited, dropped) = db.release_founded_channels(account);
    for chan in &dropped {
        ctx.channel_mode("", chan, "-r"); // server-sourced: release the registered mode
    }
    let _ = db.drop_account(account);
    for uid in net.uids_logged_into(account) {
        ctx.logout(&uid);
    }
    ctx.notice(me, from.uid, t!(ctx, "Your account \x02{account}\x02 has been dropped.", account = account));
    if !dropped.is_empty() {
        ctx.notice(me, from.uid, t!(ctx, "Channels released: {list}.", list = dropped.join(", ")));
    }
    if !inherited.is_empty() {
        let list: Vec<String> = inherited.iter().map(|(c, s)| format!("{c} -> {s}")).collect();
        ctx.notice(me, from.uid, t!(ctx, "Channels passed to their successor: {list}.", list = list.join(", ")));
    }
}
