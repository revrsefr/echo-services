use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};
use fedserv_api::NetView;

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
    if db.authenticate(account, password).is_none() {
        ctx.notice(me, from.uid, "Invalid password.");
        return;
    }
    let channels = db.channels_owned_by(account);
    for chan in &channels {
        let _ = db.drop_channel(chan);
        ctx.channel_mode("", chan, "-r"); // server-sourced: release the registered mode
    }
    let _ = db.drop_account(account);
    for uid in net.uids_logged_into(account) {
        ctx.logout(&uid);
    }
    ctx.notice(me, from.uid, format!("Your account \x02{account}\x02 has been dropped."));
    if !channels.is_empty() {
        ctx.notice(me, from.uid, format!("Channels released: {}.", channels.join(", ")));
    }
}
