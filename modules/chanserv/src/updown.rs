use echo_api::{status_mode, NetView, Sender, ServiceCtx, Store};

// UP <#channel>: (re)apply the status mode your access entitles you to.
// DOWN <#channel>: drop your channel status modes. `up` selects which.
pub fn handle(me: &str, from: &Sender, up: bool, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, if up { "Syntax: UP <#channel>" } else { "Syntax: DOWN <#channel>" });
        return;
    };
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let Some(info) = db.channel(chan) else {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
        return;
    };
    if !net.channel_members(chan).iter().any(|u| u.as_str() == from.uid) {
        ctx.notice(me, from.uid, format!("You're not in \x02{chan}\x02."));
        return;
    }
    if up {
        match info.join_mode(account) {
            Some(mode) => {
                ctx.channel_mode(me, chan, &status_mode(mode, from.uid));
                ctx.notice(me, from.uid, format!("Your status in \x02{chan}\x02 has been applied."));
            }
            None => ctx.notice(me, from.uid, format!("You have no status access in \x02{chan}\x02.")),
        }
    } else {
        // Strip owner, admin, op, halfop and voice; the ircd ignores any you don't hold.
        ctx.channel_mode(me, chan, &status_mode("-qaohv", from.uid));
        ctx.notice(me, from.uid, format!("Your status in \x02{chan}\x02 has been removed."));
    }
}
