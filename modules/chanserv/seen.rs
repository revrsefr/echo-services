use crate::engine::service::{Sender, ServiceCtx};
use crate::engine::state::NetView;

// SEEN <nick>: when a nick was last seen, and doing what.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    let Some(&nick) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: SEEN <nick>");
        return;
    };
    if net.uid_by_nick(nick).is_some() {
        ctx.notice(me, from.uid, format!("\x02{nick}\x02 is currently online."));
        return;
    }
    match net.last_seen(nick) {
        Some(s) => ctx.notice(me, from.uid, format!("\x02{}\x02 was last seen {} ({}).", s.nick, crate::engine::db::human_time(s.ts), s.what)),
        None => ctx.notice(me, from.uid, format!("I have no record of \x02{nick}\x02.")),
    }
}
