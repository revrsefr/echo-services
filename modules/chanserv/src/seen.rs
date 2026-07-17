use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;

// SEEN <nick>            — network-wide: when a nick was last seen, and doing what.
// SEEN <#channel> <nick> — channel-scoped: when last active there, and their last
//                          message. The fantasy form (!seen nick) injects #channel.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    match args.get(1) {
        // Channel-scoped (also the fantasy `!seen nick` path, which injects the channel).
        Some(&chan) if chan.starts_with('#') => {
            let Some(&nick) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: SEEN <#channel> <nick>");
                return;
            };
            if net.uid_by_nick(nick).is_some() {
                ctx.notice(me, from.uid, format!("{}: \x02{nick}\x02 is here right now.", from.nick));
                return;
            }
            match net.channel_seen(chan, nick) {
                Some(s) => ctx.notice(me, from.uid, format!(
                    "{}: \x02{}\x02 was last seen on \x02{chan}\x02 {}, last saying: {}",
                    from.nick, s.nick, echo_api::human_time(s.ts), s.msg
                )),
                None => ctx.notice(me, from.uid, format!("{}: I have no record of \x02{nick}\x02 talking in \x02{chan}\x02.", from.nick)),
            }
        }
        // Network-wide.
        Some(&nick) => {
            if net.uid_by_nick(nick).is_some() {
                ctx.notice(me, from.uid, format!("\x02{nick}\x02 is currently online."));
                return;
            }
            match net.last_seen(nick) {
                Some(s) => ctx.notice(me, from.uid, format!("\x02{}\x02 was last seen {} ({}).", s.nick, echo_api::human_time(s.ts), s.what)),
                None => ctx.notice(me, from.uid, format!("I have no record of \x02{nick}\x02.")),
            }
        }
        None => ctx.notice(me, from.uid, "Syntax: SEEN <nick>  |  SEEN <#channel> <nick>"),
    }
}
