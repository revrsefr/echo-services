use echo_api::{Sender, ServiceCtx};
use echo_api::NetView;
use echo_api::t;

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
            // Present in THIS channel right now — online elsewhere doesn't count.
            let here = net.uid_by_nick(nick).is_some_and(|uid| net.channel_members(chan).iter().any(|m| m == uid));
            if here {
                ctx.notice(me, from.uid, t!(ctx, "{who}: \x02{nick}\x02 is here right now.", who = from.nick, nick = nick));
                return;
            }
            match net.channel_seen(chan, nick) {
                Some(s) => ctx.notice(me, from.uid, t!(ctx,
                    "{who}: \x02{nick}\x02 was last seen on \x02{chan}\x02 {when}, last saying: {msg}",
                    who = from.nick, nick = s.nick, chan = chan, when = echo_api::human_time(s.ts), msg = s.msg
                )),
                None => ctx.notice(me, from.uid, t!(ctx, "{who}: I have no record of \x02{nick}\x02 talking in \x02{chan}\x02.", who = from.nick, nick = nick, chan = chan)),
            }
        }
        // Network-wide.
        Some(&nick) => {
            if net.uid_by_nick(nick).is_some() {
                ctx.notice(me, from.uid, t!(ctx, "\x02{nick}\x02 is currently online.", nick = nick));
                return;
            }
            match net.last_seen(nick) {
                Some(s) => ctx.notice(me, from.uid, t!(ctx, "\x02{nick}\x02 was last seen {when} ({what}).", nick = s.nick, when = echo_api::human_time(s.ts), what = s.what)),
                None => ctx.notice(me, from.uid, t!(ctx, "I have no record of \x02{nick}\x02.", nick = nick)),
            }
        }
        None => ctx.notice(me, from.uid, "Syntax: SEEN <nick>  |  SEEN <#channel> <nick>"),
    }
}
