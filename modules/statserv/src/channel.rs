use echo_api::{t, NetView, Sender, ServiceCtx, Store};

// <#channel>: the lines seen in a channel this session and its top talkers.
// Founder-or-admin.
pub fn handle(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    if !super::require_channel_admin(me, from, chan, ctx, db) {
        return;
    }
    let Some((lines, top)) = net.channel_activity(chan) else {
        ctx.notice(me, from.uid, t!(ctx, "No activity recorded for \x02{chan}\x02 yet.", chan = chan));
        return;
    };
    ctx.notice(me, from.uid, echo_api::plural!(ctx, lines, one = "\x02{chan}\x02 — \x02{lines}\x02 line seen.", other = "\x02{chan}\x02 — \x02{lines}\x02 lines seen.", chan = chan, lines = lines));
    if top.is_empty() {
        return;
    }
    ctx.notice(me, from.uid, "Top talkers:");
    for (i, (nick, count)) in top.iter().enumerate() {
        ctx.notice(me, from.uid, t!(ctx, "  {n}. \x02{nick}\x02 — {count}", n = i + 1, nick = nick, count = count));
    }
}
