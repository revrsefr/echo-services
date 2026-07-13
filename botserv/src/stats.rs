use fedserv_api::{NetView, Sender, ServiceCtx, Store};

// BOTSTATS <#channel>: session activity the bot has seen in a channel — total
// lines and the top talkers. Founder-or-admin.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: BOTSTATS <#channel>");
        return;
    };
    if !super::require_channel_admin(me, from, chan, ctx, db) {
        return;
    }
    let Some((lines, top)) = net.channel_activity(chan) else {
        ctx.notice(me, from.uid, format!("No activity recorded for \x02{chan}\x02 yet."));
        return;
    };
    ctx.notice(me, from.uid, format!("\x02{chan}\x02 — \x02{lines}\x02 line(s) seen this session."));
    if top.is_empty() {
        return;
    }
    ctx.notice(me, from.uid, "Top talkers:");
    for (i, (nick, count)) in top.iter().enumerate() {
        ctx.notice(me, from.uid, format!("  {}. \x02{nick}\x02 — {count}", i + 1));
    }
}
