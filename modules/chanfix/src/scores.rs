use echo_api::{t, NetView, Sender, ServiceCtx};

// SCORES <#channel>: show the op-time standings ChanFix would reop from.
pub fn handle(me: &str, from: &Sender, chan: Option<&str>, ctx: &mut ServiceCtx, net: &dyn NetView) {
    let Some(chan) = chan else {
        ctx.notice(me, from.uid, "Syntax: SCORES <#channel>");
        return;
    };
    let scores = net.chanfix_scores(chan);
    if scores.is_empty() {
        ctx.notice(me, from.uid, t!(ctx, "No op-time recorded for \x02{chan}\x02 yet.", chan = chan));
        return;
    }
    for (id, score) in scores.iter().take(15) {
        ctx.notice(me, from.uid, t!(ctx, "  \x02{score}\x02  {id}", score = score, id = id));
    }
    ctx.notice(me, from.uid, echo_api::plural!(ctx, scores.len(), one = "Top {shown} of {total} scored identity for \x02{chan}\x02.", other = "Top {shown} of {total} scored identities for \x02{chan}\x02.", shown = scores.len().min(15), total = scores.len(), chan = chan));
}
