use echo_api::{NetView, Sender, ServiceCtx};

// SCORES <#channel>: show the op-time standings ChanFix would reop from.
pub fn handle(me: &str, from: &Sender, chan: Option<&str>, ctx: &mut ServiceCtx, net: &dyn NetView) {
    let Some(chan) = chan else {
        ctx.notice(me, from.uid, "Syntax: SCORES <#channel>");
        return;
    };
    let scores = net.chanfix_scores(chan);
    if scores.is_empty() {
        ctx.notice(me, from.uid, format!("No op-time recorded for \x02{chan}\x02 yet."));
        return;
    }
    for (id, score) in scores.iter().take(15) {
        ctx.notice(me, from.uid, format!("  \x02{score}\x02  {id}"));
    }
    ctx.notice(me, from.uid, format!("Top {} of {} scored identit{} for \x02{chan}\x02.", scores.len().min(15), scores.len(), if scores.len() == 1 { "y" } else { "ies" }));
}
