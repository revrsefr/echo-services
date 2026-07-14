use echo_api::{Priv, Sender, ServiceCtx};

// GLOBAL <message>: send an announcement to every user on the network. Admin-
// only — it reaches everyone, so it's the heaviest voice services have.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — GLOBAL needs the \x02admin\x02 privilege.");
        return;
    }
    let message = args[1..].join(" ");
    if message.trim().is_empty() {
        ctx.notice(me, from.uid, "Syntax: GLOBAL <message>");
        return;
    }
    // A marker so users can tell an official announcement from a normal notice.
    ctx.global(me, format!("[\x02Network\x02] {message}"));
    ctx.notice(me, from.uid, "Your announcement has been sent to the whole network.");
}
