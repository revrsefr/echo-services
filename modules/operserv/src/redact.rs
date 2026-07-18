use echo_api::{Sender, ServiceCtx};

// REDACT <#channel|nick> <msgid> [reason]: delete a message by its IRCv3 msgid.
// The msgid comes from the reporting oper's client (which saw the tagged message);
// echo relays it as a server-trusted redaction, so no ircd oper privilege is needed
// (draft/message-redaction). One-shot — nothing is stored.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx) {
    let (Some(&target), Some(&msgid)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: REDACT <#channel|nick> <msgid> [reason]");
        return;
    };
    let reason = if args.len() > 3 { args[3..].join(" ") } else { String::new() };
    ctx.redact(me, target, msgid, &reason);
    ctx.notice(me, from.uid, format!("Redacted message \x02{msgid}\x02 in \x02{target}\x02."));
}
