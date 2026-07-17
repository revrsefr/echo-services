use echo_api::Store;
use echo_api::{access_role, Sender, ServiceCtx};
use echo_api::NetView;

// STATUS <#channel> [nick]: show a user's access level (self if no nick).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: STATUS <#channel> [nick]");
        return;
    };
    let Some(info) = db.channel(chan) else {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
        return;
    };
    let (label, account) = match args.get(2) {
        Some(&nick) => (nick.to_string(), net.uid_by_nick(nick).and_then(|u| net.account_of(u)).map(str::to_string)),
        None => (from.nick.to_string(), from.account.map(str::to_string)),
    };
    let level = match account.as_deref() {
        None => "none (not logged in)",
        Some(a) if info.founder.eq_ignore_ascii_case(a) => "founder",
        // Classify by resolved tier so halfop and sop read distinctly, matching
        // ALIST and the XOP lists.
        Some(a) => match info.access.iter().find(|e| e.account.eq_ignore_ascii_case(a)) {
            Some(e) => access_role(&e.level).label(),
            None => "none",
        },
    };
    ctx.notice(me, from.uid, format!("\x02{label}\x02 access on \x02{chan}\x02: \x02{level}\x02"));
}
