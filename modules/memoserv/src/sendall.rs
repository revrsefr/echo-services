use echo_api::{Priv, Sender, ServiceCtx, Store};

// SENDALL <text>: leave a memo on every registered account. Admin-only, for
// network-wide announcements that persist until read.
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — SENDALL needs the \x02admin\x02 privilege.");
        return;
    }
    if args.len() < 2 {
        ctx.notice(me, from.uid, "Syntax: SENDALL <text>");
        return;
    }
    let text = args[1..].join(" ");
    // Snapshot the names first so the immutable read ends before we send.
    let names: Vec<String> = db.accounts_matching("*").into_iter().map(|a| a.name).collect();
    let mut sent = 0usize;
    for name in &names {
        if db.memo_send(name, account, &text, false).is_ok() {
            sent += 1;
        }
    }
    ctx.notice(me, from.uid, format!("Memo sent to \x02{sent}\x02 account(s)."));
}
