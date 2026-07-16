use echo_api::{NetView, Priv, Sender, ServiceCtx, Store};

// STAFF <text>: leave a memo on every operator's account. Admin-only, for
// notes to the staff team that persist until read. Recipients are the union of
// the configured operators and any runtime OPER grants.
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — STAFF needs the \x02admin\x02 privilege.");
        return;
    }
    if args.len() < 2 {
        ctx.notice(me, from.uid, "Syntax: STAFF <text>");
        return;
    }
    let text = args[1..].join(" ");
    // Config opers and runtime grants, resolved to canonical account names and
    // de-duplicated so nobody gets the memo twice.
    let mut names: Vec<String> = net.oper_accounts();
    names.extend(db.opers_list().into_iter().map(|(name, _, _)| name));
    let mut sent = 0usize;
    let mut seen: Vec<String> = Vec::new();
    for name in &names {
        let Some(canon) = db.resolve_account(name).map(str::to_string) else { continue };
        if seen.contains(&canon) {
            continue;
        }
        seen.push(canon.clone());
        if db.memo_send(&canon, account, &text, false).is_ok() {
            sent += 1;
        }
    }
    ctx.notice(me, from.uid, format!("Memo sent to \x02{sent}\x02 operator(s)."));
}
