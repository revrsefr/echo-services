use fedserv_api::{human_time, Sender, ServiceCtx, Store};

// LIST: show every memo with a one-line preview; \x02*\x02 marks unread.
pub fn handle(me: &str, from: &Sender, account: &str, ctx: &mut ServiceCtx, db: &dyn Store) {
    let memos = db.memo_list(account);
    if memos.is_empty() {
        ctx.notice(me, from.uid, "You have no memos.");
        return;
    }
    let unread = memos.iter().filter(|m| !m.read).count();
    ctx.notice(me, from.uid, format!("Your memos ({} total, {unread} new). \x02*\x02 marks unread:", memos.len()));
    for (i, m) in memos.iter().enumerate() {
        let flag = if m.read { ' ' } else { '*' };
        ctx.notice(me, from.uid, format!("  {}{flag} from \x02{}\x02 ({}): {}", i + 1, m.from, human_time(m.ts), preview(&m.text)));
    }
}

// First line / first 80 chars, for LIST.
fn preview(text: &str) -> String {
    let line = text.lines().next().unwrap_or("");
    if line.chars().count() > 80 {
        format!("{}…", line.chars().take(80).collect::<String>())
    } else {
        line.to_string()
    }
}
