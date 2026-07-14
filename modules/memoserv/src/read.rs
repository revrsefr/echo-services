use echo_api::{human_time, MemoView, Sender, ServiceCtx, Store};

// READ <num>|NEW|ALL: display memos and mark them read.
pub fn handle(me: &str, from: &Sender, account: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("NEW") | Some("ALL") => {
            let only_new = args[1].eq_ignore_ascii_case("new");
            let targets: Vec<usize> = db
                .memo_list(account)
                .iter()
                .enumerate()
                .filter(|(_, m)| !only_new || !m.read)
                .map(|(i, _)| i)
                .collect();
            if targets.is_empty() {
                ctx.notice(me, from.uid, if only_new { "You have no new memos." } else { "You have no memos." });
                return;
            }
            for i in targets {
                if let Some(m) = db.memo_read(account, i) {
                    show(me, from, i, &m, ctx);
                }
            }
        }
        Some(numstr) => {
            let Some(n) = numstr.parse::<usize>().ok().filter(|n| *n >= 1) else {
                ctx.notice(me, from.uid, "Syntax: READ <num>|NEW|ALL");
                return;
            };
            match db.memo_read(account, n - 1) {
                Some(m) => show(me, from, n - 1, &m, ctx),
                None => ctx.notice(me, from.uid, format!("You have no memo #\x02{n}\x02.")),
            }
        }
        None => ctx.notice(me, from.uid, "Syntax: READ <num>|NEW|ALL"),
    }
}

fn show(me: &str, from: &Sender, index: usize, m: &MemoView, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, format!("Memo #\x02{}\x02 from \x02{}\x02 ({}):", index + 1, m.from, human_time(m.ts)));
    ctx.notice(me, from.uid, format!("  {}", m.text));
}
