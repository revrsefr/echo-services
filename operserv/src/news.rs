use fedserv_api::{Priv, Sender, ServiceCtx, Store};

// NEWS ADD <LOGON|OPER> <text> | NEWS DEL <LOGON|OPER> <number> | NEWS LIST
// [LOGON|OPER]: manage the announcements shown to users on connect (logon) and
// to operators on login (oper). Admin-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — NEWS needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => add(me, from, args.get(2).copied(), args.get(3..).unwrap_or(&[]), ctx, db),
        Some("DEL") | Some("REMOVE") => del(me, from, args.get(2).copied(), args.get(3).copied(), ctx, db),
        Some("LIST") | Some("VIEW") => list(me, from, args.get(2).copied(), ctx, db),
        _ => ctx.notice(me, from.uid, "Syntax: NEWS ADD <LOGON|OPER> <text> | NEWS DEL <LOGON|OPER> <number> | NEWS LIST [LOGON|OPER]"),
    }
}

fn add(me: &str, from: &Sender, kind: Option<&str>, text: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(kind), false) = (kind.and_then(parse_kind), text.is_empty()) else {
        ctx.notice(me, from.uid, "Syntax: NEWS ADD <LOGON|OPER> <text>");
        return;
    };
    let setter = from.account.unwrap_or(from.nick);
    db.news_add(kind, &text.join(" "), setter);
    ctx.notice(me, from.uid, format!("Added a \x02{kind}\x02 news item."));
}

fn del(me: &str, from: &Sender, kind: Option<&str>, num: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(kind), Some(n)) = (kind.and_then(parse_kind), num.and_then(|n| n.parse::<usize>().ok())) else {
        ctx.notice(me, from.uid, "Syntax: NEWS DEL <LOGON|OPER> <number>");
        return;
    };
    match db.news(kind).get(n.wrapping_sub(1)) {
        Some(item) if n >= 1 => {
            db.news_del(item.id);
            ctx.notice(me, from.uid, format!("Removed \x02{kind}\x02 news item \x02{n}\x02."));
        }
        _ => ctx.notice(me, from.uid, format!("There's no \x02{kind}\x02 news item \x02{n}\x02.")),
    }
}

fn list(me: &str, from: &Sender, kind: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let kinds: &[&str] = match kind.map(|k| k.to_ascii_uppercase()) {
        Some(k) if k == "LOGON" => &["logon"],
        Some(k) if k == "OPER" => &["oper"],
        Some(_) => {
            ctx.notice(me, from.uid, "Kind must be \x02LOGON\x02 or \x02OPER\x02.");
            return;
        }
        None => &["logon", "oper"],
    };
    let mut any = false;
    for k in kinds {
        let items = db.news(k);
        for (i, item) in items.iter().enumerate() {
            any = true;
            ctx.notice(me, from.uid, format!("{}. [\x02{k}\x02] {} — by {}", i + 1, item.text, item.setter));
        }
    }
    if !any {
        ctx.notice(me, from.uid, "No news items.");
    }
}

fn parse_kind(s: &str) -> Option<&'static str> {
    match s.to_ascii_uppercase().as_str() {
        "LOGON" => Some("logon"),
        "OPER" => Some("oper"),
        _ => None,
    }
}
