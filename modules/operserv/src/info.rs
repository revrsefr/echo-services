use echo_api::{t, Priv, Sender, ServiceCtx, Store};

// INFO <target> | INFO ADD <target> <note> | INFO DEL <target>: attach a staff
// note to an account or channel (a `#name` is a channel, else an account). The
// note is shown to operators in that service's INFO. Admin-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Oper) {
        ctx.notice(me, from.uid, "Access denied — INFO needs the \x02operator\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") | Some("SET") => set(me, from, args.get(2).copied(), args.get(3..).unwrap_or(&[]), ctx, db),
        Some("DEL") | Some("CLEAR") => set(me, from, args.get(2).copied(), &[], ctx, db),
        Some(_) => show(me, from, args[1], ctx, db),
        None => ctx.notice(me, from.uid, "Syntax: INFO <target> | INFO ADD <target> <note> | INFO DEL <target>"),
    }
}

// `note` empty clears; otherwise it's the joined note words.
fn set(me: &str, from: &Sender, target: Option<&str>, note: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    // Changing a staff note mutates account/channel data (an operator viewing it is
    // fine, but not overwriting an administrator's note, e.g. a ban-evader flag).
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — changing a staff note needs the \x02admin\x02 privilege.");
        return;
    }
    let Some(target) = target else {
        ctx.notice(me, from.uid, "Syntax: INFO ADD <target> <note> | INFO DEL <target>");
        return;
    };
    let text = note.join(" ");
    let value = if text.trim().is_empty() { None } else { Some(text) };
    let (ok, kind) = if target.starts_with('#') || target.starts_with('&') {
        (db.set_channel_note(target, value.clone()), "channel")
    } else if let Some(account) = db.resolve_account(target).map(str::to_string) {
        (db.set_account_note(&account, value.clone()), "account")
    } else {
        (false, "account")
    };
    if !ok {
        ctx.notice(me, from.uid, t!(ctx, "There's no {kind} \x02{target}\x02.", kind = kind, target = target));
    } else if value.is_some() {
        ctx.notice(me, from.uid, t!(ctx, "Staff note set on \x02{target}\x02.", target = target));
    } else {
        ctx.notice(me, from.uid, t!(ctx, "Staff note on \x02{target}\x02 cleared.", target = target));
    }
}

fn show(me: &str, from: &Sender, target: &str, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let note = if target.starts_with('#') || target.starts_with('&') {
        db.channel_note(target)
    } else {
        db.resolve_account(target).map(str::to_string).and_then(|a| db.account_note(&a))
    };
    match note {
        Some(n) => ctx.notice(me, from.uid, t!(ctx, "Staff note on \x02{target}\x02: {note}", target = target, note = n)),
        None => ctx.notice(me, from.uid, t!(ctx, "No staff note on \x02{target}\x02.", target = target)),
    }
}
