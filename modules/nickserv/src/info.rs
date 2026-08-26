use echo_api::{human_ago, human_time, NetView, Priv, ProfileField, Store};
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

// INFO [account]: show an account's registration details. The email and other
// private fields are shown to the account's own owner, or to an oper with the
// auspex privilege.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let name = args.get(1).copied().unwrap_or(from.nick);
    let Some(acct) = db.account(name) else {
        ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 isn't registered.", name = name));
        return;
    };
    let is_owner = from.account == Some(acct.name.as_str());
    let privileged = is_owner || from.privs.has(Priv::Auspex);
    ctx.notice(me, from.uid, t!(ctx, "Information for \x02{name}\x02:", name = acct.name));
    let age = human_ago(ctx.lang(), now_unix().saturating_sub(acct.ts));
    ctx.notice(me, from.uid, t!(ctx, "  Registered : {when} ({age} ago)", when = human_time(acct.ts), age = age));
    // Last-seen is public by default; SET HIDE STATUS keeps it to owner and opers.
    if privileged || !acct.hide_status {
        let last_seen = if net.uids_logged_into(&acct.name).is_empty() {
            human_time(acct.last_seen)
        } else {
            "now (online)".to_string()
        };
        ctx.notice(me, from.uid, t!(ctx, "  Last seen  : {last_seen}", last_seen = last_seen));
    }
    // A greet is public — the bot shows it in-channel to everyone anyway.
    if !acct.greet.is_empty() {
        ctx.notice(me, from.uid, t!(ctx, "  Greet      : {greet}", greet = acct.greet));
    }
    // Public profile fields (avatar/bio/pronouns/timezone/url), shown to everyone —
    // the same values are published to clients as IRCv3 metadata.
    for field in ProfileField::ALL {
        if let Some(v) = db.profile_field(&acct.name, field) {
            let label = format!("{:<8}", field.meta_key());
            ctx.notice(me, from.uid, t!(ctx, "  {label} : {value}", label = label, value = v));
        }
    }
    if privileged {
        if let Some(s) = db.suspension(&acct.name) {
            ctx.notice(me, from.uid, t!(ctx, "  Suspended  : by \x02{by}\x02 — {reason}", by = s.by, reason = s.reason));
        }
        match &acct.email {
            Some(email) if acct.verified => ctx.notice(me, from.uid, t!(ctx, "  Email      : {email}", email = email)),
            Some(email) => ctx.notice(me, from.uid, t!(ctx, "  Email      : {email} (unconfirmed)", email = email)),
            None => ctx.notice(me, from.uid, "  Email      : (none set)"),
        }
        let ajoin = db.ajoin_list(&acct.name);
        if !ajoin.is_empty() {
            ctx.notice(me, from.uid, echo_api::plural!(ctx, ajoin.len(), one = "  Auto-join  : {count} channel — see \x02AJOIN LIST\x02", other = "  Auto-join  : {count} channels — see \x02AJOIN LIST\x02", count = ajoin.len()));
        }
    }
    // A staff note is for operators' eyes only, never the account's owner.
    if from.privs.has(Priv::Auspex) {
        if let Some(note) = db.account_note(&acct.name) {
            ctx.notice(me, from.uid, t!(ctx, "  Staff note : {note}", note = note));
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
