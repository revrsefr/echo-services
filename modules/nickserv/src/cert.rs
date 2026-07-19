use echo_api::{CertError, Store};
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

// CERT ADD|DEL|LIST [password] [fingerprint]: manage the TLS certificate
// fingerprints that may log in to your account via SASL EXTERNAL. An identified
// caller acts on their own account with no password; an unidentified one must
// supply a throttled password (so CERT still works mid-session and can't be
// abused as a guessing oracle).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("LIST") => {
            let Some((account, _)) = resolve(me, from, ctx, db, &args[2..]) else {
                return;
            };
            let fps = db.certfps(&account);
            if fps.is_empty() {
                ctx.notice(me, from.uid, "No certificate fingerprints are registered to your account.");
            } else {
                ctx.notice(me, from.uid, t!(ctx, "Registered fingerprints: {list}", list = fps.join(", ")));
            }
        }
        Some("ADD") => {
            let Some((account, rest)) = resolve(me, from, ctx, db, &args[2..]) else {
                return;
            };
            let Some(&fp) = rest.first() else {
                ctx.notice(me, from.uid, "Syntax: CERT ADD [password] <fingerprint>");
                return;
            };
            match db.certfp_add(&account, fp) {
                Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Added fingerprint \x02{fp}\x02. You can now log in with SASL EXTERNAL.", fp = fp)),
                Err(CertError::InUse) => ctx.notice(me, from.uid, "That fingerprint is already registered."),
                Err(CertError::Invalid) => ctx.notice(me, from.uid, "That does not look like a certificate fingerprint."),
                Err(CertError::Full) => ctx.notice(me, from.uid, "You have too many fingerprints registered. Remove one first."),
                Err(CertError::NoAccount | CertError::Internal) => ctx.notice(me, from.uid, "Could not add the fingerprint, please try again later."),
            }
        }
        Some("DEL") | Some("REMOVE") => {
            let Some((account, rest)) = resolve(me, from, ctx, db, &args[2..]) else {
                return;
            };
            let Some(&fp) = rest.first() else {
                ctx.notice(me, from.uid, "Syntax: CERT DEL [password] <fingerprint>");
                return;
            };
            match db.certfp_del(&account, fp) {
                Ok(true) => ctx.notice(me, from.uid, t!(ctx, "Removed fingerprint \x02{fp}\x02.", fp = fp)),
                Ok(false) => ctx.notice(me, from.uid, "No such fingerprint is registered to your account."),
                Err(_) => ctx.notice(me, from.uid, "Could not remove the fingerprint, please try again later."),
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: CERT ADD|DEL|LIST [password] [fingerprint]"),
    }
}

// Resolve the acting account and the arguments that follow it. An identified
// caller operates on their own account and passes no password, so `rest` is
// returned untouched; otherwise the first argument is the throttled password and
// the remainder follows it.
fn resolve<'a>(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store, rest: &'a [&'a str]) -> Option<(String, &'a [&'a str])> {
    if let Some(account) = from.account {
        return Some((account.to_string(), rest));
    }
    let Some((&password, tail)) = rest.split_first() else {
        ctx.notice(me, from.uid, "Identify to NickServ first, or start the command with your password.");
        return None;
    };
    let account = verify(me, from, ctx, db, password)?;
    Some((account, tail))
}

// Verify the caller's password against the account matching their current nick,
// throttled and recorded like IDENTIFY — so CERT can't be used as an unthrottled
// guessing oracle (a user can `/nick victim` then CERT LIST <guess>) and each ~1s
// verify can't be spammed to stall the engine.
fn verify(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store, password: &str) -> Option<String> {
    if let Some(secs) = db.auth_lockout(from.nick) {
        ctx.notice(me, from.uid, t!(ctx, "Too many failed attempts. Please wait {secs}s and try again.", secs = secs));
        return None;
    }
    match db.authenticate(from.nick, password).map(str::to_string) {
        Some(account) => {
            db.note_auth(from.nick, true);
            Some(account)
        }
        None => {
            db.note_auth(from.nick, false);
            ctx.auth_report(false, Some(from.nick), "NickServ CERT", from.uid, Some("bad password"));
            ctx.notice(me, from.uid, "Invalid password.");
            None
        }
    }
}
