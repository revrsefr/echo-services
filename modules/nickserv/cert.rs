use crate::engine::db::{CertError, Store};
use crate::engine::service::{Sender, ServiceCtx};

// CERT ADD|DEL|LIST <password> [fingerprint]: manage the TLS certificate
// fingerprints that may log in to your account via SASL EXTERNAL. Each
// subcommand is password-gated, so it needs no identified-session state.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let auth = |db: &dyn Store, password: &str| db.authenticate(from.nick, password).map(str::to_string);
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("LIST") => {
            let Some(password) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: CERT LIST <password>");
                return;
            };
            let Some(account) = auth(db, password) else {
                ctx.notice(me, from.uid, "Invalid password.");
                return;
            };
            let fps = db.certfps(&account);
            if fps.is_empty() {
                ctx.notice(me, from.uid, "No certificate fingerprints are registered to your account.");
            } else {
                ctx.notice(me, from.uid, format!("Registered fingerprints: {}", fps.join(", ")));
            }
        }
        Some("ADD") => {
            let (Some(password), Some(fp)) = (args.get(2), args.get(3)) else {
                ctx.notice(me, from.uid, "Syntax: CERT ADD <password> <fingerprint>");
                return;
            };
            let Some(account) = auth(db, password) else {
                ctx.notice(me, from.uid, "Invalid password.");
                return;
            };
            match db.certfp_add(&account, fp) {
                Ok(()) => ctx.notice(me, from.uid, format!("Added fingerprint \x02{fp}\x02. You can now log in with SASL EXTERNAL.")),
                Err(CertError::InUse) => ctx.notice(me, from.uid, "That fingerprint is already registered."),
                Err(CertError::Invalid) => ctx.notice(me, from.uid, "That does not look like a certificate fingerprint."),
                Err(CertError::NoAccount | CertError::Internal) => ctx.notice(me, from.uid, "Could not add the fingerprint, please try again later."),
            }
        }
        Some("DEL") | Some("REMOVE") => {
            let (Some(password), Some(fp)) = (args.get(2), args.get(3)) else {
                ctx.notice(me, from.uid, "Syntax: CERT DEL <password> <fingerprint>");
                return;
            };
            let Some(account) = auth(db, password) else {
                ctx.notice(me, from.uid, "Invalid password.");
                return;
            };
            match db.certfp_del(&account, fp) {
                Ok(true) => ctx.notice(me, from.uid, format!("Removed fingerprint \x02{fp}\x02.")),
                Ok(false) => ctx.notice(me, from.uid, "No such fingerprint is registered to your account."),
                Err(_) => ctx.notice(me, from.uid, "Could not remove the fingerprint, please try again later."),
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: CERT ADD|DEL|LIST <password> [fingerprint]"),
    }
}
