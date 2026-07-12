use crate::engine::db::{CertError, Db};
use crate::engine::service::{Sender, Service, ServiceCtx};
use crate::proto::RegReply;

pub struct NickServ {
    pub uid: String,
    // Nick prefix assigned on LOGOUT (default "Guest"); a per-session sequence is
    // appended so successive guests don't collide within a run.
    pub guest_nick: String,
    pub guest_seq: u32,
}

impl Service for NickServ {
    fn nick(&self) -> &str {
        "NickServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Nickname Services"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut Db) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REGISTER") => {
                // REGISTER <password> [email] — registers the sender's current nick.
                let Some(password) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: REGISTER <password> [email]");
                    return;
                };
                let email = args.get(2).map(|s| s.to_string());
                // The engine derives the password off-thread, commits, and answers.
                ctx.defer_register(from.nick, *password, email, RegReply::NickServ {
                    agent: me.to_string(),
                    uid: from.uid.to_string(),
                    nick: from.nick.to_string(),
                });
            }
            Some("IDENTIFY") => {
                let Some(password) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: IDENTIFY <password>");
                    return;
                };
                match db.authenticate(from.nick, password) {
                    Some(account) => {
                        // Already identified to this account: don't re-fire the login.
                        if from.account == Some(account) {
                            ctx.notice(me, from.uid, format!("You are already identified for \x02{}\x02.", account));
                            return;
                        }
                        let account = account.to_string();
                        ctx.login(from.uid, &account);
                        ctx.notice(me, from.uid, format!("You are now identified for \x02{}\x02.", account));
                    }
                    None => ctx.notice(me, from.uid, "Invalid password."),
                }
            }
            Some("LOGOUT") | Some("LOGOFF") => {
                if from.account.is_none() {
                    ctx.notice(me, from.uid, "You are not logged in.");
                    return;
                }
                // Guest nick = prefix + sequence (seeded from the link TS, bumped
                // per logout). Inlined field access so it stays disjoint from `me`.
                let guest = format!("{}{}", self.guest_nick, self.guest_seq);
                self.guest_seq = self.guest_seq.wrapping_add(1);
                ctx.logout(from.uid);
                ctx.force_nick(from.uid, &guest);
                ctx.notice(me, from.uid, format!("You are now logged out. Your nick is now \x02{}\x02.", guest));
            }
            Some("CERT") => self.cert(from, &args, ctx, db),
            Some("HELP") => ctx.notice(
                me,
                from.uid,
                "Commands: REGISTER <password> [email], IDENTIFY <password>, LOGOUT, CERT ADD|DEL|LIST <password> [fingerprint].",
            ),
            Some(other) => ctx.notice(me, from.uid, format!("Unknown command: {}. Try HELP.", other)),
            None => {}
        }
    }
}

impl NickServ {
    // CERT ADD|DEL|LIST <password> [fingerprint]: manage the TLS certificate
    // fingerprints that may log in to your account via SASL EXTERNAL. Gated by
    // the account password, so it needs no separate identified-session state.
    fn cert(&self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut Db) {
        let me = self.uid.as_str();
        // All subcommands authenticate the sender's nick's account by password.
        let auth = |db: &Db, password: &str| db.authenticate(from.nick, password).map(str::to_string);
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
}
