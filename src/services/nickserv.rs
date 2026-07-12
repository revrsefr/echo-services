use crate::engine::db::Db;
use crate::engine::service::{Sender, Service, ServiceCtx};
use crate::proto::RegReply;

pub struct NickServ {
    pub uid: String,
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
                        let account = account.to_string();
                        ctx.login(from.uid, &account);
                        ctx.notice(me, from.uid, format!("You are now identified for \x02{}\x02.", account));
                    }
                    None => ctx.notice(me, from.uid, "Invalid password."),
                }
            }
            Some("HELP") => {
                ctx.notice(me, from.uid, "Commands: REGISTER <password> [email], IDENTIFY <password>.")
            }
            Some(other) => ctx.notice(me, from.uid, format!("Unknown command: {}. Try HELP.", other)),
            None => {}
        }
    }
}
