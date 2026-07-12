use crate::engine::db::Db;
use crate::proto::{NetAction, RegReply};

// Who sent the command, resolved by the engine (UID + current nick + the
// account they are identified to, if any).
pub struct Sender<'a> {
    pub uid: &'a str,
    pub nick: &'a str,
    pub account: Option<&'a str>,
}

// A pseudo-client (NickServ, ChanServ, ...). Introduced at burst, receives the
// commands users message it, reads/writes the account store, and pushes actions.
pub trait Service: Send {
    fn nick(&self) -> &str;
    fn uid(&self) -> &str;
    fn host(&self) -> &str {
        "services.local"
    }
    fn gecos(&self) -> &str;
    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut Db);
}

#[derive(Default)]
pub struct ServiceCtx {
    pub actions: Vec<NetAction>,
}

impl ServiceCtx {
    pub fn notice(&mut self, from: &str, to: &str, text: impl Into<String>) {
        self.actions.push(NetAction::Notice {
            from: from.to_string(),
            to: to.to_string(),
            text: text.into(),
        });
    }

    // Hand a registration to the engine to finish: its password derivation runs
    // off the reactor, then the engine commits it and answers `reply`.
    pub fn defer_register(&mut self, account: impl Into<String>, password: impl Into<String>, email: Option<String>, reply: RegReply) {
        self.actions.push(NetAction::DeferRegister {
            account: account.into(),
            password: password.into(),
            email,
            reply,
        });
    }

    // Log a user into an account: sets the accountname the ircd turns into
    // RPL_LOGGEDIN (900) and exposes to account-tag / WHOX, the same login the
    // SASL agent applies. Used after a successful REGISTER / IDENTIFY.
    pub fn login(&mut self, uid: &str, account: &str) {
        self.actions.push(NetAction::Metadata {
            target: uid.to_string(),
            key: "accountname".to_string(),
            value: account.to_string(),
        });
    }

    // Log a user out: clearing the accountname the ircd turns into RPL_LOGGEDOUT
    // (901) and drops from account-tag / WHOX. The inverse of `login`.
    pub fn logout(&mut self, uid: &str) {
        self.actions.push(NetAction::Metadata {
            target: uid.to_string(),
            key: "accountname".to_string(),
            value: String::new(),
        });
    }

    // Force a user's nick (SVSNICK), e.g. to a guest nick after logout.
    pub fn force_nick(&mut self, uid: &str, nick: &str) {
        self.actions.push(NetAction::ForceNick {
            uid: uid.to_string(),
            nick: nick.to_string(),
        });
    }
}
