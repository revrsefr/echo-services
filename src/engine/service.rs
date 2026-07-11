use crate::engine::db::Db;
use crate::proto::NetAction;

// Who sent the command, resolved by the engine (UID + current nick).
pub struct Sender<'a> {
    pub uid: &'a str,
    pub nick: &'a str,
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
}
