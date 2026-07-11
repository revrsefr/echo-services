use crate::proto::NetAction;

// A pseudo-client (NickServ, ChanServ, OperServ, ...). Introduced at burst,
// receives the commands users message it, and pushes actions onto the ctx.
pub trait Service: Send {
    fn nick(&self) -> &str;
    fn uid(&self) -> &str;
    fn host(&self) -> &str {
        "services.local"
    }
    fn gecos(&self) -> &str;
    fn on_command(&mut self, from: &str, args: &[&str], ctx: &mut ServiceCtx);
}

// What a service can do in response to a command, collected for the link to flush.
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
