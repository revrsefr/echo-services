use crate::engine::service::{Service, ServiceCtx};

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

    fn on_command(&mut self, from: &str, args: &[&str], ctx: &mut ServiceCtx) {
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("HELP") => ctx.notice(self.uid(), from, "Commands: REGISTER, IDENTIFY (coming soon)."),
            Some(other) => ctx.notice(self.uid(), from, format!("Unknown command: {}. Try HELP.", other)),
            None => {}
        }
    }
}
