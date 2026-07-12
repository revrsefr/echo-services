use crate::engine::db::{ChanError, Db};
use crate::engine::service::{Sender, Service, ServiceCtx};

pub struct ChanServ {
    pub uid: String,
}

impl Service for ChanServ {
    fn nick(&self) -> &str {
        "ChanServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Channel Services"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut Db) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REGISTER") => {
                let Some(&chan) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: REGISTER <#channel>");
                    return;
                };
                if !chan.starts_with('#') {
                    ctx.notice(me, from.uid, "Channel names start with #.");
                    return;
                }
                // The founder is the account the sender is identified to.
                let Some(account) = from.account else {
                    ctx.notice(me, from.uid, "You must be identified to register a channel.");
                    return;
                };
                match db.register_channel(chan, account) {
                    Ok(()) => {
                        ctx.channel_mode(chan, "+r"); // mark the channel registered
                        ctx.notice(me, from.uid, format!("Channel \x02{chan}\x02 is now registered to \x02{account}\x02."));
                    }
                    Err(ChanError::Exists) => ctx.notice(me, from.uid, format!("\x02{chan}\x02 is already registered.")),
                    Err(_) => ctx.notice(me, from.uid, "Registration failed, please try again later."),
                }
            }
            Some("INFO") => {
                let Some(&chan) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: INFO <#channel>");
                    return;
                };
                match db.channel(chan) {
                    Some(info) => ctx.notice(me, from.uid, format!("\x02{}\x02 is registered to \x02{}\x02 (since {}).", info.name, info.founder, info.ts)),
                    None => ctx.notice(me, from.uid, format!("\x02{chan}\x02 is not registered.")),
                }
            }
            Some("DROP") => {
                let Some(&chan) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: DROP <#channel>");
                    return;
                };
                // Read the founder, then drop, without holding the borrow across the mutation.
                let founder = match db.channel(chan) {
                    Some(info) => info.founder.clone(),
                    None => {
                        ctx.notice(me, from.uid, format!("\x02{chan}\x02 is not registered."));
                        return;
                    }
                };
                if from.account != Some(founder.as_str()) {
                    ctx.notice(me, from.uid, "Only the channel founder can drop it.");
                    return;
                }
                match db.drop_channel(chan) {
                    Ok(()) => {
                        ctx.channel_mode(chan, "-r"); // no longer registered
                        ctx.notice(me, from.uid, format!("Channel \x02{chan}\x02 has been dropped."));
                    }
                    Err(_) => ctx.notice(me, from.uid, "Drop failed, please try again later."),
                }
            }
            Some("HELP") => ctx.notice(me, from.uid, "Commands: REGISTER <#channel>, INFO <#channel>, DROP <#channel>."),
            Some(other) => ctx.notice(me, from.uid, format!("Unknown command: {other}. Try HELP.")),
            None => {}
        }
    }
}
