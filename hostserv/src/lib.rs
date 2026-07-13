//! HostServ assigns virtual hosts (vhosts) to accounts and applies them to the
//! displayed host. Members toggle their own with ON/OFF; operators assign them
//! with SET/DEL and review with LIST. `lib.rs` holds the dispatcher; each
//! command lives in its own file.

use fedserv_api::{NetView, Priv, Sender, Service, ServiceCtx, Store};

#[path = "on.rs"]
mod on;
#[path = "off.rs"]
mod off;
#[path = "set.rs"]
mod set;
#[path = "del.rs"]
mod del;
#[path = "list.rs"]
mod list;

pub struct HostServ {
    pub uid: String,
}

impl Service for HostServ {
    fn nick(&self) -> &str {
        "HostServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Host Services"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("ON") => on::handle(me, from, ctx, db),
            Some("OFF") => off::handle(me, from, ctx, net, db),
            Some("SET") => set::handle(me, from, args, ctx, net, db),
            Some("DEL") => del::handle(me, from, args, ctx, net, db),
            Some("LIST") => list::handle(me, from, ctx, db),
            Some("HELP") | None => ctx.notice(me, from.uid, "HostServ gives you a vhost: \x02ON\x02 activates your assigned vhost, \x02OFF\x02 restores your normal host. Operators use \x02SET\x02 <account> <host>, \x02DEL\x02 <account> and \x02LIST\x02."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}

// Operator gate for vhost administration.
fn require_oper(me: &str, from: &Sender, ctx: &mut ServiceCtx) -> bool {
    if from.privs.has(Priv::Admin) {
        return true;
    }
    ctx.notice(me, from.uid, "Access denied — assigning vhosts is for services operators.");
    false
}

// Whether `host` is a syntactically valid vhost: a hostname of dot-separated
// labels using letters, digits and hyphens, not too long.
pub(crate) fn valid_vhost(host: &str) -> bool {
    if host.is_empty() || host.len() > 64 || !host.contains('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
