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
#[path = "request.rs"]
mod request;
#[path = "waiting.rs"]
mod waiting;
#[path = "approve.rs"]
mod approve;
#[path = "offer.rs"]
mod offer;
#[path = "take.rs"]
mod take;

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
            // SET(ALL)/DEL(ALL): the per-account model already covers every
            // grouped nick, so ALL is an alias, and GROUP is a no-op reassurance.
            Some("SET") | Some("SETALL") => set::handle(me, from, args, ctx, net, db),
            Some("DEL") | Some("DELALL") => del::handle(me, from, args, ctx, net, db),
            Some("GROUP") => ctx.notice(me, from.uid, "Your vhost already applies to all your grouped nicks — nothing to sync."),
            Some("LIST") => list::handle(me, from, ctx, db),
            Some("REQUEST") => request::handle(me, from, args, ctx, db),
            Some("WAITING") => waiting::handle(me, from, ctx, db),
            Some("ACTIVATE") | Some("APPROVE") => approve::handle(me, from, args, ctx, net, db, true),
            Some("REJECT") => approve::handle(me, from, args, ctx, net, db, false),
            Some("OFFER") => offer::add(me, from, args, ctx, db),
            Some("OFFERLIST") => offer::list(me, from, ctx, db),
            Some("OFFERDEL") => offer::del(me, from, args, ctx, db),
            Some("TAKE") => take::handle(me, from, args, ctx, db),
            Some("HELP") | None => ctx.notice(me, from.uid, "HostServ gives you a vhost: \x02ON\x02 activates your assigned vhost, \x02OFF\x02 restores your normal host, \x02REQUEST\x02 <host> asks for one, \x02OFFERLIST\x02 + \x02TAKE\x02 <n> pick from the menu. Operators use \x02SET\x02/\x02DEL\x02 <account>, \x02LIST\x02, \x02WAITING\x02 + \x02ACTIVATE\x02/\x02REJECT\x02, and \x02OFFER\x02/\x02OFFERDEL\x02 for the menu."),
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

// Whether `spec` is a valid vhost: an optional `ident@` (letters, digits, a few
// punctuation) followed by a hostname of dot-separated alphanumeric/hyphen labels.
pub(crate) fn valid_vhost(spec: &str) -> bool {
    let (ident, host) = match spec.split_once('@') {
        Some((i, h)) => (Some(i), h),
        None => (None, spec),
    };
    if let Some(i) = ident {
        if i.is_empty() || i.len() > 12 || !i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
            return false;
        }
    }
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
