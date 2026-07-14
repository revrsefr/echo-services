//! HostServ assigns virtual hosts (vhosts) to accounts and applies them to the
//! displayed host. Members toggle their own with ON/OFF; operators assign them
//! with SET/DEL and review with LIST. `lib.rs` holds the dispatcher; each
//! command lives in its own file.

use echo_api::{NetView, Priv, Sender, Service, ServiceCtx, Store};

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
#[path = "forbid.rs"]
mod forbid;
#[path = "template.rs"]
mod template;
#[path = "default.rs"]
mod default;

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
            Some("FORBID") => forbid::add(me, from, args, ctx, db),
            Some("FORBIDLIST") => forbid::list(me, from, ctx, db),
            Some("FORBIDDEL") => forbid::del(me, from, args, ctx, db),
            Some("TEMPLATE") => template::handle(me, from, args, ctx, db),
            Some("DEFAULT") => default::handle(me, from, ctx, db),
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

// Canonicalise a vhost the way the ircd will actually display it: the host part
// only allows letters, digits, dots and hyphens, so a disallowed character it
// would rewrite (an underscore becomes a hyphen) is rewritten here first. This
// keeps what we store identical to what shows on the network, so two inputs
// that would collapse to the same host are detected as one.
pub(crate) fn normalize_vhost(spec: &str) -> String {
    let (ident, host) = match spec.split_once('@') {
        Some((i, h)) => (Some(i), h),
        None => (None, spec),
    };
    let norm_host: String = host.chars().map(|c| if c == '_' { '-' } else { c }).collect();
    match ident {
        Some(i) => format!("{i}@{norm_host}"),
        None => norm_host,
    }
}

// Normalise a requested vhost and check it's valid and not already another
// account's. Returns the canonical spec to store, or a message to show.
pub(crate) fn prepare_vhost(spec: &str, account: &str, db: &dyn Store) -> Result<String, String> {
    let host = normalize_vhost(spec);
    if !valid_vhost(&host) {
        return Err(format!("\x02{host}\x02 isn't a valid host (letters, digits, hyphens and dots)."));
    }
    if db.vhost_owner(&host).is_some_and(|owner| !owner.eq_ignore_ascii_case(account)) {
        return Err(format!("\x02{host}\x02 is already in use. Please choose another."));
    }
    Ok(host)
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
