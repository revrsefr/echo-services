//! HostServ assigns virtual hosts (vhosts) to accounts and applies them to the
//! displayed host. Members toggle their own with ON/OFF; operators assign them
//! with SET/DEL and review with LIST. `lib.rs` holds the dispatcher; each
//! command lives in its own file.

use echo_api::{HelpEntry, NetView, Priv, Sender, Service, ServiceCtx, Store};

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

const BLURB: &str = "HostServ gives you a virtual host (vhost). Activate an assigned one, pick one from the menu, or request one from an operator.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "ON", summary: "activate your vhost", detail: "Syntax: \x02ON\x02\nActivates your assigned vhost on your host." },
    HelpEntry { cmd: "OFF", summary: "restore your normal host", detail: "Syntax: \x02OFF\x02\nRestores your normal host." },
    HelpEntry { cmd: "REQUEST", summary: "request a vhost", detail: "Syntax: \x02REQUEST <host>\x02\nAsks an operator to approve a vhost for you." },
    HelpEntry { cmd: "OFFERLIST", summary: "show the vhost menu", detail: "Syntax: \x02OFFERLIST\x02\nShows the self-serve vhost menu." },
    HelpEntry { cmd: "TAKE", summary: "take a vhost from the menu", detail: "Syntax: \x02TAKE <number>\x02\nTakes a vhost from the menu (see OFFERLIST)." },
    HelpEntry { cmd: "SET", summary: "assign a vhost (operator)", detail: "Syntax: \x02SET <account> <host> [duration]\x02\nAssigns a vhost to an account. Operators only." },
    HelpEntry { cmd: "DEL", summary: "remove a vhost (operator)", detail: "Syntax: \x02DEL <account>\x02\nRemoves an account's vhost. Operators only." },
    HelpEntry { cmd: "LIST", summary: "list vhosts (operator)", detail: "Syntax: \x02LIST\x02\nLists assigned vhosts. Operators only." },
    HelpEntry { cmd: "WAITING", summary: "pending requests (operator)", detail: "Syntax: \x02WAITING\x02\nLists pending vhost requests. Operators only." },
    HelpEntry { cmd: "ACTIVATE", summary: "approve a request (operator)", detail: "Syntax: \x02ACTIVATE <account>\x02\nApproves a pending vhost request. Operators only." },
    HelpEntry { cmd: "REJECT", summary: "reject a request (operator)", detail: "Syntax: \x02REJECT <account>\x02\nRejects a pending vhost request. Operators only." },
    HelpEntry { cmd: "OFFER", summary: "add a menu vhost (operator)", detail: "Syntax: \x02OFFER <host>\x02\nAdds a vhost to the self-serve menu. Operators only." },
    HelpEntry { cmd: "OFFERDEL", summary: "remove a menu vhost (operator)", detail: "Syntax: \x02OFFERDEL <number>\x02\nRemoves a menu entry (see OFFERLIST). Operators only." },
    HelpEntry { cmd: "FORBID", summary: "forbid a vhost pattern (operator)", detail: "Syntax: \x02FORBID <regex>\x02\nForbids vhosts matching a pattern. Operators only." },
    HelpEntry { cmd: "FORBIDDEL", summary: "remove a forbidden pattern (operator)", detail: "Syntax: \x02FORBIDDEL <number>\x02\nRemoves a forbidden pattern (see FORBIDLIST). Operators only." },
];

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
            Some("HELP") | None => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
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
