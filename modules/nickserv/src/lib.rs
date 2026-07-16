use echo_api::Store;
use echo_api::{HelpEntry, Sender, Service, ServiceCtx};
use echo_api::NetView;

#[path = "register.rs"]
mod register;
#[path = "identify.rs"]
mod identify;
#[path = "logout.rs"]
mod logout;
#[path = "cert.rs"]
mod cert;
#[path = "info.rs"]
mod info;
#[path = "alist.rs"]
mod alist;
#[path = "set.rs"]
mod set;
#[path = "saset.rs"]
mod saset;
#[path = "drop.rs"]
mod drop;
#[path = "group.rs"]
mod group;
#[path = "glist.rs"]
mod glist;
#[path = "ungroup.rs"]
mod ungroup;
#[path = "ghost.rs"]
mod ghost;
#[path = "resetpass.rs"]
mod resetpass;
#[path = "confirm.rs"]
mod confirm;
#[path = "ajoin.rs"]
mod ajoin;
#[path = "update.rs"]
mod update;
#[path = "list.rs"]
mod list;
#[path = "getemail.rs"]
mod getemail;
#[path = "suspend.rs"]
mod suspend;
mod noexpire;
#[path = "password.rs"]
mod password;

const BLURB: &str = "NickServ looks after your nickname and account: register it, identify to it, and manage its settings.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "REGISTER", summary: "register your nick as an account", detail: "Syntax: \x02REGISTER <password> [email]\x02\nRegisters your current nick as an account. If an email is given and confirmation is on, you get a code to \x02CONFIRM\x02." },
    HelpEntry { cmd: "IDENTIFY", summary: "log in to your account", detail: "Syntax: \x02IDENTIFY [account] <password>\x02\nLogs you in. Also \x02ID\x02." },
    HelpEntry { cmd: "LOGOUT", summary: "log out to a guest nick", detail: "Syntax: \x02LOGOUT\x02\nLogs you out and moves you to a guest nick. Also \x02LOGOFF\x02." },
    HelpEntry { cmd: "INFO", summary: "show account information", detail: "Syntax: \x02INFO [account]\x02\nShows account information. The email is shown only to the owner." },
    HelpEntry { cmd: "ALIST", summary: "list channels you have access on", detail: "Syntax: \x02ALIST\x02\nLists the channels you hold access on." },
    HelpEntry { cmd: "SET", summary: "change password, email, or preferences", detail: "Syntax: \x02SET PASSWORD <new>\x02, \x02SET EMAIL <address>\x02, \x02SET GREET [message]\x02, \x02SET AUTOOP {ON|OFF}\x02, or \x02SET KILL {ON|OFF}\x02\nChanges your password, email, greet, auto-op, or nick-protection preference." },
    HelpEntry { cmd: "SASET", summary: "change another account's settings (operator)", detail: "Syntax: \x02SASET <account> PASSWORD <new>\x02, \x02EMAIL [address]\x02, or \x02GREET [message]\x02\nEdits another account's settings. Operators only." },
    HelpEntry { cmd: "GROUP", summary: "link this nick to an account", detail: "Syntax: \x02GROUP <account> <password>\x02\nLinks your current nick to an account as an alias, so identifying under it logs into that account." },
    HelpEntry { cmd: "GLIST", summary: "list your grouped nicks", detail: "Syntax: \x02GLIST\x02\nLists the nicks grouped to your account." },
    HelpEntry { cmd: "UNGROUP", summary: "remove a grouped nick", detail: "Syntax: \x02UNGROUP [nick]\x02\nRemoves a grouped nick (your current one by default)." },
    HelpEntry { cmd: "GHOST", summary: "free a session on your nick", detail: "Syntax: \x02GHOST <nick> [password]\x02\nRenames off a session using a nick you own." },
    HelpEntry { cmd: "RECOVER", summary: "reclaim your nick", detail: "Syntax: \x02RECOVER <nick> [password]\x02\nFrees a nick you own and puts you back onto it." },
    HelpEntry { cmd: "RESETPASS", summary: "reset your password by email", detail: "Syntax: \x02RESETPASS <account>\x02, then \x02RESETPASS <account> <code> <newpassword>\x02\nEmails a reset code, then sets a new password with it." },
    HelpEntry { cmd: "CONFIRM", summary: "confirm your email", detail: "Syntax: \x02CONFIRM <code>\x02\nConfirms the email on a newly registered account with the code you were sent." },
    HelpEntry { cmd: "DROP", summary: "delete your account", detail: "Syntax: \x02DROP <password>\x02\nDeletes your account and releases the channels you founded." },
    HelpEntry { cmd: "CERT", summary: "manage SASL EXTERNAL certs", detail: "Syntax: \x02CERT ADD <password> [fingerprint]\x02, \x02CERT DEL <fingerprint>\x02, \x02CERT LIST\x02\nManages the TLS certificate fingerprints that can log in via SASL EXTERNAL." },
    HelpEntry { cmd: "AJOIN", summary: "auto-join channels on login", detail: "Syntax: \x02AJOIN ADD <#channel>\x02, \x02AJOIN DEL <#channel>\x02, \x02AJOIN LIST\x02\nChannels you are auto-joined to when you identify." },
    HelpEntry { cmd: "UPDATE", summary: "refresh your session", detail: "Syntax: \x02UPDATE\x02\nRe-applies your auto-joins and vhost and re-checks for new memos." },
    HelpEntry { cmd: "LIST", summary: "list accounts (oper)", detail: "Syntax: \x02LIST <pattern>\x02\nLists registered accounts matching a glob. Requires the auspex privilege." },
    HelpEntry { cmd: "GETEMAIL", summary: "find accounts by email (oper)", detail: "Syntax: \x02GETEMAIL <email>\x02\nLists accounts registered with a matching email. Requires the auspex privilege." },
    HelpEntry { cmd: "SUSPEND", summary: "block an account (operator)", detail: "Syntax: \x02SUSPEND <account> [reason]\x02\nBlocks an account from logging in. Operators only." },
    HelpEntry { cmd: "UNSUSPEND", summary: "lift a suspension (operator)", detail: "Syntax: \x02UNSUSPEND <account>\x02\nLifts a suspension. Operators only." },
    HelpEntry { cmd: "NOEXPIRE", summary: "pin against expiry (operator)", detail: "Syntax: \x02NOEXPIRE <account> {ON|OFF}\x02\nPins an account so inactivity expiry never drops it. Operators only." },
];

pub struct NickServ {
    pub uid: String,
    // Nick prefix assigned on LOGOUT (default "Guest"); a per-session sequence is
    // appended so successive guests don't collide within a run.
    pub guest_nick: String,
    pub guest_seq: u32,
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
    fn manages_accounts(&self) -> bool {
        true
    }

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        let cmd = args.first().map(|s| s.to_ascii_uppercase());
        // When identity is owned externally (the website), IRC can log in but not
        // create or change an account — those commands are refused.
        if db.external_accounts() && matches!(cmd.as_deref(), Some("REGISTER" | "DROP" | "RESETPASS" | "CONFIRM" | "CERT" | "GROUP" | "UNGROUP")) {
            ctx.notice(me, from.uid, "Your account is managed on the website — register or change it there. From IRC you can only \x02IDENTIFY\x02.");
            return;
        }
        match cmd.as_deref() {
            Some("REGISTER") => register::handle(me, from, args, ctx),
            Some("IDENTIFY") | Some("ID") => identify::handle(me, from, args, ctx, db),
            Some("LOGOUT") | Some("LOGOFF") => logout::handle(me, &self.guest_nick, &mut self.guest_seq, from, ctx),
            Some("CERT") => cert::handle(me, from, args, ctx, db),
            Some("INFO") => info::handle(me, from, args, ctx, net, db),
            Some("ALIST") => alist::handle(me, from, ctx, db),
            Some("SET") => set::handle(me, from, args, ctx, db),
            Some("SASET") => saset::handle(me, from, args, ctx, db),
            Some("DROP") => drop::handle(me, from, args, ctx, net, db),
            Some("GROUP") => group::handle(me, from, args, ctx, db),
            Some("GLIST") => glist::handle(me, from, ctx, db),
            Some("UNGROUP") => ungroup::handle(me, from, args, ctx, db),
            Some("GHOST") => ghost::handle(me, &self.guest_nick, &mut self.guest_seq, from, args, ctx, net, db, false),
            Some("RECOVER") => ghost::handle(me, &self.guest_nick, &mut self.guest_seq, from, args, ctx, net, db, true),
            Some("RESETPASS") => resetpass::handle(me, from, args, ctx, db),
            Some("CONFIRM") => confirm::handle(me, from, args, ctx, db),
            Some("AJOIN") => ajoin::handle(me, from, args, ctx, db),
            Some("SUSPEND") => suspend::handle(me, from, args, ctx, net, db, true),
            Some("UNSUSPEND") => suspend::handle(me, from, args, ctx, net, db, false),
            Some("NOEXPIRE") => noexpire::handle(me, from, args, ctx, db),
            Some("UPDATE") => update::handle(me, from, ctx, db),
            Some("LIST") => list::handle(me, from, args, ctx, db),
            Some("GETEMAIL") => getemail::handle(me, from, args, ctx, db),
            Some("HELP") => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
            None => {}
        }
    }
}
