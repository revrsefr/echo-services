//! A minimal example service module — the smallest complete `Service`, meant to
//! be copied when writing a new pseudo-client. It depends on nothing but the
//! `fedserv-api` SDK crate, reads through the `Store`/`NetView` traits, and
//! answers users by pushing notices onto the `ServiceCtx`. It never mutates the
//! store, so it is safe to enable anywhere.
//!
//! To run it: add `"example"` to `[modules] services` in the config. To ship a
//! real module, replace the commands below with your own and register the struct
//! in the daemon's `main.rs` (see MODULES.md).

use fedserv_api::{human_time, NetView, Sender, Service, ServiceCtx, Store};

// A service is a plain struct. It is introduced to the network at burst and then
// receives the commands users message it. `uid` is assigned by the daemon.
pub struct ExampleServ {
    pub uid: String,
}

impl Service for ExampleServ {
    // The nick, uid and gecos the pseudo-client is introduced with.
    fn nick(&self) -> &str {
        "ExampleServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Example Service (SDK template)"
    }

    // One message from a user, already split into `args`. `from` is who sent it,
    // `net` is a read-only view of the live network, `store` the account/channel
    // store. Emit replies by pushing onto `ctx`; the engine sends them.
    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, store: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            // Reading the sender + the account store. `from.account` is set when
            // the user is logged in; `store.account` hands back a view with only
            // non-secret fields (never a password hash).
            Some("WHOAMI") => match from.account.and_then(|a| store.account(a)) {
                Some(acct) => {
                    let email = acct.email.as_deref().unwrap_or("(none)");
                    let state = if acct.verified { "verified" } else { "unverified" };
                    ctx.notice(me, from.uid, format!(
                        "You are \x02{}\x02, registered {} ({state}), email {email}.",
                        acct.name, human_time(acct.ts),
                    ));
                }
                None => ctx.notice(me, from.uid, "You are not logged in to an account."),
            },
            // Reading the live network view.
            Some("LOOKUP") => {
                let Some(&nick) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: LOOKUP <nick>");
                    return;
                };
                match net.uid_by_nick(nick) {
                    Some(uid) => {
                        let host = net.host_of(uid).unwrap_or("*");
                        let account = net.account_of(uid).unwrap_or("(not logged in)");
                        ctx.notice(me, from.uid, format!("\x02{nick}\x02 is online — host {host}, account {account}."));
                    }
                    None => ctx.notice(me, from.uid, format!("\x02{nick}\x02 is not online.")),
                }
            }
            Some("HELP") | None => ctx.notice(me, from.uid, "Commands: \x02WHOAMI\x02, \x02LOOKUP\x02 <nick>."),
            Some(other) => ctx.notice(me, from.uid, format!("Unknown command \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}
