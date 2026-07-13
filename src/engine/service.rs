use crate::engine::db::Db;
use crate::engine::state::Network;

// Sender + ServiceCtx (the command context a module receives) live in the
// fedserv-api SDK crate; re-exported so modules keep using
// `crate::engine::service::{Sender, ServiceCtx}`.
pub use fedserv_api::{Sender, ServiceCtx};

// A pseudo-client (NickServ, ChanServ, ...). Introduced at burst, receives the
// commands users message it, reads/writes the account store, and pushes actions.
pub trait Service: Send {
    fn nick(&self) -> &str;
    fn uid(&self) -> &str;
    fn host(&self) -> &str {
        "services.local"
    }
    fn gecos(&self) -> &str;
    // Whether this service owns channel modes (ChanServ), so the engine can source
    // channel mode changes from it.
    fn manages_channels(&self) -> bool {
        false
    }
    // Whether this is the account service (NickServ), so the engine can source
    // account-related notices from it.
    fn manages_accounts(&self) -> bool {
        false
    }
    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &Network, db: &mut Db);
}
