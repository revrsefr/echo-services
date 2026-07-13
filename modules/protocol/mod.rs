// Protocol layer. The normalized vocabulary (NetEvent / NetAction / RegReply)
// and the Protocol trait live in the fedserv-api SDK crate; re-exported here so
// the engine and the ircd modules keep referring to them as `crate::proto::*`.
pub mod inspircd;

pub use fedserv_api::{NetAction, NetEvent, Protocol, RegReply};
