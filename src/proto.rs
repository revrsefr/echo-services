// The normalized protocol vocabulary lives in the fedserv-api SDK crate;
// re-exported so the engine keeps referring to it as `crate::proto::*`. The
// concrete ircd link (InspIRCd) is an external module crate, not part of core.
pub use fedserv_api::{NetAction, NetEvent, Protocol, RegReply};
