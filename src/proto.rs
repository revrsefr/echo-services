// The normalized protocol vocabulary lives in the echo-api SDK crate;
// re-exported so the engine keeps referring to it as `crate::proto::*`. The
// concrete ircd link (InspIRCd) is an external module crate, not part of core.
pub use echo_api::{AuthThen, NetAction, NetEvent, Protocol, RegReply};
