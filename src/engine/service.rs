// Sender, ServiceCtx, and the Service trait a pseudo-client implements all live
// in the fedserv-api SDK crate; re-exported so the engine and the service
// modules keep using `crate::engine::service::{...}`.
pub use fedserv_api::{Sender, Service, ServiceCtx};
