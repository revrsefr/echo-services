//! Redeeming website login keycards. A member already authenticated on the
//! website (a Django session) connects with a single-use `kc_…` token instead of
//! replaying their password. It isn't the account password, so it can't be
//! checked against a SCRAM verifier — we hand it to Django's localhost
//! login-token endpoint, which redeems the keycard (exactly once) and confirms
//! the bound account.
//!
//! Runs on a blocking thread (see link.rs): a synchronous localhost round-trip,
//! never on the reactor or under the engine lock.
use crate::config::Keycard;

/// Redeem `token` for `account` against the configured endpoint. Returns true
/// only on a confirmed success (HTTP 2xx). A missing config, transport error, or
/// any non-2xx (bad / expired / already-used / account-mismatched keycard) is a
/// clean `false` — the caller then fails the SASL exchange.
pub fn redeem(cfg: Option<&Keycard>, account: &str, token: &str) -> bool {
    let Some(cfg) = cfg else { return false };
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(3))
        .timeout_read(std::time::Duration::from_secs(4))
        .build();
    agent
        .post(&cfg.url)
        .set("X-API-Key", &cfg.api_key)
        .send_form(&[("username", account), ("password", token)])
        .is_ok()
}
