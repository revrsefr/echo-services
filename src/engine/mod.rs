pub mod db;
pub mod service;
pub mod state;

use std::collections::HashMap;

use crate::proto::{NetAction, NetEvent};
use db::{Db, RegError};
use service::{Sender, Service, ServiceCtx};
use state::Network;

// SASL mechanisms we offer. Advertised to the uplink as the `sasl=` capability
// value (IRCv3 SASL 3.2 mechanism list) and the set we accept in the exchange.
const SASL_MECHS: &str = "PLAIN";

// A client's base64 response is split into chunks of this length; a chunk
// shorter than this (or a lone "+") marks the end of the response (SASL 3.1).
const MAX_AUTHENTICATE: usize = 400;

// Upper bound on a reassembled response, to cap a pre-auth client's buffer.
const MAX_SASL_RESPONSE: usize = 8 * 1024;

// A client's in-progress SASL exchange: the chosen mechanism and the base64
// response reassembled from the uplink's fixed-size AUTHENTICATE chunks.
#[derive(Default)]
struct SaslSession {
    mech: String,
    response: String,
}

pub struct Engine {
    services: Vec<Box<dyn Service>>,
    network: Network,
    db: Db,
    sasl_sessions: HashMap<String, SaslSession>, // client uid -> in-progress exchange
}

impl Engine {
    pub fn new(services: Vec<Box<dyn Service>>, db: Db) -> Self {
        Self { services, network: Network::default(), db, sasl_sessions: HashMap::new() }
    }

    // Sent right after the SERVER line: burst, introduce every service, endburst.
    pub fn startup_actions(&self) -> Vec<NetAction> {
        let mut out = vec![NetAction::Burst];
        for svc in &self.services {
            out.push(NetAction::IntroduceUser {
                uid: svc.uid().to_string(),
                nick: svc.nick().to_string(),
                ident: "services".to_string(),
                host: svc.host().to_string(),
                gecos: svc.gecos().to_string(),
            });
        }
        // Advertise our SASL mechanisms so the uplink can offer `sasl=PLAIN` to
        // clients in CAP LS (IRCv3 SASL 3.2).
        out.push(NetAction::Metadata {
            target: "*".to_string(),
            key: "saslmechlist".to_string(),
            value: SASL_MECHS.to_string(),
        });
        out.push(NetAction::EndBurst);
        out
    }

    pub fn handle(&mut self, event: NetEvent) -> Vec<NetAction> {
        match event {
            NetEvent::Ping { token, from } => vec![NetAction::Pong { token, from }],
            NetEvent::UserConnect { uid, nick } => {
                self.network.user_connect(uid, nick);
                Vec::new()
            }
            NetEvent::Quit { uid } => {
                self.network.user_quit(&uid);
                Vec::new()
            }
            NetEvent::Privmsg { from, to, text } => self.dispatch(&from, &to, &text),
            NetEvent::AccountRequest { reqid, kind, account, p2, p3, .. } => {
                self.account_request(reqid, kind, account, p2, p3)
            }
            NetEvent::Sasl { client, mode, data, .. } => self.sasl(client, mode, data),
            _ => Vec::new(),
        }
    }

    // SASL agent side of the exchange the ircd relays to us (modes H/S/C/D),
    // per IRCv3 SASL 3.2. PLAIN only: on a valid client response we set the
    // client's account (drives 900) then report success (drives 903); a bad
    // credential or unknown mechanism reports failure (drives 904).
    fn sasl(&mut self, client: String, mode: String, data: Vec<String>) -> Vec<NetAction> {
        let agent = match self.services.first() {
            Some(s) => s.uid().to_string(),
            None => return Vec::new(),
        };
        let mk = |mode: &str, d: Vec<String>| {
            vec![NetAction::Sasl { agent: agent.clone(), client: client.clone(), mode: mode.to_string(), data: d }]
        };
        match mode.as_str() {
            "H" => Vec::new(), // host info
            "S" => match data.first().map(String::as_str) {
                Some("PLAIN") => {
                    self.sasl_sessions.insert(
                        client.clone(),
                        SaslSession { mech: "PLAIN".to_string(), response: String::new() },
                    );
                    mk("C", vec!["+".to_string()]) // empty challenge -> client sends the payload
                }
                _ => mk("D", vec!["F".to_string()]), // unsupported mechanism
            },
            "C" => {
                // Reassemble the base64 response: append each chunk until one is
                // shorter than a full chunk (or a lone "+"), which ends it.
                let chunk = data.first().map(String::as_str).unwrap_or("");
                let overflowed = match self.sasl_sessions.get_mut(&client) {
                    Some(s) => {
                        if chunk != "+" {
                            s.response.push_str(chunk);
                        }
                        s.response.len() > MAX_SASL_RESPONSE
                    }
                    None => return mk("D", vec!["F".to_string()]),
                };
                if overflowed {
                    self.sasl_sessions.remove(&client);
                    return mk("D", vec!["F".to_string()]);
                }
                if chunk.len() >= MAX_AUTHENTICATE {
                    return Vec::new(); // more chunks still to come
                }
                let session = self.sasl_sessions.remove(&client).unwrap_or_default();
                let account = (session.mech == "PLAIN")
                    .then(|| login_plain(&session.response, &self.db))
                    .flatten();
                match account {
                    Some(account) => vec![
                        NetAction::Metadata {
                            target: client.clone(),
                            key: "accountname".to_string(),
                            value: account,
                        },
                        NetAction::Sasl {
                            agent: agent.clone(),
                            client: client.clone(),
                            mode: "D".to_string(),
                            data: vec!["S".to_string()],
                        },
                    ],
                    None => mk("D", vec!["F".to_string()]),
                }
            }
            "D" => {
                self.sasl_sessions.remove(&client);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    // Authority side of the IRCv3 account-registration relay: create the account
    // (same store as classic NickServ REGISTER) and answer the requesting ircd.
    fn account_request(&mut self, reqid: String, kind: String, account: String, p2: String, p3: String) -> Vec<NetAction> {
        if !kind.eq_ignore_ascii_case("REGISTER") {
            return Vec::new(); // VERIFY / RESEND / STATUS: later
        }
        let email = if p2.is_empty() || p2 == "*" { None } else { Some(p2) };
        let (status, code, message) = match self.db.register(&account, &p3, email) {
            Ok(()) => ("success", "*", "Account registered."),
            Err(RegError::Exists) => ("error", "ACCOUNT_EXISTS", "That account name is already registered."),
            Err(RegError::Internal) => ("error", "TEMPORARILY_UNAVAILABLE", "Registration is unavailable, try again later."),
        };
        vec![NetAction::AccountResponse {
            reqid,
            kind,
            account,
            status: status.to_string(),
            code: code.to_string(),
            message: message.to_string(),
        }]
    }

    // Route a PRIVMSG addressed to a service (by uid or nick) into that service,
    // handing it the sender's resolved nick and the account store.
    fn dispatch(&mut self, from: &str, to: &str, text: &str) -> Vec<NetAction> {
        let nick = self.network.nick_of(from).unwrap_or(from).to_string();
        let mut ctx = ServiceCtx::default();
        let sender = Sender { uid: from, nick: &nick };
        let Self { services, db, .. } = self;
        for svc in services.iter_mut() {
            if to.eq_ignore_ascii_case(svc.uid()) || to.eq_ignore_ascii_case(svc.nick()) {
                let args: Vec<&str> = text.split_whitespace().collect();
                svc.on_command(&sender, &args, &mut ctx, db);
                break;
            }
        }
        ctx.actions
    }
}

// Decode a SASL PLAIN payload (authzid \0 authcid \0 passwd) and authenticate
// it, returning the canonical account name on success.
fn login_plain(b64: &str, db: &Db) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let raw = STANDARD.decode(b64).ok()?;
    let parts: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authcid = std::str::from_utf8(parts[1]).ok()?;
    let passwd = std::str::from_utf8(parts[2]).ok()?;
    db.authenticate(authcid, passwd).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::nickserv::NickServ;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    fn plain(authzid: &[u8], authcid: &[u8], passwd: &[u8]) -> String {
        let mut payload = Vec::new();
        payload.extend_from_slice(authzid);
        payload.push(0);
        payload.extend_from_slice(authcid);
        payload.push(0);
        payload.extend_from_slice(passwd);
        STANDARD.encode(payload)
    }

    fn engine_with(name: &str, account: &str, password: &str) -> Engine {
        let path = std::env::temp_dir().join(format!("fedserv-sasl-{name}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path);
        assert!(db.register(account, password, None).is_ok());
        Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".to_string() })], db)
    }

    fn sasl(engine: &mut Engine, mode: &str, chunk: &str) -> Vec<NetAction> {
        engine.handle(NetEvent::Sasl {
            client: "000AAAAAB".to_string(),
            agent: "*".to_string(),
            mode: mode.to_string(),
            data: vec![chunk.to_string()],
        })
    }

    fn is_success(out: &[NetAction]) -> bool {
        out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "foo"))
            && out.iter().any(|a| matches!(a, NetAction::Sasl { mode, data, .. } if mode == "D" && data.as_slice() == ["S"]))
    }

    // Single-chunk PLAIN (short response) logs in.
    #[test]
    fn plain_single_chunk() {
        let mut e = engine_with("single", "foo", "sesame");
        sasl(&mut e, "S", "PLAIN");
        let out = sasl(&mut e, "C", &plain(b"", b"foo", b"sesame"));
        assert!(is_success(&out), "{out:?}");
    }

    // A response that is not a multiple of 400 splits into 400 + remainder.
    #[test]
    fn plain_chunked_412() {
        let pw = "bar".repeat(100);
        let mut e = engine_with("c412", "foo", &pw);
        let auth = plain(b"foo", b"foo", pw.as_bytes());
        assert_eq!(auth.len(), 412);
        sasl(&mut e, "S", "PLAIN");
        assert!(sasl(&mut e, "C", &auth[0..400]).is_empty());
        let out = sasl(&mut e, "C", &auth[400..]);
        assert!(is_success(&out), "{out:?}");
    }

    // A response that is an exact multiple of 400 ends with a trailing "+".
    #[test]
    fn plain_chunked_800() {
        let pw = "x".repeat(592);
        let mut e = engine_with("c800", "foo", &pw);
        let auth = plain(b"foo", b"foo", pw.as_bytes());
        assert_eq!(auth.len(), 800);
        sasl(&mut e, "S", "PLAIN");
        assert!(sasl(&mut e, "C", &auth[0..400]).is_empty());
        assert!(sasl(&mut e, "C", &auth[400..800]).is_empty());
        let out = sasl(&mut e, "C", "+");
        assert!(is_success(&out), "{out:?}");
    }

    // Wrong password fails.
    #[test]
    fn plain_bad_password() {
        let mut e = engine_with("bad", "foo", "sesame");
        sasl(&mut e, "S", "PLAIN");
        let out = sasl(&mut e, "C", &plain(b"", b"foo", b"wrong"));
        assert!(out.iter().any(|a| matches!(a, NetAction::Sasl { mode, data, .. } if mode == "D" && data.as_slice() == ["F"])), "{out:?}");
    }
}
