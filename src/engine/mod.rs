pub mod db;
pub mod scram;
pub mod service;
pub mod state;

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::proto::{NetAction, NetEvent};
use db::{Db, RegError};
use scram::Verifier;
use service::{Sender, Service, ServiceCtx};
use state::Network;

// SASL mechanisms we offer, strongest first. Advertised to the uplink as the
// `sasl=` capability value (IRCv3 SASL 3.2 mechanism list) and the set we accept.
const SASL_MECHS: &str = "SCRAM-SHA-512,SCRAM-SHA-256,PLAIN";

// A client's base64 response is split into chunks of this length; a chunk
// shorter than this (or a lone "+") marks the end of the response (SASL 3.1).
const MAX_AUTHENTICATE: usize = 400;

// Upper bound on a reassembled response, to cap a pre-auth client's buffer.
const MAX_SASL_RESPONSE: usize = 8 * 1024;

// A client's in-progress SASL exchange.
enum SaslSession {
    // PLAIN: the base64 response reassembled from the uplink's chunks.
    Plain { response: String },
    // SCRAM: which hash, and where we are in the challenge/response.
    Scram { hash: scram::Hash, step: ScramStep },
}

// The SCRAM state advances client-first -> client-final -> ack.
enum ScramStep {
    ClientFirst,
    ClientFinal {
        account: String,
        verifier: Verifier,
        client_first_bare: String,
        server_first: String,
        gs2_header: String,
        nonce: String,
    },
    Ack {
        account: String,
    },
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

    // SASL agent side of the exchange the ircd relays to us (modes H/S/C/D), per
    // IRCv3 SASL 3.2. On success we set the client's account (drives 900) then
    // report success (drives 903); a bad credential or unknown mechanism reports
    // failure (drives 904). PLAIN and SCRAM-SHA-256/512 are supported.
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
                    self.sasl_sessions.insert(client.clone(), SaslSession::Plain { response: String::new() });
                    mk("C", vec!["+".to_string()]) // empty challenge -> client sends the payload
                }
                Some(mech) if scram::Hash::from_mech(mech).is_some() => {
                    let hash = scram::Hash::from_mech(mech).unwrap();
                    self.sasl_sessions.insert(client.clone(), SaslSession::Scram { hash, step: ScramStep::ClientFirst });
                    mk("C", vec!["+".to_string()]) // client sends client-first next
                }
                _ => mk("D", vec!["F".to_string()]), // unsupported mechanism
            },
            "C" => {
                let chunk = data.first().map(String::as_str).unwrap_or("");
                match self.sasl_sessions.remove(&client) {
                    None => mk("D", vec!["F".to_string()]),
                    Some(SaslSession::Plain { mut response }) => {
                        // Reassemble the base64 response: append each chunk until
                        // one is shorter than a full chunk (or a lone "+").
                        if chunk != "+" {
                            response.push_str(chunk);
                        }
                        if response.len() > MAX_SASL_RESPONSE {
                            return mk("D", vec!["F".to_string()]);
                        }
                        if chunk.len() >= MAX_AUTHENTICATE {
                            self.sasl_sessions.insert(client.clone(), SaslSession::Plain { response });
                            return Vec::new(); // more chunks still to come
                        }
                        match login_plain(&response, &self.db) {
                            Some(account) => sasl_success(&agent, &client, account),
                            None => mk("D", vec!["F".to_string()]),
                        }
                    }
                    Some(SaslSession::Scram { hash, step }) => self.sasl_scram(&agent, &client, hash, step, chunk),
                }
            }
            "D" => {
                self.sasl_sessions.remove(&client);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    // One SCRAM step. The client's messages arrive base64-encoded in the C data
    // (except the final empty "+" acknowledgement).
    fn sasl_scram(&mut self, agent: &str, client: &str, hash: scram::Hash, step: ScramStep, chunk: &str) -> Vec<NetAction> {
        let fail = || vec![NetAction::Sasl {
            agent: agent.to_string(), client: client.to_string(), mode: "D".to_string(), data: vec!["F".to_string()],
        }];
        let challenge = |msg: String| vec![NetAction::Sasl {
            agent: agent.to_string(), client: client.to_string(), mode: "C".to_string(), data: vec![STANDARD.encode(msg)],
        }];
        let decode = |chunk: &str| STANDARD.decode(chunk).ok().and_then(|b| String::from_utf8(b).ok());

        match step {
            ScramStep::ClientFirst => {
                let Some(cf) = decode(chunk).as_deref().and_then(scram::parse_client_first) else {
                    return fail();
                };
                let Some((account, verifier)) = self.db.scram_lookup(&cf.username, hash.mech()) else {
                    return fail();
                };
                let (account, Some(verifier)) = (account.to_string(), scram::parse_verifier(verifier)) else {
                    return fail();
                };
                let (server_first, nonce) = scram::server_first(&cf.cnonce, &verifier);
                let out = challenge(server_first.clone());
                self.sasl_sessions.insert(client.to_string(), SaslSession::Scram {
                    hash,
                    step: ScramStep::ClientFinal {
                        account,
                        verifier,
                        client_first_bare: cf.client_first_bare,
                        server_first,
                        gs2_header: cf.gs2_header,
                        nonce,
                    },
                });
                out
            }
            ScramStep::ClientFinal { account, verifier, client_first_bare, server_first, gs2_header, nonce } => {
                let Some(msg) = decode(chunk) else { return fail() };
                match scram::verify_final(hash, &verifier, &client_first_bare, &server_first, &gs2_header, &nonce, &msg) {
                    Some(server_final) => {
                        let out = challenge(server_final);
                        self.sasl_sessions.insert(client.to_string(), SaslSession::Scram { hash, step: ScramStep::Ack { account } });
                        out
                    }
                    None => fail(),
                }
            }
            // Client acknowledged our server-final ("+"); apply the login.
            ScramStep::Ack { account } => sasl_success(agent, client, account),
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
    let raw = STANDARD.decode(b64).ok()?;
    let parts: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authcid = std::str::from_utf8(parts[1]).ok()?;
    let passwd = std::str::from_utf8(parts[2]).ok()?;
    db.authenticate(authcid, passwd).map(str::to_string)
}

// The two actions that complete any mechanism: set the account (drives 900),
// then report SASL success (drives 903).
fn sasl_success(agent: &str, client: &str, account: String) -> Vec<NetAction> {
    vec![
        NetAction::Metadata { target: client.to_string(), key: "accountname".to_string(), value: account },
        NetAction::Sasl { agent: agent.to_string(), client: client.to_string(), mode: "D".to_string(), data: vec!["S".to_string()] },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::nickserv::NickServ;

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
        db.scram_iterations = 4096; // keep the debug-build verifier cheap in tests
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

    // The single reply datum of a C/D action (SCRAM messages are single-chunk).
    fn datum(out: &[NetAction]) -> (&str, &str) {
        match out.first() {
            Some(NetAction::Sasl { mode, data, .. }) => (mode.as_str(), data[0].as_str()),
            other => panic!("expected a SASL action, got {other:?}"),
        }
    }

    // Drive a full SCRAM exchange through the engine, playing the client, and
    // return the final actions. `login_pw` may differ from the registered one.
    fn scram_exchange(mech: &str, login_pw: &str) -> Vec<NetAction> {
        use scram::Hash;
        let hash = Hash::from_mech(mech).unwrap();
        let mut e = engine_with("scram", "foo", "sesame");

        assert_eq!(datum(&sasl(&mut e, "S", mech)), ("C", "+"));

        let client_first_bare = "n=foo,r=cnonce";
        let client_first = format!("n,,{client_first_bare}");
        let first_out = sasl(&mut e, "C", &STANDARD.encode(&client_first));
        let (mode, b64) = datum(&first_out);
        assert_eq!(mode, "C");
        let server_first = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();

        // Reconstruct salt/iterations from server-first and forge the proof.
        let salt = STANDARD.decode(server_first.split(",s=").nth(1).unwrap().split(',').next().unwrap()).unwrap();
        let iters: u32 = server_first.rsplit(",i=").next().unwrap().parse().unwrap();
        let full_nonce = server_first.split("r=").nth(1).unwrap().split(',').next().unwrap();

        let salted = scram::hi(hash, login_pw.as_bytes(), &salt, iters);
        let client_key = scram::hmac(hash, &salted, b"Client Key");
        let stored_key = scram::h(hash, &client_key);
        let without_proof = format!("c=biws,r={full_nonce}");
        let auth = format!("{client_first_bare},{server_first},{without_proof}");
        let proof = scram::xor(&client_key, &scram::hmac(hash, &stored_key, auth.as_bytes()));
        let client_final = format!("{without_proof},p={}", STANDARD.encode(&proof));

        let final_out = sasl(&mut e, "C", &STANDARD.encode(&client_final));
        // On success the engine sends server-final (C v=...); the client then acks.
        match datum(&final_out) {
            ("C", _) => sasl(&mut e, "C", "+"),
            _ => final_out,
        }
    }

    #[test]
    fn scram_sha256_success() {
        assert!(is_success(&scram_exchange("SCRAM-SHA-256", "sesame")));
    }

    #[test]
    fn scram_sha512_success() {
        assert!(is_success(&scram_exchange("SCRAM-SHA-512", "sesame")));
    }

    #[test]
    fn scram_bad_password() {
        let out = scram_exchange("SCRAM-SHA-256", "millet");
        assert!(out.iter().any(|a| matches!(a, NetAction::Sasl { mode, data, .. } if mode == "D" && data.as_slice() == ["F"])), "{out:?}");
    }

    #[test]
    fn scram_unknown_user_fails() {
        let mut e = engine_with("scramnouser", "foo", "sesame");
        sasl(&mut e, "S", "SCRAM-SHA-256");
        let out = sasl(&mut e, "C", &STANDARD.encode("n,,n=ghost,r=cnonce"));
        assert_eq!(datum(&out), ("D", "F"));
    }
}
