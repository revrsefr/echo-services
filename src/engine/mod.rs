pub mod db;
pub mod scram;
pub mod service;
pub mod state;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::proto::{NetAction, NetEvent, RegReply};
use db::{Db, LogEntry, RegError};
use scram::Verifier;
use service::{Sender, Service, ServiceCtx};
use state::Network;

// SASL mechanisms we offer, strongest first. Advertised to the uplink as the
// `sasl=` capability value (IRCv3 SASL 3.2 mechanism list) and the set we accept.
const SASL_MECHS: &str = "EXTERNAL,SCRAM-SHA-512,SCRAM-SHA-256,PLAIN";

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
    // EXTERNAL: the TLS cert fingerprints the ircd relayed for this client.
    External { fingerprints: Vec<String> },
}

// An in-progress exchange with its last-activity stamp, so abandoned sessions
// can be swept. The ircd does not always tell us a mid-SASL client vanished, so
// without this the uid-keyed map would grow without bound (a memory-exhaustion
// DoS: open a connection, send AUTHENTICATE, drop, repeat).
struct TimedSession {
    touched: Instant,
    session: SaslSession,
}

// How long an idle SASL exchange lives before it is swept. A real exchange
// completes in well under a second; each step refreshes the stamp.
const SASL_SESSION_TTL: Duration = Duration::from_secs(60);
// Hard ceiling on concurrent in-progress exchanges, bounding worst-case memory
// under a burst faster than the TTL.
const MAX_SASL_SESSIONS: usize = 4096;

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
    sasl_sessions: HashMap<String, TimedSession>, // client uid -> in-progress exchange
    reg_limiter: RegLimiter,
    chan_service: Option<String>, // uid to source channel modes from (ChanServ)
}

impl Engine {
    pub fn new(services: Vec<Box<dyn Service>>, db: Db) -> Self {
        let chan_service = services.iter().find(|s| s.manages_channels()).map(|s| s.uid().to_string());
        Self {
            services,
            network: Network::default(),
            db,
            sasl_sessions: HashMap::new(),
            reg_limiter: RegLimiter::new(),
            chan_service,
        }
    }

    // Cost of a fresh SCRAM verifier; read by the link layer for off-thread derivation.
    pub fn scram_iterations(&self) -> u32 {
        self.db.scram_iterations
    }

    // Gossip pass-throughs to the account store, used by the replication layer.
    pub fn gossip_digest(&self) -> HashMap<String, u64> {
        self.db.version_vector()
    }

    pub fn gossip_missing(&self, peer: &HashMap<String, u64>) -> Vec<LogEntry> {
        self.db.missing_for(peer)
    }

    pub fn gossip_ingest(&mut self, entry: LogEntry) -> std::io::Result<()> {
        self.db.ingest(entry)
    }

    // Compact the log if it has grown past the live account count. Returns
    // whether it rewrote anything.
    pub fn maybe_compact(&mut self) -> std::io::Result<bool> {
        if self.db.should_compact() {
            self.db.compact()?;
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(test)]
    pub(crate) fn test_register(&mut self, name: &str) {
        self.db.register(name, "pw", None).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn test_has_account(&self, name: &str) -> bool {
        self.db.exists(name)
    }

    // Insert or refresh a client's in-progress SASL session, stamped now.
    fn stash_sasl(&mut self, client: String, session: SaslSession) {
        self.sasl_sessions.insert(client, TimedSession { touched: Instant::now(), session });
    }

    // Evict exchanges idle past the TTL. Run before starting a new one so a
    // dropped-mid-auth client the ircd never reported cannot pile up.
    fn sweep_sasl(&mut self) {
        let now = Instant::now();
        self.sasl_sessions.retain(|_, t| now.duration_since(t.touched) < SASL_SESSION_TTL);
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
        let out = match event {
            NetEvent::Ping { token, from } => vec![NetAction::Pong { token, from }],
            NetEvent::UserConnect { uid, nick } => {
                self.network.user_connect(uid, nick);
                Vec::new()
            }
            NetEvent::NickChange { uid, nick } => {
                self.network.user_nick_change(&uid, nick);
                Vec::new()
            }
            // A registered channel just (re)appeared: re-assert +r. Fires on
            // creation and on the uplink burst, so registered channels regain the
            // mode after emptying, and after a services relink.
            NetEvent::ChannelCreate { channel } => {
                let from = self.chan_service.clone().unwrap_or_default();
                match self.db.channel(&channel) {
                    Some(info) => vec![NetAction::ChannelMode { from, channel, modes: info.lock_modes() }],
                    None => Vec::new(),
                }
            }
            // Enforce the mode lock: revert any change that broke it.
            NetEvent::ChannelModeChange { channel, modes } => {
                let from = self.chan_service.clone().unwrap_or_default();
                match self.db.channel(&channel).and_then(|info| info.enforce(&modes)) {
                    Some(revert) => vec![NetAction::ChannelMode { from, channel, modes: revert }],
                    None => Vec::new(),
                }
            }
            // Auto-op the founder when they join their registered channel.
            NetEvent::Join { uid, channel } => {
                let founder = self.db.channel(&channel).map(|c| c.founder.clone());
                let account = self.network.account_of(&uid).map(str::to_string);
                match (founder, account) {
                    (Some(f), Some(a)) if f == a => {
                        let from = self.chan_service.clone().unwrap_or_default();
                        vec![NetAction::ChannelMode { from, channel, modes: format!("+o {uid}") }]
                    }
                    _ => Vec::new(),
                }
            }
            NetEvent::Quit { uid } => {
                self.network.user_quit(&uid);
                self.sasl_sessions.remove(&uid); // drop any half-finished exchange
                Vec::new()
            }
            NetEvent::Privmsg { from, to, text } => self.dispatch(&from, &to, &text),
            NetEvent::AccountRequest { reqid, kind, account, p2, p3, .. } => {
                self.account_request(reqid, kind, account, p2, p3)
            }
            NetEvent::Sasl { client, mode, data, .. } => self.sasl(client, mode, data),
            _ => Vec::new(),
        };
        self.track_accounts(&out);
        out
    }

    // Keep per-user login state in step with the accountname metadata we send:
    // a non-empty value (SASL/IDENTIFY/REGISTER) logs the uid in, an empty one
    // (LOGOUT) logs it out. Server-global metadata ("*") is not a login.
    fn track_accounts(&mut self, actions: &[NetAction]) {
        for action in actions {
            if let NetAction::Metadata { target, key, value } = action {
                if key == "accountname" && target != "*" {
                    if value.is_empty() {
                        self.network.clear_account(target);
                    } else {
                        self.network.set_account(target, value);
                    }
                }
            }
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
            "S" => {
                self.sweep_sasl();
                if self.sasl_sessions.len() >= MAX_SASL_SESSIONS {
                    return mk("D", vec!["F".to_string()]); // too many in flight
                }
                match data.first().map(String::as_str) {
                    Some("PLAIN") => {
                        self.stash_sasl(client.clone(), SaslSession::Plain { response: String::new() });
                        mk("C", vec!["+".to_string()]) // empty challenge -> client sends the payload
                    }
                    Some("EXTERNAL") => {
                        // The ircd appends the client's TLS cert fingerprints after the mechanism.
                        let fingerprints = data.iter().skip(1).map(|f| f.to_ascii_lowercase()).collect();
                        self.stash_sasl(client.clone(), SaslSession::External { fingerprints });
                        mk("C", vec!["+".to_string()]) // client sends its authzid (or "+")
                    }
                    Some(mech) if scram::Hash::from_mech(mech).is_some() => {
                        let hash = scram::Hash::from_mech(mech).unwrap();
                        self.stash_sasl(client.clone(), SaslSession::Scram { hash, step: ScramStep::ClientFirst });
                        mk("C", vec!["+".to_string()]) // client sends client-first next
                    }
                    _ => mk("D", vec!["F".to_string()]), // unsupported mechanism
                }
            }
            "C" => {
                let chunk = data.first().map(String::as_str).unwrap_or("");
                match self.sasl_sessions.remove(&client).map(|t| t.session) {
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
                            self.stash_sasl(client.clone(), SaslSession::Plain { response });
                            return Vec::new(); // more chunks still to come
                        }
                        match login_plain(&response, &self.db) {
                            Some(account) => sasl_success(&agent, &client, account),
                            None => mk("D", vec!["F".to_string()]),
                        }
                    }
                    Some(SaslSession::Scram { hash, step }) => self.sasl_scram(&agent, &client, hash, step, chunk),
                    Some(SaslSession::External { fingerprints }) => self.sasl_external(&agent, &client, fingerprints, chunk),
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
                self.stash_sasl(client.to_string(), SaslSession::Scram {
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
                        self.stash_sasl(client.to_string(), SaslSession::Scram { hash, step: ScramStep::Ack { account } });
                        out
                    }
                    None => fail(),
                }
            }
            // Client acknowledged our server-final ("+"); apply the login.
            ScramStep::Ack { account } => sasl_success(agent, client, account),
        }
    }

    // SASL EXTERNAL: the credential is the client's TLS cert fingerprint, which
    // the ircd handed us in the S message (already validated at the handshake).
    // Match it to an account; an authzid, if given, must name that same account.
    fn sasl_external(&self, agent: &str, client: &str, fingerprints: Vec<String>, chunk: &str) -> Vec<NetAction> {
        let authzid = if chunk == "+" || chunk.is_empty() {
            String::new()
        } else {
            match STANDARD.decode(chunk).ok().and_then(|b| String::from_utf8(b).ok()) {
                Some(a) => a,
                None => return sasl_fail(agent, client),
            }
        };
        match fingerprints.iter().find_map(|fp| self.db.certfp_owner(fp)) {
            Some(account) if authzid.is_empty() || authzid.eq_ignore_ascii_case(account) => {
                let account = account.to_string();
                sasl_success(agent, client, account)
            }
            _ => sasl_fail(agent, client),
        }
    }

    // Authority side of the IRCv3 account-registration relay. Hands the work to
    // the link layer (which derives the password off-thread) via DeferRegister.
    fn account_request(&mut self, reqid: String, kind: String, account: String, p2: String, p3: String) -> Vec<NetAction> {
        if !kind.eq_ignore_ascii_case("REGISTER") {
            return Vec::new(); // VERIFY / RESEND / STATUS: later
        }
        let email = if p2.is_empty() || p2 == "*" { None } else { Some(p2) };
        vec![NetAction::DeferRegister { account, password: p3, email, reply: RegReply::Relay { reqid, kind } }]
    }

    // Cheap gate run before the expensive derivation: reject an already-taken name
    // outright, and rate-limit the rest so a REGISTER flood can't pin CPU. Returns
    // the rejection response if refused, or None to proceed (spending a token).
    pub fn pre_register_check(&mut self, account: &str, reply: &RegReply) -> Option<Vec<NetAction>> {
        if self.db.exists(account) {
            return Some(reg_reply(reply, RegOutcome::Exists, account));
        }
        if !self.reg_limiter.allow() {
            return Some(reg_reply(reply, RegOutcome::RateLimited, account));
        }
        None
    }

    // Commit credentials the link layer derived off-thread, then answer `reply`.
    pub fn complete_register(&mut self, account: &str, creds: Option<db::Credentials>, email: Option<String>, reply: RegReply) -> Vec<NetAction> {
        let Some(creds) = creds else {
            return reg_reply(&reply, RegOutcome::Internal, account);
        };
        let outcome = match self.db.register_prepared(account, creds, email) {
            Ok(()) => RegOutcome::Ok,
            Err(RegError::Exists) => RegOutcome::Exists,
            Err(RegError::Internal) => RegOutcome::Internal,
        };
        let out = reg_reply(&reply, outcome, account);
        self.track_accounts(&out);
        out
    }

    // Route a PRIVMSG addressed to a service (by uid or nick) into that service,
    // handing it the sender's resolved nick, login state, and the account store.
    fn dispatch(&mut self, from: &str, to: &str, text: &str) -> Vec<NetAction> {
        let nick = self.network.nick_of(from).unwrap_or(from).to_string();
        let account = self.network.account_of(from).map(str::to_string);
        let mut ctx = ServiceCtx::default();
        let sender = Sender { uid: from, nick: &nick, account: account.as_deref() };
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

// Report SASL failure to the ircd (drives 904).
fn sasl_fail(agent: &str, client: &str) -> Vec<NetAction> {
    vec![NetAction::Sasl { agent: agent.to_string(), client: client.to_string(), mode: "D".to_string(), data: vec!["F".to_string()] }]
}

// The two actions that complete any mechanism: set the account (drives 900),
// then report SASL success (drives 903).
fn sasl_success(agent: &str, client: &str, account: String) -> Vec<NetAction> {
    vec![
        NetAction::Metadata { target: client.to_string(), key: "accountname".to_string(), value: account },
        NetAction::Sasl { agent: agent.to_string(), client: client.to_string(), mode: "D".to_string(), data: vec!["S".to_string()] },
    ]
}

// Outcome of a registration attempt, rendered to the right wire response below.
enum RegOutcome {
    Ok,
    Exists,
    RateLimited,
    Internal,
}

// Render a registration outcome for whichever origin asked (relay or NickServ),
// so both the pre-check rejection and the post-derivation result share one place.
fn reg_reply(reply: &RegReply, outcome: RegOutcome, account: &str) -> Vec<NetAction> {
    match reply {
        RegReply::Relay { reqid, kind } => {
            let (status, code, message) = match outcome {
                RegOutcome::Ok => ("success", "*", "Account registered."),
                RegOutcome::Exists => ("error", "ACCOUNT_EXISTS", "That account name is already registered."),
                RegOutcome::RateLimited => ("error", "TEMPORARILY_UNAVAILABLE", "Too many registrations, please wait a moment."),
                RegOutcome::Internal => ("error", "TEMPORARILY_UNAVAILABLE", "Registration is unavailable, try again later."),
            };
            vec![NetAction::AccountResponse {
                reqid: reqid.clone(),
                kind: kind.clone(),
                account: account.to_string(),
                status: status.to_string(),
                code: code.to_string(),
                message: message.to_string(),
            }]
        }
        RegReply::NickServ { agent, uid, nick } => {
            let notice = |text: String| NetAction::Notice { from: agent.clone(), to: uid.clone(), text };
            match outcome {
                RegOutcome::Ok => vec![
                    // Registering identifies you to the nick right away (drives 900).
                    NetAction::Metadata { target: uid.clone(), key: "accountname".to_string(), value: nick.clone() },
                    notice(format!("Your nick \x02{nick}\x02 is now registered and you're logged in. Welcome!")),
                ],
                RegOutcome::Exists => vec![notice(format!("\x02{nick}\x02 is already registered. If it's yours, use \x02IDENTIFY <password>\x02."))],
                RegOutcome::RateLimited => vec![notice("Registrations are busy right now. Please try again in a moment.".to_string())],
                RegOutcome::Internal => vec![notice("Sorry, that didn't work. Please try again in a moment.".to_string())],
            }
        }
    }
}

// Token bucket bounding how often the expensive registration derivation may run,
// so a REGISTER flood degrades to a trickle instead of pinning a core. Global on
// purpose: it caps total work regardless of which user or server relayed it.
struct RegLimiter {
    tokens: f64,
    last: Instant,
}

const REG_BURST: f64 = 8.0; // registrations allowed back-to-back from a full bucket
const REG_REFILL_PER_SEC: f64 = 0.5; // steady-state: one every two seconds

impl RegLimiter {
    fn new() -> Self {
        Self { tokens: REG_BURST, last: Instant::now() }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * REG_REFILL_PER_SEC).min(REG_BURST);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
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
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096; // keep the debug-build verifier cheap in tests
        assert!(db.register(account, password, None).is_ok());
        Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".to_string(), guest_nick: "Guest".to_string(), guest_seq: 12345 })], db)
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

    // Start a SASL exchange for an arbitrary client uid.
    fn start(e: &mut Engine, client: &str) -> Vec<NetAction> {
        e.handle(NetEvent::Sasl { client: client.into(), agent: "*".into(), mode: "S".into(), data: vec!["PLAIN".into()] })
    }

    // A client that starts SASL then vanishes must not linger forever.
    #[test]
    fn abandoned_session_swept_after_ttl() {
        let mut e = engine_with("swept", "foo", "sesame");
        start(&mut e, "AAA");
        assert!(e.sasl_sessions.contains_key("AAA"));
        // Backdate it past the TTL; guarded so a just-booted monotonic clock can't panic.
        if let Some(stale) = Instant::now().checked_sub(SASL_SESSION_TTL + Duration::from_secs(1)) {
            e.sasl_sessions.get_mut("AAA").unwrap().touched = stale;
            start(&mut e, "BBB"); // any new start sweeps first
            assert!(!e.sasl_sessions.contains_key("AAA"), "stale exchange should be swept");
            assert!(e.sasl_sessions.contains_key("BBB"));
        }
    }

    // The map is hard-capped so a flood of half-open exchanges can't exhaust memory.
    #[test]
    fn concurrent_sessions_capped() {
        let mut e = engine_with("capped", "foo", "sesame");
        for i in 0..MAX_SASL_SESSIONS {
            assert_eq!(datum(&start(&mut e, &format!("u{i}"))), ("C", "+"));
        }
        assert_eq!(datum(&start(&mut e, "over")), ("D", "F"), "over-cap start must be refused");
    }

    // A QUIT drops any half-finished exchange for that uid.
    #[test]
    fn session_cleared_on_quit() {
        let mut e = engine_with("quit", "foo", "sesame");
        start(&mut e, "ZZZ");
        assert!(e.sasl_sessions.contains_key("ZZZ"));
        e.handle(NetEvent::Quit { uid: "ZZZ".into() });
        assert!(!e.sasl_sessions.contains_key("ZZZ"), "quit should drop the exchange");
    }

    // Drive a SASL step with a multi-field data vector (EXTERNAL carries the
    // mechanism plus the ircd-supplied fingerprints in one message).
    fn sasl_multi(e: &mut Engine, mode: &str, data: &[&str]) -> Vec<NetAction> {
        e.handle(NetEvent::Sasl {
            client: "000AAAAAB".into(),
            agent: "*".into(),
            mode: mode.into(),
            data: data.iter().map(|s| s.to_string()).collect(),
        })
    }

    // EXTERNAL with a registered fingerprint logs in; matching is case-insensitive.
    #[test]
    fn external_success_with_registered_cert() {
        let mut e = engine_with("extok", "foo", "sesame");
        e.db.certfp_add("foo", "aabbccddeeff00112233445566778899").unwrap();
        assert_eq!(datum(&sasl_multi(&mut e, "S", &["EXTERNAL", "AABBCCDDEEFF00112233445566778899"])), ("C", "+"));
        assert!(is_success(&sasl(&mut e, "C", "+")), "empty authzid should log in");
    }

    // An authzid, if sent, must name the cert's own account.
    #[test]
    fn external_authzid_must_match() {
        let mut e = engine_with("extaz", "foo", "sesame");
        e.db.certfp_add("foo", "aabbccddeeff00112233445566778899").unwrap();
        sasl_multi(&mut e, "S", &["EXTERNAL", "aabbccddeeff00112233445566778899"]);
        assert!(is_success(&sasl(&mut e, "C", &STANDARD.encode("foo"))), "matching authzid ok");

        let mut e = engine_with("extaz2", "foo", "sesame");
        e.db.certfp_add("foo", "aabbccddeeff00112233445566778899").unwrap();
        sasl_multi(&mut e, "S", &["EXTERNAL", "aabbccddeeff00112233445566778899"]);
        assert_eq!(datum(&sasl(&mut e, "C", &STANDARD.encode("bar"))), ("D", "F"), "foreign authzid rejected");
    }

    // An unknown fingerprint, or no fingerprint at all (plaintext client), fails.
    #[test]
    fn external_without_registered_cert_fails() {
        let mut e = engine_with("extno", "foo", "sesame");
        sasl_multi(&mut e, "S", &["EXTERNAL", "0011223344556677889900aabbccddee"]);
        assert_eq!(datum(&sasl(&mut e, "C", "+")), ("D", "F"), "unknown fp rejected");

        sasl_multi(&mut e, "S", &["EXTERNAL"]); // no fingerprint supplied
        assert_eq!(datum(&sasl(&mut e, "C", "+")), ("D", "F"), "no cert rejected");
    }

    // End to end: enrol a cert with NickServ CERT ADD, then log in with EXTERNAL.
    #[test]
    fn nickserv_cert_add_enables_external() {
        let mut e = engine_with("nscert", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into() });
        let fp = "aabbccddeeff00112233445566778899";

        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(),
            to: "42SAAAAAA".into(),
            text: format!("CERT ADD sesame {fp}"),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Added"))), "{out:?}");

        sasl_multi(&mut e, "S", &["EXTERNAL", fp]);
        assert!(is_success(&sasl(&mut e, "C", "+")), "external should work after CERT ADD");
    }

    // A wrong password can't enrol a cert, and a fingerprint is one account only.
    #[test]
    fn cert_add_is_guarded_and_unique() {
        let mut e = engine_with("certguard", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into() });
        let fp = "aabbccddeeff00112233445566778899";

        let bad = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(),
            to: "42SAAAAAA".into(),
            text: format!("CERT ADD wrongpw {fp}"),
        });
        assert!(bad.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Invalid password"))), "{bad:?}");
        assert!(e.db.certfp_owner(fp).is_none(), "bad password must not enrol");

        e.db.certfp_add("foo", fp).unwrap();
        e.db.register("bar", "sesame", None).unwrap();
        assert!(matches!(e.db.certfp_add("bar", fp), Err(db::CertError::InUse)), "a fingerprint maps to one account");
    }

    // IDENTIFY logs in, LOGOUT clears the accountname (ircd emits RPL_LOGGEDOUT).
    #[test]
    fn nickserv_logout_clears_account() {
        let mut e = engine_with("nslogout", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into() });

        let login = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(),
            to: "42SAAAAAA".into(),
            text: "IDENTIFY sesame".into(),
        });
        assert!(login.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "foo")), "{login:?}");

        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(),
            to: "42SAAAAAA".into(),
            text: "LOGOUT".into(),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value.is_empty())), "logout clears accountname: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAB" && nick == "Guest12345")), "logout renames to guest nick: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("logged out"))), "{out:?}");
    }

    fn logout(e: &mut Engine, uid: &str) -> Vec<NetAction> {
        e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "LOGOUT".into() })
    }

    // LOGOUT while not identified must not rename you or clear anything.
    #[test]
    fn logout_without_login_is_noop() {
        let mut e = engine_with("nologin", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "someone".into() });
        let out = logout(&mut e, "000AAAAAB");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("not logged in"))), "{out:?}");
        assert!(!out.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "must not rename when not logged in: {out:?}");
    }

    // Regression: a second LOGOUT is a no-op, not another guest rename (the churn
    // where Guest33294 -> LOGOUT -> Guest33295).
    #[test]
    fn logout_twice_renames_only_once() {
        let mut e = engine_with("twice", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let first = logout(&mut e, "000AAAAAB");
        assert!(first.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "first logout renames: {first:?}");

        let second = logout(&mut e, "000AAAAAB");
        assert!(second.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("not logged in"))), "{second:?}");
        assert!(!second.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "second logout must not rename again: {second:?}");
    }

    // A SASL login (before the user is even bursted) is remembered, so a later
    // LOGOUT from that uid is recognised as logged in.
    #[test]
    fn sasl_login_is_tracked_for_logout() {
        let mut e = engine_with("sasllogout", "foo", "sesame");
        sasl(&mut e, "S", "PLAIN");
        let ok = sasl(&mut e, "C", &plain(b"", b"foo", b"sesame"));
        assert!(is_success(&ok), "{ok:?}");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into() });

        let out = logout(&mut e, "000AAAAAB");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "sasl-authed user can log out: {out:?}");
    }

    // Regression: repeated IDENTIFY while already identified must not re-fire the
    // login (the 900 loop when the command is spammed).
    #[test]
    fn identify_twice_does_not_relogin() {
        let mut e = engine_with("reident", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into() });
        let ident = |e: &mut Engine| e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into(),
        });

        let first = ident(&mut e);
        assert!(first.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "foo")), "first identify logs in: {first:?}");

        let second = ident(&mut e);
        assert!(!second.iter().any(|a| matches!(a, NetAction::Metadata { key, .. } if key == "accountname")), "second identify must not re-login: {second:?}");
        assert!(second.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("already identified"))), "{second:?}");
    }

    // The event log is the source of truth: state survives a reopen, rebuilt by
    // folding the log (with its origin/seq metadata) rather than a snapshot.
    #[test]
    fn account_store_survives_reopen() {
        let path = std::env::temp_dir().join("fedserv-reopen.jsonl");
        let _ = std::fs::remove_file(&path);
        {
            let mut db = Db::open(&path, "n1");
            db.scram_iterations = 4096;
            db.register("foo", "sesame", None).unwrap();
            db.certfp_add("foo", "aabbccddeeff00112233445566778899").unwrap();
        }
        let db = Db::open(&path, "n1");
        assert_eq!(db.certfps("foo").len(), 1, "cert replayed from log");
        assert!(db.authenticate("foo", "sesame").is_some(), "account replayed from log");
    }

    // Regression: after a nick change (e.g. a guest rename, then back to your
    // real nick), IDENTIFY must authenticate the CURRENT nick, not the one held
    // at burst time — otherwise you log into the wrong account.
    #[test]
    fn identify_uses_current_nick_after_rename() {
        let mut e = engine_with("renameident", "realnick", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "Guest99999".into() });
        e.handle(NetEvent::NickChange { uid: "000AAAAAB".into(), nick: "realnick".into() });
        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into(),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "realnick")), "must log into the current nick's account: {out:?}");
    }

    // ChanServ: registration needs identification, INFO shows the founder, and
    // only the founder can drop.
    #[test]
    fn chanserv_register_info_drop() {
        use crate::services::chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-chanserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);

        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        let notice = |out: &[NetAction], needle: &str| {
            out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)))
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into() });

        // Not identified yet: refused.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "REGISTER #room"), "logged in"));

        // Identify, then register: sets +r on the channel.
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let out = to_cs(&mut e, "000AAAAAB", "REGISTER #room");
        assert!(notice(&out, "now registered"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "+r")), "register sets +r: {out:?}");
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "INFO #room"), "alice"));

        // Founder sets a mode lock: it applies immediately and shows on view.
        let out = to_cs(&mut e, "000AAAAAB", "MLOCK #room +nt-s");
        assert!(notice(&out, "updated"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "+rnt-s")), "mlock applied: {out:?}");
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "MLOCK #room"), "+nt-s"));

        // A different, unidentified user cannot set the lock or drop it.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into() });
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "MLOCK #room +i"), "founder"));
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "DROP #room"), "founder"));

        // The founder can, which also clears +r.
        let out = to_cs(&mut e, "000AAAAAB", "DROP #room");
        assert!(notice(&out, "dropped"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "-r")), "drop clears +r: {out:?}");
    }

    // A registered channel (re)appearing re-asserts +r; an unregistered one does not.
    #[test]
    fn channel_create_reasserts_registered_mode() {
        let path = std::env::temp_dir().join("fedserv-chancreate.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register_channel("#reg", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);

        let out = e.handle(NetEvent::ChannelCreate { channel: "#reg".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#reg" && modes == "+r")), "registered channel regains +r: {out:?}");

        let out = e.handle(NetEvent::ChannelCreate { channel: "#other".into() });
        assert!(out.is_empty(), "unregistered channel is left alone: {out:?}");
    }

    // A channel's mode lock is applied on creation and enforced on violation.
    #[test]
    fn mode_lock_is_applied_and_enforced() {
        let path = std::env::temp_dir().join("fedserv-mlock-engine.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register_channel("#lk", "alice").unwrap();
        db.set_mlock("#lk", "nt", "s").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);

        // Creation applies the full lock.
        let out = e.handle(NetEvent::ChannelCreate { channel: "#lk".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#lk" && modes == "+rnt-s")), "{out:?}");

        // Setting a locked-off mode is reverted.
        let out = e.handle(NetEvent::ChannelModeChange { channel: "#lk".into(), modes: "+s".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#lk" && modes == "-s")), "{out:?}");

        // An unrelated mode change is left alone.
        assert!(e.handle(NetEvent::ChannelModeChange { channel: "#lk".into(), modes: "+m".into() }).is_empty());
    }

    // The founder is opped when they join their channel; others are not.
    #[test]
    fn founder_is_opped_on_join() {
        let path = std::env::temp_dir().join("fedserv-autoop.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#x", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#x".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#x" && modes == "+o 000AAAAAB")), "founder opped: {out:?}");

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into() });
        assert!(e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#x".into() }).is_empty(), "non-founder not opped");
    }
}
