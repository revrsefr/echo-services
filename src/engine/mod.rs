pub mod db;
pub mod scram;
pub mod service;
pub mod state;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::sync::mpsc;

use crate::proto::{NetAction, NetEvent, RegReply};
use db::{Db, LogEntry, RegError};
use scram::Verifier;
use fedserv_api::Privs;
use service::{Sender, Service, ServiceCtx};
use state::Network;

// SASL mechanisms we offer, strongest first. Advertised to the uplink as the
// `sasl=` capability value (IRCv3 SASL 3.2 mechanism list) and the set we accept.
const SASL_MECHS: &str = "EXTERNAL,SCRAM-SHA-512,SCRAM-SHA-256,PLAIN";

// The in-channel fantasy trigger, e.g. `!op`. Matches Anope's default.
const FANTASY_PREFIX: &str = "!";

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

// Outcome of an authority-originated account operation (see grpc.rs and the
// `authority_*` methods below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityStatus {
    Ok,
    AlreadyExists,
    NotFound,
    RateLimited,
    Invalid,
    Internal,
}

pub struct Engine {
    services: Vec<Box<dyn Service>>,
    network: Network,
    db: Db,
    sasl_sessions: HashMap<String, TimedSession>, // client uid -> in-progress exchange
    reg_limiter: RegLimiter,
    chan_service: Option<String>, // uid to source channel modes from (ChanServ)
    nick_service: Option<String>, // uid of the account service (NickServ), for its notices
    irc_out: Option<mpsc::UnboundedSender<NetAction>>, // services-initiated actions -> the uplink
    opers: HashMap<String, Privs>, // casefolded account -> privileges (from [[oper]] config)
    sid: String, // our services SID, for minting bot uids
    bot_uids: HashMap<String, String>, // casefolded bot nick -> live uid (per connection)
    next_bot_index: u32,
    bot_channels: std::collections::HashSet<(String, String)>, // (bot nick lc, channel) the bot has joined
}

impl Engine {
    pub fn new(services: Vec<Box<dyn Service>>, db: Db) -> Self {
        let chan_service = services.iter().find(|s| s.manages_channels()).map(|s| s.uid().to_string());
        let nick_service = services.iter().find(|s| s.manages_accounts()).map(|s| s.uid().to_string());
        Self {
            services,
            network: Network::default(),
            db,
            sasl_sessions: HashMap::new(),
            reg_limiter: RegLimiter::new(),
            chan_service,
            nick_service,
            irc_out: None,
            opers: HashMap::new(),
            sid: String::new(),
            bot_uids: HashMap::new(),
            next_bot_index: 0,
            bot_channels: std::collections::HashSet::new(),
        }
    }

    // Wire the channel the link layer drains, so the engine can push actions to the
    // uplink that no ircd event asked for (here: a forced logout after losing a
    // registration conflict).
    pub fn set_irc_out(&mut self, tx: mpsc::UnboundedSender<NetAction>) {
        self.irc_out = Some(tx);
    }

    // Load the services-operator table (casefolded account -> privileges).
    pub fn set_opers(&mut self, opers: HashMap<String, Privs>) {
        self.opers = opers;
    }

    // The privileges an account holds, empty if it is not an oper.
    fn oper_privs(&self, account: &str) -> Privs {
        self.opers.get(&account.to_ascii_lowercase()).copied().unwrap_or_default()
    }

    // Our services SID, needed to mint valid bot uids.
    pub fn set_sid(&mut self, sid: String) {
        self.sid = sid;
    }

    // Bring the network's bot pseudo-clients in line with the registry: introduce
    // any new bots, quit any that were deleted. Run at burst and after commands.
    fn reconcile_bots(&mut self) -> Vec<NetAction> {
        let mut out = Vec::new();
        let live: Vec<(String, String, String, String)> =
            self.db.bots().map(|b| (b.nick.clone(), b.user.clone(), b.host.clone(), b.gecos.clone())).collect();
        for (nick, user, host, gecos) in &live {
            let k = nick.to_ascii_lowercase();
            if !self.bot_uids.contains_key(&k) {
                let uid = format!("{}B{:05}", self.sid, self.next_bot_index);
                self.next_bot_index += 1;
                out.push(NetAction::IntroduceUser { uid: uid.clone(), nick: nick.clone(), ident: user.clone(), host: host.clone(), gecos: gecos.clone() });
                self.network.bot_connect(nick, &uid);
                self.bot_uids.insert(k, uid);
            }
        }
        let live_keys: std::collections::HashSet<String> = live.iter().map(|(n, ..)| n.to_ascii_lowercase()).collect();
        let removed: Vec<String> = self.bot_uids.keys().filter(|k| !live_keys.contains(*k)).cloned().collect();
        for k in removed {
            if let Some(uid) = self.bot_uids.remove(&k) {
                out.push(NetAction::QuitUser { uid, reason: "Bot removed".to_string() });
            }
            self.network.bot_forget(&k);
            self.bot_channels.retain(|(b, _)| *b != k); // its channel memberships go with it
        }
        // Join assigned channels, part unassigned ones (for still-live bots).
        let assigned: Vec<(String, String)> = self.db.channels()
            .filter_map(|c| c.assigned_bot.as_ref().map(|b| (b.to_ascii_lowercase(), c.name.clone())))
            .collect();
        let desired: std::collections::HashSet<(String, String)> =
            assigned.into_iter().filter(|(b, _)| self.bot_uids.contains_key(b)).collect();
        for (bot_lc, chan) in &desired {
            if !self.bot_channels.contains(&(bot_lc.clone(), chan.clone())) {
                if let Some(uid) = self.bot_uids.get(bot_lc) {
                    out.push(NetAction::ServiceJoin { uid: uid.clone(), channel: chan.clone() });
                    self.bot_channels.insert((bot_lc.clone(), chan.clone()));
                }
            }
        }
        let to_part: Vec<(String, String)> = self.bot_channels.iter().filter(|bc| !desired.contains(*bc)).cloned().collect();
        for (bot_lc, chan) in to_part {
            self.bot_channels.remove(&(bot_lc.clone(), chan.clone()));
            if let Some(uid) = self.bot_uids.get(&bot_lc) {
                out.push(NetAction::ServicePart { uid: uid.clone(), channel: chan });
            }
        }
        out
    }

    // Finish a SASL login, unless the account is suspended.
    fn sasl_login(&self, agent: &str, client: &str, account: String) -> Vec<NetAction> {
        if self.db.is_suspended(&account) {
            return sasl_fail(agent, client);
        }
        sasl_success(agent, client, account)
    }

    fn emit_irc(&self, action: NetAction) {
        if let Some(tx) = &self.irc_out {
            let _ = tx.send(action); // unbounded: never blocks; only fails if the link is down
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

    // A full read of current directory state, for the gRPC Snapshot RPC.
    pub fn directory_snapshot(&self) -> (Vec<db::Account>, Vec<db::ChannelInfo>) {
        (self.db.accounts().cloned().collect(), self.db.channels().cloned().collect())
    }

    // ── Account authority (see grpc.rs) ─────────────────────────────────────
    // A trusted caller (e.g. a website backend that already did its own login
    // check) managing accounts the same way an IRC user does through NickServ,
    // minus the command syntax. The bearer token on the gRPC side IS the
    // authorization: unlike the mirrored NickServ commands, these do NOT
    // re-check the account's own password — Register and Authenticate are the
    // two exceptions, since the password is the actual input there.

    pub fn authority_pre_check(&mut self, name: &str) -> Result<(), AuthorityStatus> {
        if self.db.exists(name) {
            return Err(AuthorityStatus::AlreadyExists);
        }
        if !self.reg_limiter.allow() {
            return Err(AuthorityStatus::RateLimited);
        }
        Ok(())
    }

    pub fn authority_register(&mut self, name: &str, creds: Option<db::Credentials>, email: Option<String>) -> AuthorityStatus {
        let Some(creds) = creds else { return AuthorityStatus::Internal };
        let addr = email.clone();
        let status = match self.db.register_prepared(name, creds, email) {
            Ok(()) => AuthorityStatus::Ok,
            Err(RegError::Exists) => AuthorityStatus::AlreadyExists,
            Err(RegError::Internal) => AuthorityStatus::Internal,
        };
        if status == AuthorityStatus::Ok && !self.db.is_verified(name) {
            if let Some(addr) = addr {
                let code = self.db.issue_code(name, db::CodeKind::Confirm);
                let mail = fedserv_api::email::confirm(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), name, &code);
                self.emit_irc(NetAction::SendEmail { to: addr, subject: mail.subject, text: mail.text, html: Some(mail.html) });
            }
        }
        status
    }

    pub fn authority_authenticate(&self, name: &str, password: &str) -> Option<String> {
        self.db.authenticate(name, password).map(str::to_string)
    }

    pub fn authority_set_password(&mut self, account: &str, creds: Option<db::Credentials>) -> AuthorityStatus {
        let Some(creds) = creds else { return AuthorityStatus::Internal };
        // set_credentials's only Err is Internal, which here always means "no such account".
        match self.db.set_credentials(account, creds) {
            Ok(()) => AuthorityStatus::Ok,
            Err(_) => AuthorityStatus::NotFound,
        }
    }

    pub fn authority_set_email(&mut self, account: &str, email: Option<String>) -> AuthorityStatus {
        match self.db.set_email(account, email) {
            Ok(()) => AuthorityStatus::Ok,
            Err(_) => AuthorityStatus::NotFound,
        }
    }

    pub fn authority_confirm(&mut self, account: &str, code: &str) -> AuthorityStatus {
        if !self.db.exists(account) {
            return AuthorityStatus::NotFound;
        }
        if self.db.is_verified(account) {
            return AuthorityStatus::Ok; // already confirmed — idempotent, not an error
        }
        if !self.db.take_code(account, db::CodeKind::Confirm, code) {
            return AuthorityStatus::Invalid;
        }
        match self.db.verify_account(account) {
            Ok(()) => AuthorityStatus::Ok,
            Err(_) => AuthorityStatus::Internal,
        }
    }

    // Drop reuses the exact cleanup a peer's gossiped drop already triggers
    // locally (channel release + session logout) — see `handle_account_gone`.
    pub fn authority_drop(&mut self, account: &str) -> AuthorityStatus {
        match self.db.drop_account(account) {
            Ok(true) => {
                self.handle_account_gone(account, "was dropped");
                AuthorityStatus::Ok
            }
            Ok(false) => AuthorityStatus::NotFound,
            Err(_) => AuthorityStatus::Internal,
        }
    }

    // Unlike Drop, the account itself is untouched — only its active IRC
    // sessions are logged out (no channel cleanup, this isn't "account gone").
    pub fn authority_force_logout(&mut self, account: &str) -> u32 {
        let victims = self.network.uids_logged_into(account);
        let n = victims.len() as u32;
        let ns = self.nick_service.clone();
        for uid in victims {
            self.network.clear_account(&uid);
            self.emit_irc(NetAction::Metadata { target: uid.clone(), key: "accountname".to_string(), value: String::new() });
            if let Some(ns) = &ns {
                self.emit_irc(NetAction::Notice { from: ns.clone(), to: uid, text: format!("You have been logged out of \x02{account}\x02.") });
            }
        }
        n
    }

    pub fn authority_group_nick(&mut self, nick: &str, account: &str) -> AuthorityStatus {
        if self.db.account(nick).is_some() {
            return AuthorityStatus::Invalid; // nick is itself a registered account
        }
        match self.db.group_nick(nick, account) {
            Ok(()) => AuthorityStatus::Ok,
            Err(_) => AuthorityStatus::NotFound, // group_nick's only Err means the account doesn't exist
        }
    }

    pub fn authority_ungroup_nick(&mut self, nick: &str) -> AuthorityStatus {
        match self.db.ungroup_nick(nick) {
            Ok(true) => AuthorityStatus::Ok,
            Ok(false) => AuthorityStatus::NotFound,
            Err(_) => AuthorityStatus::Internal,
        }
    }

    pub fn gossip_ingest(&mut self, entry: LogEntry) -> std::io::Result<()> {
        // If ingesting a peer's entry removed an account a local session relied on
        // (lost a conflict, or dropped elsewhere), clean up after it.
        match self.db.ingest(entry)? {
            Some(db::AccountChange::TakenOver(a)) => self.handle_account_gone(&a, "collided with another network and no longer belongs to you"),
            Some(db::AccountChange::Dropped(a)) => self.handle_account_gone(&a, "was dropped"),
            None => {}
        }
        Ok(())
    }

    // An account a local session was using is gone (lost a conflict, or dropped on
    // another node). Log out those sessions (their credential is gone) and drop the
    // channels it founded locally — their founder identity no longer exists here.
    fn handle_account_gone(&mut self, account: &str, reason: &str) {
        let victims = self.network.uids_logged_into(account);
        let orphaned = self.db.channels_owned_by(account);
        for chan in &orphaned {
            let _ = self.db.drop_channel(chan);
        }
        let (cs, ns) = (self.chan_service.clone(), self.nick_service.clone());
        // Release the registered mode on each dropped channel.
        for chan in &orphaned {
            if let Some(cs) = &cs {
                self.emit_irc(NetAction::ChannelMode { from: cs.clone(), channel: chan.clone(), modes: "-r".to_string() });
            }
        }
        // Log out and inform each local session that held the name.
        for uid in victims {
            self.network.clear_account(&uid);
            self.emit_irc(NetAction::Metadata { target: uid.clone(), key: "accountname".to_string(), value: String::new() });
            if let Some(ns) = &ns {
                self.emit_irc(NetAction::Notice {
                    from: ns.clone(),
                    to: uid.clone(),
                    text: format!("Your account \x02{account}\x02 {reason}. You have been logged out."),
                });
                if !orphaned.is_empty() {
                    self.emit_irc(NetAction::Notice {
                        from: ns.clone(),
                        to: uid,
                        text: format!("Channels you had registered as \x02{account}\x02 were released: {}.", orphaned.join(", ")),
                    });
                }
            }
        }
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

    // Simulate a uid being logged into `account`, for tests that need
    // `authority_force_logout` to have a live session to clear.
    #[cfg(test)]
    pub(crate) fn test_login(&mut self, uid: &str, account: &str) {
        self.network.set_account(uid, account);
    }

    #[cfg(test)]
    pub(crate) fn test_has_account(&self, name: &str) -> bool {
        self.db.exists(name)
    }

    #[cfg(test)]
    pub(crate) fn test_register_pw(&mut self, name: &str, pw: &str) {
        self.db.register(name, pw, None).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn test_account_hash(&self, name: &str) -> Option<String> {
        self.db.test_hash(name)
    }

    #[cfg(test)]
    pub(crate) fn test_register_channel(&mut self, name: &str, founder: &str) {
        self.db.register_channel(name, founder).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn test_has_channel(&self, name: &str) -> bool {
        self.db.channel(name).is_some()
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
    pub fn startup_actions(&mut self) -> Vec<NetAction> {
        // Fresh link: forget bot uids minted on any previous connection.
        self.bot_uids.clear();
        self.bot_channels.clear();
        self.network.clear_bots();
        self.next_bot_index = 0;
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
        // Introduce the registered bots too.
        out.extend(self.reconcile_bots());
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
            NetEvent::UserConnect { uid, nick, host } => {
                self.network.user_connect(uid, nick, host);
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
                    Some(info) => {
                        let mut out = vec![NetAction::ChannelMode { from: from.clone(), channel: channel.clone(), modes: info.lock_modes() }];
                        // KEEPTOPIC: restore the remembered topic on a recreated channel.
                        if info.settings.keeptopic && !info.topic.is_empty() {
                            out.push(NetAction::Topic { from, channel, topic: info.topic.clone() });
                        }
                        out
                    }
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
            // On join: record membership, enforce the auto-kick list, give access
            // members their status mode, and send the entry message.
            NetEvent::Join { uid, channel, op } => {
                self.network.channel_join(&channel, &uid, op);
                // A suspended channel is frozen: no auto-op, akick, or entry message.
                if self.db.is_channel_suspended(&channel) {
                    return Vec::new();
                }
                let account = self.network.account_of(&uid).map(str::to_string);
                let from = self.chan_service.clone().unwrap_or_default();
                let mode = account.as_deref().and_then(|a| self.db.channel(&channel).and_then(|c| c.join_mode(a)));
                let entrymsg = self.db.channel(&channel).map(|c| c.entrymsg.clone()).filter(|m| !m.is_empty());
                // Computed before the match below moves `channel` into its actions.
                let greet = self.greet_on_join(&channel, account.as_deref());
                let mut out = Vec::new();
                // SECUREOPS: a user who arrives opped (FJOIN prefix) but lacks op-level
                // access loses it, unless we're about to grant it to them anyway.
                if op && mode != Some("+o") && self.db.channel(&channel).is_some_and(|c| c.settings.secureops) {
                    out.push(NetAction::ChannelMode { from: from.clone(), channel: channel.clone(), modes: format!("-o {uid}") });
                }
                match mode {
                    // A user with access gets their status mode, plus the entry message.
                    Some(m) => {
                        if let Some(msg) = entrymsg {
                            out.push(NetAction::Notice { from: from.clone(), to: uid.clone(), text: msg });
                        }
                        out.push(NetAction::ChannelMode { from, channel, modes: format!("{m} {uid}") });
                    }
                    // No access: an auto-kick match is banned and kicked, else greeted.
                    None => {
                        let nick = self.network.nick_of(&uid).unwrap_or("*").to_string();
                        let host = self.network.host_of(&uid).unwrap_or("*").to_string();
                        let hostmask = format!("{nick}!*@{host}");
                        let akick = self.db.channel(&channel).and_then(|c| c.akick_match(&hostmask)).map(|k| {
                            let reason = if k.reason.is_empty() { "You are banned from this channel.".to_string() } else { k.reason.clone() };
                            (k.mask.clone(), reason)
                        });
                        match akick {
                            Some((mask, reason)) => {
                                self.network.channel_part(&channel, &uid);
                                out.push(NetAction::ChannelMode { from: from.clone(), channel: channel.clone(), modes: format!("+b {mask}") });
                                out.push(NetAction::Kick { from, channel, uid, reason });
                            }
                            None => {
                                if let Some(msg) = entrymsg {
                                    out.push(NetAction::Notice { from, to: uid, text: msg });
                                }
                            }
                        }
                    }
                }
                // GREET: if the channel shows greets and this member has channel
                // access + a personal greet, the assigned bot displays it.
                if let Some(g) = greet {
                    out.push(g);
                }
                out
            }
            NetEvent::Part { uid, channel } => {
                self.network.channel_part(&channel, &uid);
                Vec::new()
            }
            NetEvent::ChannelOp { channel, uid, op } => {
                self.network.set_op(&channel, &uid, op);
                // SECUREOPS: a user who gains +o without op-level access loses it.
                if op {
                    if let Some(c) = self.db.channel(&channel) {
                        if c.settings.secureops && !self.network.account_of(&uid).is_some_and(|a| c.join_mode(a) == Some("+o")) {
                            let from = self.chan_service.clone().unwrap_or_default();
                            return vec![NetAction::ChannelMode { from, channel, modes: format!("-o {uid}") }];
                        }
                    }
                }
                Vec::new()
            }
            NetEvent::ChannelKey { channel, key } => {
                self.network.set_channel_key(&channel, key);
                Vec::new()
            }
            NetEvent::TopicChange { channel, setter, topic } => {
                let info = self.db.channel(&channel).map(|c| (c.settings.keeptopic, c.settings.topiclock, c.topic.clone()));
                // The setter may change a locked topic only with op-level access.
                let authorized = self.network.account_of(&setter).and_then(|a| self.db.channel(&channel).map(|c| c.join_mode(a) == Some("+o"))).unwrap_or(false);
                match info {
                    // TOPICLOCK + unauthorised: put the kept topic back.
                    Some((_, true, stored)) if !authorized => {
                        let from = self.chan_service.clone().unwrap_or_default();
                        vec![NetAction::Topic { from, channel, topic: stored }]
                    }
                    // Otherwise remember the new topic if the channel keeps it.
                    Some((keep, lock, _)) if keep || lock => {
                        let _ = self.db.set_channel_topic(&channel, &topic);
                        Vec::new()
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
                            Some(account) => self.sasl_login(&agent, &client, account),
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
            ScramStep::Ack { account } => self.sasl_login(agent, client, account),
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
                self.sasl_login(agent, client, account)
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
        let addr = email.clone();
        let outcome = match self.db.register_prepared(account, creds, email) {
            Ok(()) => RegOutcome::Ok,
            Err(RegError::Exists) => RegOutcome::Exists,
            Err(RegError::Internal) => RegOutcome::Internal,
        };
        let ok = matches!(outcome, RegOutcome::Ok);
        let mut out = reg_reply(&reply, outcome, account);
        self.track_accounts(&out);
        // If this created an unverified account (email confirmation applies), email a code.
        if ok && !self.db.is_verified(account) {
            if let (Some(addr), RegReply::NickServ { agent, uid, .. }) = (addr, &reply) {
                let code = self.db.issue_code(account, db::CodeKind::Confirm);
                let mail = fedserv_api::email::confirm(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), account, &code);
                out.push(NetAction::SendEmail { to: addr, subject: mail.subject, text: mail.text, html: Some(mail.html) });
                out.push(NetAction::Notice { from: agent.clone(), to: uid.clone(), text: "A confirmation code has been emailed to you. Confirm with \x02CONFIRM <code>\x02.".to_string() });
            }
        }
        out
    }

    // Commit a password change the link layer derived off-thread, then notice the user.
    pub fn complete_password_change(&mut self, account: &str, creds: Option<db::Credentials>, agent: &str, uid: &str) -> Vec<NetAction> {
        let text = match creds.and_then(|c| self.db.set_credentials(account, c).ok()) {
            Some(()) => format!("Your password for \x02{account}\x02 has been changed."),
            None => "Sorry, that didn't work. Please try again in a moment.".to_string(),
        };
        vec![NetAction::Notice { from: agent.to_string(), to: uid.to_string(), text }]
    }

    // Route a PRIVMSG addressed to a service (by uid or nick) into that service,
    // handing it the sender's resolved nick, login state, and the account store.
    fn dispatch(&mut self, from: &str, to: &str, text: &str) -> Vec<NetAction> {
        let nick = self.network.nick_of(from).unwrap_or(from).to_string();
        let account = self.network.account_of(from).map(str::to_string);
        let privs = account.as_deref().map(|a| self.oper_privs(a)).unwrap_or_default();
        let mut ctx = ServiceCtx::default();
        let sender = Sender { uid: from, nick: &nick, account: account.as_deref(), privs };
        if to.starts_with('#') || to.starts_with('&') {
            // In-channel: a fantasy command (!op …) if a bot is assigned, plus a
            // BotServ kicker check on every line.
            self.fantasy(&sender, to, text, &mut ctx);
            if let Some(k) = self.kicker_check(from, to, text) {
                ctx.actions.push(k);
            }
        } else {
            let Self { services, network, db, .. } = self;
            for svc in services.iter_mut() {
                if to.eq_ignore_ascii_case(svc.uid()) || to.eq_ignore_ascii_case(svc.nick()) {
                    let args: Vec<&str> = text.split_whitespace().collect();
                    svc.on_command(&sender, &args, &mut ctx, network, db);
                    break;
                }
            }
        }
        // A command may have changed the bot registry (BotServ BOT ADD/DEL).
        let mut out = ctx.actions;
        out.extend(self.reconcile_bots());
        out
    }

    // The greet a channel's bot shows when a member logged into `account` joins:
    // only when greets are enabled for the channel, the member holds channel
    // access, and has set a non-empty personal greet.
    fn greet_on_join(&self, channel: &str, account: Option<&str>) -> Option<NetAction> {
        let acc = account?;
        let c = self.db.channel(channel)?;
        if !c.settings.bot_greet || c.join_mode(acc).is_none() {
            return None;
        }
        let bot = c.assigned_bot.clone()?;
        let greet = self.db.account(acc)?.greet.clone();
        if greet.is_empty() {
            return None;
        }
        let botuid = self.network.uid_by_nick(&bot)?.to_string();
        Some(NetAction::Privmsg { from: botuid, to: channel.to_string(), text: format!("[{acc}] {greet}") })
    }

    // A BotServ kicker verdict for a channel line: if the channel has an active
    // kicker the message trips (and the sender isn't an exempt operator), the
    // assigned bot kicks them.
    fn kicker_check(&self, from: &str, channel: &str, text: &str) -> Option<NetAction> {
        let c = self.db.channel(channel)?;
        if !c.kickers.any() {
            return None;
        }
        if c.kickers.dontkickops && self.network.is_op(channel, from) {
            return None;
        }
        let reason = c.kickers.violation(text)?;
        let bot = c.assigned_bot.clone()?;
        let botuid = self.network.uid_by_nick(&bot)?.to_string();
        Some(NetAction::Kick { from: botuid, channel: channel.to_string(), uid: from.to_string(), reason: reason.to_string() })
    }

    // Fantasy commands: `!op nick`, `!kick nick`, `!topic …` spoken in a channel
    // that has a bot assigned. We reuse ChanServ's real command handlers — the
    // fantasy word becomes the command and the channel is injected as its first
    // argument — then re-source the resulting actions from the bot, so the bot is
    // the visible actor (Anope routes fantasy through the assigned bot too).
    fn fantasy(&mut self, sender: &Sender, chan: &str, text: &str, ctx: &mut ServiceCtx) {
        let Some(rest) = text.strip_prefix(FANTASY_PREFIX) else { return };
        let mut words = rest.split_whitespace();
        let Some(cmd) = words.next() else { return };
        // Fantasy only works through an assigned, live bot.
        let Some(botnick) = self.db.channel(chan).and_then(|c| c.assigned_bot.clone()) else { return };
        let Some(botuid) = self.network.uid_by_nick(&botnick).map(str::to_string) else { return };
        let Some(csuid) = self
            .services
            .iter()
            .find(|s| s.nick().eq_ignore_ascii_case("ChanServ"))
            .map(|s| s.uid().to_string())
        else {
            return;
        };
        // Rewrite `!cmd args…` into `CMD #channel args…` for ChanServ.
        let mut args: Vec<&str> = Vec::new();
        args.push(cmd);
        args.push(chan);
        args.extend(words);
        {
            let Self { services, network, db, .. } = self;
            if let Some(cs) = services.iter_mut().find(|s| s.uid() == csuid) {
                cs.on_command(sender, &args, ctx, network, db);
            }
        }
        // Make the bot the source of everything ChanServ just emitted.
        for a in ctx.actions.iter_mut() {
            resource_action(a, &csuid, &botuid);
        }
    }
}

// Rewrite the source uid of an action from `old` to `new`, where the variant
// carries a `from`. Used to make fantasy output appear to come from the bot.
fn resource_action(a: &mut NetAction, old: &str, new: &str) {
    let from = match a {
        NetAction::Notice { from, .. }
        | NetAction::Privmsg { from, .. }
        | NetAction::ChannelMode { from, .. }
        | NetAction::Kick { from, .. }
        | NetAction::Topic { from, .. }
        | NetAction::Invite { from, .. } => from,
        _ => return,
    };
    if from == old {
        *from = new.to_string();
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
    use fedserv_nickserv::NickServ;

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
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() });
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
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() });
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
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() });

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
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "someone".into(), host: "host.example".into() });
        let out = logout(&mut e, "000AAAAAB");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("not logged in"))), "{out:?}");
        assert!(!out.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "must not rename when not logged in: {out:?}");
    }

    // Regression: a second LOGOUT is a no-op, not another guest rename (the churn
    // where Guest33294 -> LOGOUT -> Guest33295).
    #[test]
    fn logout_twice_renames_only_once() {
        let mut e = engine_with("twice", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() });
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
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() });

        let out = logout(&mut e, "000AAAAAB");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "sasl-authed user can log out: {out:?}");
    }

    // Regression: repeated IDENTIFY while already identified must not re-fire the
    // login (the 900 loop when the command is spammed).
    #[test]
    fn identify_twice_does_not_relogin() {
        let mut e = engine_with("reident", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() });
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
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "Guest99999".into(), host: "host.example".into() });
        e.handle(NetEvent::NickChange { uid: "000AAAAAB".into(), nick: "realnick".into() });
        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into(),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "realnick")), "must log into the current nick's account: {out:?}");
    }

    // Losing a registration conflict logs out the local session on that name and
    // notifies them over the services-initiated outbound path.
    #[test]
    fn lost_conflict_logs_out_local_session() {
        use fedserv_chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-lostconf.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 12345 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        // A local user logs into alice and registers a channel as founder.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        assert_eq!(e.network.account_of("000AAAAAB"), Some("alice"), "logged in before the conflict");
        e.db.register_channel("#hers", "alice").unwrap();

        // An earlier claim from another node wins and takes the name over.
        let winner = db::Account {
            name: "alice".into(), password_hash: "OTHER".into(), email: None,
            ts: 0, home: "peer".into(), scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![], suspension: None, memos: vec![], greet: String::new(),
        };
        let entry = LogEntry::for_test("peer", 0, 1, db::Event::AccountRegistered(winner));
        e.gossip_ingest(entry).unwrap();

        // The local session is logged out and its orphaned channel is dropped.
        assert!(e.network.account_of("000AAAAAB").is_none(), "session cleared after losing the name");
        assert!(e.db.channel("#hers").is_none(), "orphaned channel dropped");
        // The outbound path got a logout, a notice, a -r on the channel, and a release notice.
        let (mut logout, mut notice, mut unreg, mut released) = (false, false, false, false);
        while let Ok(a) = rx.try_recv() {
            match a {
                NetAction::Metadata { target, key, value } if target == "000AAAAAB" && key == "accountname" && value.is_empty() => logout = true,
                NetAction::Notice { to, text, .. } if to == "000AAAAAB" && text.contains("collided") => notice = true,
                NetAction::Notice { to, text, .. } if to == "000AAAAAB" && text.contains("released") => released = true,
                NetAction::ChannelMode { channel, modes, .. } if channel == "#hers" && modes == "-r" => unreg = true,
                _ => {}
            }
        }
        assert!(logout, "a logout must be pushed to the uplink");
        assert!(notice, "the user must be told why");
        assert!(unreg, "the orphaned channel must be de-registered (-r)");
        assert!(released, "the user must be told which channels were released");
    }

    // NickServ INFO shows registration details (email only to the owner); ALIST
    // lists the channels the account founds or has access on.
    #[test]
    fn nickserv_info_and_alist() {
        use fedserv_chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-nsinfo.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#a", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_ns = |e: &mut Engine, text: &str| {
            e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() })
        };
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let info = to_ns(&mut e, "INFO");
        assert!(notice(&info, "Information for \x02alice\x02"));
        assert!(notice(&info, "Registered"));
        assert!(notice(&info, "Email"), "owner sees their email line: {info:?}");
        assert!(notice(&to_ns(&mut e, "INFO ghost"), "isn't registered"));
        assert!(notice(&to_ns(&mut e, "ALIST"), "#a"));
    }

    // SET EMAIL stores an email; SET PASSWORD defers derivation, and once
    // completed the new password authenticates and the old one no longer does.
    #[test]
    fn nickserv_set_password_and_email() {
        let mut e = engine_with("nsset", "alice", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let to_ns = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        assert!(notice(&to_ns(&mut e, "SET EMAIL alice@example.org"), "updated"));
        assert!(notice(&to_ns(&mut e, "INFO"), "alice@example.org"), "owner INFO shows the email");

        let out = to_ns(&mut e, "SET PASSWORD newsecret");
        let deferred = out.iter().find_map(|a| match a {
            NetAction::DeferPassword { account, password, agent, uid } => Some((account.clone(), password.clone(), agent.clone(), uid.clone())),
            _ => None,
        });
        let (account, password, agent, uid) = deferred.expect("SET PASSWORD defers derivation");
        assert_eq!(password, "newsecret");
        let creds = Db::derive_credentials(&password, 4096);
        e.complete_password_change(&account, creds, &agent, &uid);
        assert!(e.db.authenticate("alice", "newsecret").is_some(), "new password works");
        assert!(e.db.authenticate("alice", "sesame").is_none(), "old password rejected");
    }

    // DROP deletes the account, releases and drops the channels it founded, and
    // logs the session out; a wrong password is refused.
    #[test]
    fn nickserv_drop_account() {
        let mut e = engine_with("nsdrop", "alice", "sesame");
        e.db.register_channel("#a", "alice").unwrap();
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let to_ns = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        assert!(notice(&to_ns(&mut e, "DROP wrongpass"), "Invalid password"));
        assert!(e.db.account("alice").is_some(), "wrong password keeps the account");

        let out = to_ns(&mut e, "DROP sesame");
        assert!(notice(&out, "has been dropped"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#a" && modes == "-r")), "channel released: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { target, key, value } if target == "000AAAAAB" && key == "accountname" && value.is_empty())), "session logged out: {out:?}");
        assert!(e.db.account("alice").is_none(), "account gone");
        assert!(e.db.channel("#a").is_none(), "founded channel gone");
    }

    // GROUP links a nick to an account so it identifies there too; GLIST lists the
    // aliases; UNGROUP removes one, after which the nick no longer resolves.
    #[test]
    fn nickserv_grouped_nicks() {
        let mut e = engine_with("nsgroup", "alice", "sesame");
        let to_ns = |e: &mut Engine, uid: &str, text: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));
        // A user on a different nick groups it to alice by password.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "ali".into(), host: "h".into() });
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "GROUP alice sesame"), "grouped to \x02alice\x02"));
        // Identifying as the grouped nick logs into alice.
        let out = to_ns(&mut e, "000AAAAAB", "IDENTIFY sesame");
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "alice")), "grouped nick identifies to alice: {out:?}");
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "GLIST"), "ali"));
        // Ungroup it; a fresh session on that nick no longer resolves.
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "UNGROUP ali"), "no longer grouped"));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "ali".into(), host: "h".into() });
        assert!(notice(&to_ns(&mut e, "000AAAAAC", "IDENTIFY sesame"), "isn't registered"));
    }

    // RESETPASS emails a code, and that code + a new password completes the reset;
    // the new password then authenticates and the old one no longer does.
    #[test]
    fn nickserv_resetpass() {
        let mut e = engine_with("nsreset", "alice", "sesame");
        e.db.set_email_enabled(true);
        e.db.set_email("alice", Some("alice@example.org".into())).unwrap();
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "someone".into(), host: "h".into() });
        let to_ns = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() });

        // Request: a code is emailed to the address on file.
        let out = to_ns(&mut e, "RESETPASS alice");
        let (to, body) = out.iter().find_map(|a| match a {
            NetAction::SendEmail { to, text, .. } => Some((to.clone(), text.clone())),
            _ => None,
        }).expect("a reset code is emailed");
        assert_eq!(to, "alice@example.org");
        let code = body.split("is: ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();

        // Complete: the code + a new password defers the change.
        let out = to_ns(&mut e, &format!("RESETPASS alice {code} brandnew"));
        let (account, password, agent, uid) = out.iter().find_map(|a| match a {
            NetAction::DeferPassword { account, password, agent, uid } => Some((account.clone(), password.clone(), agent.clone(), uid.clone())),
            _ => None,
        }).expect("a valid code defers the new password");
        assert_eq!(password, "brandnew");
        e.complete_password_change(&account, Db::derive_credentials(&password, 4096), &agent, &uid);
        assert!(e.db.authenticate("alice", "brandnew").is_some(), "new password works");
        assert!(e.db.authenticate("alice", "sesame").is_none(), "old password rejected");

        // A used/wrong code is refused.
        assert!(to_ns(&mut e, "RESETPASS alice 000000 x").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Invalid or expired"))));
    }

    // With email configured, registering with an address creates an unverified
    // account and emails a confirmation code; CONFIRM <code> verifies it.
    #[test]
    fn nickserv_confirm() {
        let path = std::env::temp_dir().join("fedserv-nsconfirm.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.set_email_enabled(true);
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "newbie".into(), host: "h".into() });

        // REGISTER with an email defers; complete it as the link layer would.
        let reg = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "REGISTER correcthorse newbie@example.org".into() });
        let (account, password, email, reply) = reg.iter().find_map(|a| match a {
            NetAction::DeferRegister { account, password, email, reply } => Some((account.clone(), password.clone(), email.clone(), reply.clone())),
            _ => None,
        }).expect("register defers");
        let out = e.complete_register(&account, Db::derive_credentials(&password, 4096), email, reply);
        assert!(!e.db.is_verified("newbie"), "registering with email starts unverified");
        let body = out.iter().find_map(|a| match a {
            NetAction::SendEmail { text, .. } => Some(text.clone()),
            _ => None,
        }).expect("a confirm code is emailed");
        let code = body.split("CONFIRM ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();

        // CONFIRM verifies (the user was auto-logged-in by register).
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: format!("CONFIRM {code}") });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("now confirmed"))), "{out:?}");
        assert!(e.db.is_verified("newbie"), "confirmed after CONFIRM");
    }

    // GHOST renames off a session using a nick the caller owns.
    #[test]
    fn nickserv_ghost() {
        let mut e = engine_with("nsghost", "alice", "sesame");
        let to_ns = |e: &mut Engine, uid: &str, text: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: text.into() });
        // A ghost sits on nick alice; the owner identifies from another nick.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "owner".into(), host: "h".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY alice sesame".into() });
        let out = to_ns(&mut e, "000AAAAAC", "GHOST alice");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, .. } if uid == "000AAAAAB")), "ghost renamed off: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("freed"))), "{out:?}");
    }

    // IDENTIFY accepts the two-arg account+password form: log into a named
    // account even when the current nick differs; a wrong password is refused.
    #[test]
    fn identify_two_arg_account_form() {
        let mut e = engine_with("twoarg", "realacct", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "someguest".into(), host: "host.example".into() });
        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY realacct sesame".into(),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "realacct")), "two-arg identify logs into the named account: {out:?}");

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "other".into(), host: "host.example".into() });
        let bad = e.handle(NetEvent::Privmsg {
            from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY realacct wrongpw".into(),
        });
        assert!(bad.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Invalid password"))), "{bad:?}");
        assert!(!bad.iter().any(|a| matches!(a, NetAction::Metadata { .. })), "wrong password must not log in: {bad:?}");

        // An unregistered account says so, rather than "Invalid password".
        let missing = e.handle(NetEvent::Privmsg {
            from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY ghost whatever".into(),
        });
        assert!(missing.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("isn't registered"))), "{missing:?}");
    }

    // SECUREOPS strips channel-operator status from a user without op-level access.
    #[test]
    fn secureops_strips_op_from_a_user_without_access() {
        use fedserv_chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-secureops.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register_channel("#c", "boss").unwrap();
        db.set_channel_setting("#c", db::ChanSetting::SecureOps, true).unwrap();
        let mut e = Engine::new(vec![Box::new(ChanServ { uid: "42SAAAAAB".into() })], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "rando".into(), host: "h".into() });
        // rando holds no access; being opped triggers a -o from ChanServ.
        let out = e.handle(NetEvent::ChannelOp { channel: "#c".into(), uid: "000AAAAAB".into(), op: true });
        assert!(
            out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "-o 000AAAAAB")),
            "SECUREOPS strips the op: {out:?}"
        );
        // With SECUREOPS off, the same op is left alone.
        e.db.set_channel_setting("#c", db::ChanSetting::SecureOps, false).unwrap();
        let out = e.handle(NetEvent::ChannelOp { channel: "#c".into(), uid: "000AAAAAB".into(), op: true });
        assert!(out.is_empty(), "no enforcement when SECUREOPS is off: {out:?}");
    }

    // BotServ BOT ADD/LIST is oper-gated (Priv::Admin) and the bot is remembered.
    #[test]
    fn botserv_bot_add_list_is_oper_gated() {
        use fedserv_botserv::BotServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-botserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(fedserv_api::Priv::Admin));
        e.set_opers(opers);
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "rando".into(), host: "h".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() });

        // A non-oper cannot add a bot.
        assert!(notice(&bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper"), "Access denied"));
        // The admin oper identifies, adds a bot, and sees it listed.
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        assert!(notice(&bs(&mut e, "000AAAAAC", "BOT ADD Bendy bot serv.host A Helper"), "added"));
        assert!(notice(&bs(&mut e, "000AAAAAC", "BOT LIST"), "Bendy"));
    }

    // A bot is introduced on the network when added, and quit when deleted.
    #[test]
    fn botserv_introduces_and_quits_bots() {
        use fedserv_botserv::BotServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-botintro.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(fedserv_api::Priv::Admin));
        e.set_opers(opers);
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        // Adding a bot introduces it on the network with a SID-prefixed uid.
        let out = bs(&mut e, "000AAAAAC", "BOT ADD Bendy bot serv.host A Helper");
        assert!(out.iter().any(|a| matches!(a, NetAction::IntroduceUser { nick, uid, .. } if nick == "Bendy" && uid.starts_with("42SB"))), "introduced: {out:?}");
        // A later command doesn't re-introduce an already-live bot.
        assert!(!bs(&mut e, "000AAAAAC", "BOT LIST").iter().any(|a| matches!(a, NetAction::IntroduceUser { .. })), "no duplicate introduce");
        // Deleting it quits the pseudo-client.
        assert!(bs(&mut e, "000AAAAAC", "BOT DEL Bendy").iter().any(|a| matches!(a, NetAction::QuitUser { .. })), "quit on delete");
        // A registered bot is introduced at burst.
        bs(&mut e, "000AAAAAC", "BOT ADD Roger svc host Bot");
        assert!(e.startup_actions().iter().any(|a| matches!(a, NetAction::IntroduceUser { nick, .. } if nick == "Roger")), "introduced at burst");
    }

    // ASSIGN puts the bot in the channel; UNASSIGN takes it out.
    #[test]
    fn botserv_assign_joins_and_unassign_parts() {
        use fedserv_botserv::BotServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-bsassign.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("staff", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(fedserv_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAC", "IDENTIFY password1");
        bs(&mut e, "000AAAAAC", "BOT ADD Bendy bot serv.host Helper"); // goes live

        // The founder assigns the bot: it joins the channel.
        let out = bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");
        assert!(out.iter().any(|a| matches!(a, NetAction::ServiceJoin { channel, .. } if channel == "#c")), "joins on assign: {out:?}");
        // Unassigning parts it.
        let out = bs(&mut e, "000AAAAAB", "UNASSIGN #c");
        assert!(out.iter().any(|a| matches!(a, NetAction::ServicePart { channel, .. } if channel == "#c")), "parts on unassign: {out:?}");
    }

    // SAY/ACT speak through the channel's assigned bot, sourced from the bot's uid.
    #[test]
    fn botserv_say_speaks_through_bot() {
        use fedserv_botserv::BotServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-bssay.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("rando", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(fedserv_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAR".into(), nick: "rando".into(), host: "h".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAR", "IDENTIFY password1");
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");

        // Founder SAY: a PRIVMSG to the channel sourced from the bot's uid.
        let out = bs(&mut e, "000AAAAAB", "SAY #c hello there");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text } if from.starts_with("42SB") && to == "#c" && text == "hello there")),
            "bot says: {out:?}"
        );
        // ACT wraps the text in a CTCP ACTION.
        let out = bs(&mut e, "000AAAAAB", "ACT #c waves");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Privmsg { text, .. } if text == "\x01ACTION waves\x01")),
            "bot acts: {out:?}"
        );
        // A non-op can't drive the bot.
        let out = bs(&mut e, "000AAAAAR", "SAY #c nope");
        assert!(!out.iter().any(|a| matches!(a, NetAction::Privmsg { .. })), "non-op blocked: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "denied notice: {out:?}");
    }

    // The caps kicker makes the assigned bot kick a shouting message, exempts
    // operators when DONTKICKOPS is on, and leaves ordinary lines alone.
    #[test]
    fn botserv_caps_kicker_kicks() {
        use fedserv_botserv::BotServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-bskick.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(fedserv_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "#c".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAR".into(), nick: "rando".into(), host: "h".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");
        bs(&mut e, "000AAAAAB", "KICK #c CAPS ON");
        e.handle(NetEvent::Join { uid: "000AAAAAR".into(), channel: "#c".into(), op: false });

        // Shouting is kicked, sourced from the bot.
        let out = say(&mut e, "000AAAAAR", "HELLO EVERYONE LISTEN UP");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Kick { from, channel, uid, .. } if from.starts_with("42SB") && channel == "#c" && uid == "000AAAAAR")),
            "caps kicked: {out:?}"
        );
        // A normal line is fine.
        assert!(!say(&mut e, "000AAAAAR", "hello everyone").iter().any(|a| matches!(a, NetAction::Kick { .. })), "quiet line ok");
        // With DONTKICKOPS, an operator can shout.
        bs(&mut e, "000AAAAAB", "KICK #c DONTKICKOPS ON");
        e.network.set_op("#c", "000AAAAAR", true);
        assert!(!say(&mut e, "000AAAAAR", "SHOUTING BUT I AM OP").iter().any(|a| matches!(a, NetAction::Kick { .. })), "op exempt");
    }

    // A member's personal greet is shown by the assigned bot on join, once the
    // channel enables greets and the member has access.
    #[test]
    fn botserv_greet_shown_on_join() {
        use fedserv_botserv::BotServ;
        use fedserv_chanserv::ChanServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-bsgreet.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(fedserv_api::Priv::Admin));
        e.set_opers(opers);
        e.chan_service = Some("42SAAAAAB".into());
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAB", "SET GREET hello all");
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");

        // Greets off by default: joining is silent.
        assert!(
            !e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: true }).iter().any(|a| matches!(a, NetAction::Privmsg { .. })),
            "no greet before it is enabled"
        );
        e.handle(NetEvent::Part { uid: "000AAAAAB".into(), channel: "#c".into() });
        bs(&mut e, "000AAAAAB", "SET #c GREET ON");
        // Now the founder's greet is shown by the bot.
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: true });
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text } if from.starts_with("42SB") && to == "#c" && text == "[boss] hello all")),
            "greet shown: {out:?}"
        );
    }

    // Fantasy commands typed in-channel route through ChanServ and are sourced
    // from the assigned bot.
    #[test]
    fn botserv_fantasy_routes_through_bot() {
        use fedserv_botserv::BotServ;
        use fedserv_chanserv::ChanServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-bsfantasy.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        db.register_channel("#d", "boss").unwrap(); // registered, no bot
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(fedserv_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        let chan = |e: &mut Engine, uid: &str, c: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: c.into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");

        // `!op` (founder, no target) ops the invoker, sourced from the bot uid.
        let out = chan(&mut e, "000AAAAAB", "#c", "!op");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::ChannelMode { from, channel, modes } if from.starts_with("42SB") && channel == "#c" && modes.contains("+o") && modes.contains("000AAAAAB"))),
            "fantasy op via bot: {out:?}"
        );
        // Ordinary chatter is ignored.
        assert!(chan(&mut e, "000AAAAAB", "#c", "hello everyone").is_empty(), "chatter ignored");
        // Fantasy in a channel with no bot does nothing.
        assert!(chan(&mut e, "000AAAAAB", "#d", "!op").is_empty(), "no bot, no fantasy");
    }

    // MemoServ delivers a memo to an offline account and notifies them on login.
    #[test]
    fn memoserv_delivers_and_notifies_on_login() {
        use fedserv_memoserv::MemoServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-memoserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "password1", None).unwrap();
        db.register("bob", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(MemoServ { uid: "42SAAAAAE".into() }),
            ],
            db,
        );
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let ms = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAE".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        // alice identifies and sends bob (offline) a memo.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        assert!(notice(&ms(&mut e, "000AAAAAB", "SEND bob Hello from alice"), "Memo sent"));

        // bob logs in later and is told he has a new memo, then reads it.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into() });
        assert!(notice(&ns(&mut e, "000AAAAAC", "IDENTIFY password1"), "new memo"));
        assert!(notice(&ms(&mut e, "000AAAAAC", "READ NEW"), "Hello from alice"));
    }

    // Channel SUSPEND is oper-gated and freezes founder management until lifted.
    #[test]
    fn channel_suspend_is_oper_gated_and_freezes_management() {
        use fedserv_chanserv::ChanServ;
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-chansuspendcmd.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("staff", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(fedserv_api::Priv::Suspend));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAC", "IDENTIFY password1");

        // A non-oper cannot suspend a channel.
        assert!(notice(&cs(&mut e, "000AAAAAB", "SUSPEND #c"), "Access denied"));
        // The oper suspends it.
        assert!(notice(&cs(&mut e, "000AAAAAC", "SUSPEND #c raided"), "now suspended"));
        // The founder can no longer manage it.
        assert!(notice(&cs(&mut e, "000AAAAAB", "SET #c SIGNKICK ON"), "suspended"));
        // UNSUSPEND restores management.
        assert!(notice(&cs(&mut e, "000AAAAAC", "UNSUSPEND #c"), "no longer suspended"));
        assert!(notice(&cs(&mut e, "000AAAAAB", "SET #c SIGNKICK ON"), "is now"));
    }

    // SUSPEND is oper-gated, blocks the victim's login, and UNSUSPEND restores it.
    #[test]
    fn suspend_blocks_login_and_needs_oper() {
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-suspendcmd.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("victim", "password1", None).unwrap();
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(fedserv_api::Priv::Suspend));
        e.set_opers(opers);
        let to_ns = |e: &mut Engine, uid: &str, text: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "victim".into(), host: "h".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() });

        // A non-oper cannot suspend.
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "SUSPEND victim"), "Access denied"));
        // The oper identifies and suspends the victim.
        to_ns(&mut e, "000AAAAAC", "IDENTIFY password1");
        assert!(notice(&to_ns(&mut e, "000AAAAAC", "SUSPEND victim being a nuisance"), "now suspended"));
        // The victim can no longer identify.
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "IDENTIFY password1"), "suspended"));
        // UNSUSPEND lets them back in.
        assert!(notice(&to_ns(&mut e, "000AAAAAC", "UNSUSPEND victim"), "no longer suspended"));
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "IDENTIFY password1"), "now identified"));
    }

    // An auspex oper sees another account's hidden INFO (email); a non-oper does not.
    #[test]
    fn auspex_oper_sees_hidden_info() {
        use fedserv_nickserv::NickServ;
        let path = std::env::temp_dir().join("fedserv-auspex.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "password1", Some("alice@example.org".into())).unwrap();
        db.register("operator", "password1", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        let mut opers = std::collections::HashMap::new();
        opers.insert("operator".to_string(), Privs::default().with(fedserv_api::Priv::Auspex));
        e.set_opers(opers);
        let info_alice = |e: &mut Engine, uid: &str| {
            e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "INFO alice".into() })
        };
        let shows_email = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("alice@example.org")));

        // The auspex oper identifies and sees alice's email.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "operator".into(), host: "h".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        assert!(shows_email(&info_alice(&mut e, "000AAAAAB")), "auspex oper sees the email");

        // An unidentified (non-oper) viewer does not.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "guest".into(), host: "h".into() });
        assert!(!shows_email(&info_alice(&mut e, "000AAAAAC")), "non-oper sees no email");
    }

    // TOPICLOCK reverts an unauthorised topic change; KEEPTOPIC restores the
    // remembered topic when the channel is recreated.
    #[test]
    fn topiclock_reverts_and_keeptopic_restores() {
        use fedserv_chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-topic.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register_channel("#c", "boss").unwrap();
        db.set_channel_setting("#c", db::ChanSetting::KeepTopic, true).unwrap();
        db.set_channel_setting("#c", db::ChanSetting::TopicLock, true).unwrap();
        db.set_channel_topic("#c", "Official topic").unwrap();
        let mut e = Engine::new(vec![Box::new(ChanServ { uid: "42SAAAAAB".into() })], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "rando".into(), host: "h".into() });
        // A user without access changes the topic -> reverted to the stored one.
        let out = e.handle(NetEvent::TopicChange { channel: "#c".into(), setter: "000AAAAAB".into(), topic: "hacked".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Topic { topic, .. } if topic == "Official topic")), "topiclock reverts: {out:?}");
        // KEEPTOPIC restores the remembered topic on channel (re)creation.
        let out = e.handle(NetEvent::ChannelCreate { channel: "#c".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Topic { topic, .. } if topic == "Official topic")), "keeptopic restores: {out:?}");
    }

    // ChanServ: registration needs identification, INFO shows the founder, and
    // only the founder can drop.
    #[test]
    fn chanserv_register_info_drop() {
        use fedserv_chanserv::ChanServ;
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
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "host.example".into() });

        // Not identified yet: refused.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "REGISTER #room"), "logged in"));

        // Identify, then register. Registration needs operator status in the channel.
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "REGISTER #room"), "channel operator"), "op required to register");
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: true });
        let out = to_cs(&mut e, "000AAAAAB", "REGISTER #room");
        assert!(notice(&out, "now registered"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "+r")), "register sets +r: {out:?}");
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "INFO #room"), "alice"));

        // Founder sets a mode lock: it applies immediately and shows on view.
        let out = to_cs(&mut e, "000AAAAAB", "MLOCK #room +nt-s");
        assert!(notice(&out, "updated"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "+rnt-s")), "mlock applied: {out:?}");
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "MLOCK #room"), "+nt-s"));

        // Founder sets modes directly via ChanServ MODE.
        let out = to_cs(&mut e, "000AAAAAB", "MODE #room +S");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "+S")), "MODE applies: {out:?}");

        // Founder manages the access list.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "ACCESS #room ADD helper op"), "Added"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "ACCESS #room"), "helper"));

        // A different, unidentified user cannot change modes, access, the lock, or drop it.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "host.example".into() });
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "MODE #room +i"), "founder"));
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "ACCESS #room ADD x op"), "founder"));
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "MLOCK #room +i"), "founder"));
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "DROP #room"), "founder"));

        // The founder can, which also clears +r.
        let out = to_cs(&mut e, "000AAAAAB", "DROP #room");
        assert!(notice(&out, "dropped"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "-r")), "drop clears +r: {out:?}");
    }

    // ChanServ moderation: an op can op/kick/ban users; a non-op is refused.
    #[test]
    fn chanserv_moderation() {
        use fedserv_chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-cs-mod.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#m", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);

        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        // Founder alice identifies; target bob connects with a known host.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "1.2.3.4".into() });

        // OP a user by nick.
        let out = to_cs(&mut e, "000AAAAAB", "OP #m bob");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#m" && modes == "+o 000AAAAAC")), "{out:?}");

        // KICK a user by nick, with a reason.
        let out = to_cs(&mut e, "000AAAAAB", "KICK #m bob rude");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { channel, uid, reason, .. } if channel == "#m" && uid == "000AAAAAC" && reason == "rude")), "{out:?}");

        // BAN sets +b *!*@host and kicks.
        let out = to_cs(&mut e, "000AAAAAB", "BAN #m bob spam");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#m" && modes == "+b *!*@1.2.3.4")), "{out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAC")), "{out:?}");

        // UNBAN clears it.
        let out = to_cs(&mut e, "000AAAAAB", "UNBAN #m bob");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#m" && modes == "-b *!*@1.2.3.4")), "{out:?}");

        // A user with no access is refused.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAD".into(), nick: "carol".into(), host: "h2".into() });
        assert!(to_cs(&mut e, "000AAAAAD", "KICK #m alice").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("operator access"))));
    }

    // ChanServ topic, invite, auto-kick (with enforcement on join), list and status.
    #[test]
    fn chanserv_topic_invite_akick() {
        use fedserv_chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-cs-tia.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "bad.host".into() });

        // TOPIC and INVITE are sourced from ChanServ.
        let out = to_cs(&mut e, "000AAAAAB", "TOPIC #c hello there");
        assert!(out.iter().any(|a| matches!(a, NetAction::Topic { channel, topic, .. } if channel == "#c" && topic == "hello there")), "{out:?}");
        let out = to_cs(&mut e, "000AAAAAB", "INVITE #c bob");
        assert!(out.iter().any(|a| matches!(a, NetAction::Invite { uid, channel, .. } if uid == "000AAAAAC" && channel == "#c")), "{out:?}");

        // LIST and STATUS.
        assert!(to_cs(&mut e, "000AAAAAB", "LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("#c"))));
        assert!(to_cs(&mut e, "000AAAAAB", "STATUS #c").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("founder"))));

        // AKICK a mask, then a matching join is banned and kicked.
        assert!(to_cs(&mut e, "000AAAAAB", "AKICK #c ADD *!*@bad.host begone").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Added"))));
        let out = e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#c".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#c" && modes == "+b *!*@bad.host")), "{out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { channel, uid, reason, .. } if channel == "#c" && uid == "000AAAAAC" && reason == "begone")), "{out:?}");

        // The founder joining is never auto-kicked (they get +o instead).
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes.starts_with("+o"))), "{out:?}");
    }

    // ChanServ SET: description and founder transfer, founder-gated.
    #[test]
    fn chanserv_set() {
        use fedserv_chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-cs-set.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "hunter2", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        let notice = |out: &[NetAction], needle: &str| {
            out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)))
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        // Description is stored and shows in INFO.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c DESC a friendly place"), "updated"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "INFO #c"), "a friendly place"));

        // Transfer to a non-account is refused.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c FOUNDER nobody"), "isn't a registered account"));

        // Transfer to bob works; alice is then no longer the founder.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c FOUNDER bob"), "transferred"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c DESC nope"), "founder can change"));
    }

    // ChanServ entrymsg, enforce, getkey, seen, clone and the xop lists.
    #[test]
    fn chanserv_extended() {
        use fedserv_chanserv::ChanServ;
        let path = std::env::temp_dir().join("fedserv-cs-ext.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("carol", "pw", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        let notice = |out: &[NetAction], needle: &str| {
            out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)))
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        // ENTRYMSG: set it, then a joining user is noticed it.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "ENTRYMSG #c welcome aboard"), "updated"));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "guest".into(), host: "h2".into() });
        let out = e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#c".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "000AAAAAC" && text == "welcome aboard")), "{out:?}");

        // XOP: AOP add shows in the AOP list and grants op access.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "AOP #c ADD carol"), "Added"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "AOP #c LIST"), "carol"));

        // ENFORCE: alice present gets +o, the akick-matching guest is kicked.
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false });
        to_cs(&mut e, "000AAAAAB", "AKICK #c ADD *!*@h2 out");
        let out = to_cs(&mut e, "000AAAAAB", "ENFORCE #c");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "+o 000AAAAAB")), "{out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAC")), "{out:?}");

        // GETKEY: reflects a tracked key change.
        e.handle(NetEvent::ChannelKey { channel: "#c".into(), key: Some("s3cret".into()) });
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "GETKEY #c"), "s3cret"));

        // SEEN: an online user vs one who quit.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SEEN alice"), "currently online"));
        e.handle(NetEvent::Quit { uid: "000AAAAAC".into() });
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SEEN guest"), "last seen"));

        // CLONE: copy #c's settings (incl. the AOP) into a second owned channel.
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#d".into(), op: true });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: "REGISTER #d".into() });
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "CLONE #c #d"), "Copied"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "AOP #d LIST"), "carol"));
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
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "host.example".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#x".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#x" && modes == "+o 000AAAAAB")), "founder opped: {out:?}");

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "host.example".into() });
        assert!(e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#x".into(), op: false }).is_empty(), "non-founder not opped");
    }

    // An access-list voice gets +v on join.
    #[test]
    fn access_voice_on_join() {
        let path = std::env::temp_dir().join("fedserv-access-join.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("carol", "sesame", None).unwrap();
        db.register_channel("#y", "boss").unwrap();
        db.access_add("#y", "carol", "voice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "carol".into(), host: "host.example".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#y".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#y" && modes == "+v 000AAAAAB")), "{out:?}");
    }
}
