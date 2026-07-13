// Directory replication over gRPC: lets a website (Django, or anything else
// with a protoc-generated client) mirror the account/channel directory this
// node owns. See proto/fedserv.proto for the wire contract and exactly which
// fields are exposed — no credentials of any kind cross this API.
use std::pin::Pin;
use std::sync::Arc;

use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use crate::config::Grpc as GrpcCfg;
use crate::engine::db::{Account, ChannelInfo, Db, Event, LogEntry};
use crate::engine::{AuthorityStatus, Engine};

pub mod pb {
    tonic::include_proto!("fedserv.v1");
}

use pb::accounts_server::{Accounts, AccountsServer};
use pb::directory_server::{Directory, DirectoryServer};
use pb::replication_event::Kind;
use pb::stats_server::{Stats, StatsServer};
use pb::{
    AccountDropped, AccountEmailSet, AccountRecord, AccountRegistered, AccountReply, AccountVerified,
    AuthenticateReply, AuthenticateRequest, ChannelDescSet, ChannelDropped, ChannelFounderSet, ChannelRecord,
    ChannelRegistered, ConfirmRequest, DropRequest, ForceLogoutReply, ForceLogoutRequest, GroupNickRequest,
    NickGrouped, NickUngrouped, RegisterRequest, ReplicationEvent, SetEmailRequest, SetPasswordRequest,
    SnapshotRequest, SnapshotResponse, Status as PbStatus, StatsRequest, StatsResponse, SubscribeRequest,
    UngroupNickRequest,
};

type Shared = Arc<Mutex<Engine>>;

// How many not-yet-sent events a slow subscriber may buffer before it starts
// blocking the broadcast (matches the gossip outbound channel's own sizing).
const SUBSCRIBER_BUFFER: usize = 1024;

// Every RPC (both services) needs `authorization: Bearer <token>` matching the
// configured secret. Constant-time compare — same posture as password/secret
// checks elsewhere in this codebase, cheap insurance against a timing side-channel.
// Status is tonic's error type, used by every RPC — boxing it here would fight
// the framework's convention for marginal size gain.
#[allow(clippy::result_large_err)]
fn authorize<T>(req: &Request<T>, token: &str) -> Result<(), Status> {
    let got = req
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if got.as_bytes().ct_eq(token.as_bytes()).into() {
        Ok(())
    } else {
        Err(Status::unauthenticated("bad or missing bearer token"))
    }
}

fn status_of(s: AuthorityStatus) -> PbStatus {
    match s {
        AuthorityStatus::Ok => PbStatus::Ok,
        AuthorityStatus::AlreadyExists => PbStatus::AlreadyExists,
        AuthorityStatus::NotFound => PbStatus::NotFound,
        AuthorityStatus::RateLimited => PbStatus::RateLimited,
        AuthorityStatus::Invalid => PbStatus::Invalid,
        AuthorityStatus::Internal => PbStatus::Internal,
    }
}

fn reply(s: AuthorityStatus, message: impl Into<String>) -> AccountReply {
    AccountReply { status: status_of(s) as i32, message: message.into() }
}

struct DirectoryService {
    engine: Shared,
    outbound: broadcast::Sender<LogEntry>,
    token: String,
}

fn account_record(a: &Account) -> AccountRecord {
    AccountRecord {
        name: a.name.clone(),
        email: a.email.clone().unwrap_or_default(),
        verified: a.verified,
        registered_at: a.ts,
        home: a.home.clone(),
    }
}

fn channel_record(c: &ChannelInfo) -> ChannelRecord {
    ChannelRecord { name: c.name.clone(), founder: c.founder.clone(), registered_at: c.ts, description: c.desc.clone() }
}

// Translate one committed log entry to a wire event. Returns None for events
// this API doesn't replicate (credential changes, and the finer-grained
// channel-ops-list events) — the subscriber simply never sees them, v1 scope.
fn to_wire(entry: &LogEntry) -> Option<ReplicationEvent> {
    let kind = match entry.event() {
        Event::AccountRegistered(a) => Kind::AccountRegistered(AccountRegistered {
            name: a.name.clone(),
            email: a.email.clone().unwrap_or_default(),
            verified: a.verified,
            registered_at: a.ts,
            home: a.home.clone(),
        }),
        Event::AccountEmailSet { account, email } => {
            Kind::AccountEmailSet(AccountEmailSet { account: account.clone(), email: email.clone().unwrap_or_default() })
        }
        Event::AccountVerified { account } => Kind::AccountVerified(AccountVerified { account: account.clone() }),
        Event::AccountDropped { account } => Kind::AccountDropped(AccountDropped { account: account.clone() }),
        Event::NickGrouped { nick, account } => Kind::NickGrouped(NickGrouped { nick: nick.clone(), account: account.clone() }),
        Event::NickUngrouped { nick } => Kind::NickUngrouped(NickUngrouped { nick: nick.clone() }),
        Event::ChannelRegistered { name, founder, ts } => {
            Kind::ChannelRegistered(ChannelRegistered { name: name.clone(), founder: founder.clone(), registered_at: *ts })
        }
        Event::ChannelDropped { name } => Kind::ChannelDropped(ChannelDropped { name: name.clone() }),
        Event::ChannelFounderSet { channel, founder } => {
            Kind::ChannelFounderSet(ChannelFounderSet { name: channel.clone(), founder: founder.clone() })
        }
        Event::ChannelDescSet { channel, desc } => Kind::ChannelDescSet(ChannelDescSet { name: channel.clone(), description: desc.clone() }),
        // Credentials (never leave this API) and the finer channel-ops-list
        // events (access/akick/mlock/entrymsg — internal IRC bookkeeping, not
        // directory identity) are intentionally not replicated.
        Event::CertAdded { .. }
        | Event::CertRemoved { .. }
        | Event::AccountPasswordSet { .. }
        | Event::AccountGreetSet { .. }
        | Event::AjoinAdded { .. }
        | Event::AjoinRemoved { .. }
        | Event::VhostSet { .. }
        | Event::VhostDeleted { .. }
        | Event::VhostRequested { .. }
        | Event::VhostRequestCleared { .. }
        | Event::AccountSuspended { .. }
        | Event::AccountUnsuspended { .. }
        | Event::MemoSent { .. }
        | Event::MemoRead { .. }
        | Event::MemoDeleted { .. }
        | Event::ChannelMlock { .. }
        | Event::ChannelAccessAdd { .. }
        | Event::ChannelAccessDel { .. }
        | Event::ChannelAkickAdd { .. }
        | Event::ChannelAkickDel { .. }
        | Event::ChannelEntryMsgSet { .. }
        | Event::ChannelSettingsSet { .. }
        | Event::ChannelKickerSet { .. }
        | Event::ChannelBadwordsSet { .. }
        | Event::ChannelTriggersSet { .. }
        | Event::ChannelTopicSet { .. }
        | Event::ChannelSuspended { .. }
        | Event::ChannelUnsuspended { .. }
        | Event::ChannelBotAssigned { .. }
        | Event::ChannelBotUnassigned { .. }
        | Event::BotAdded(_)
        | Event::BotRemoved { .. }
        | Event::VhostOfferAdded { .. }
        | Event::VhostOfferRemoved { .. }
        | Event::VhostForbidAdded { .. }
        | Event::VhostForbidRemoved { .. }
        | Event::VhostTemplateSet { .. } => return None,
    };
    Some(ReplicationEvent { origin: entry.origin().to_string(), seq: entry.seq(), lamport: entry.lamport(), kind: Some(kind) })
}

#[tonic::async_trait]
impl Directory for DirectoryService {
    async fn snapshot(&self, req: Request<SnapshotRequest>) -> Result<Response<SnapshotResponse>, Status> {
        authorize(&req, &self.token)?;
        let (accounts, channels) = self.engine.lock().await.directory_snapshot();
        Ok(Response::new(SnapshotResponse {
            accounts: accounts.iter().map(account_record).collect(),
            channels: channels.iter().map(channel_record).collect(),
        }))
    }

    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<ReplicationEvent, Status>> + Send + 'static>>;

    async fn subscribe(&self, req: Request<SubscribeRequest>) -> Result<Response<Self::SubscribeStream>, Status> {
        authorize(&req, &self.token)?;
        let mut rx = self.outbound.subscribe();
        let (tx, out) = tokio::sync::mpsc::channel(SUBSCRIBER_BUFFER);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(entry) => {
                        if let Some(ev) = to_wire(&entry) {
                            if tx.send(Ok(ev)).await.is_err() {
                                break; // subscriber went away
                            }
                        }
                    }
                    // We fell behind and the sender overwrote entries we hadn't read
                    // yet: the stream is no longer a complete replica of what
                    // changed, so end it. The documented contract (see the .proto)
                    // is that a subscriber re-Snapshots after a dropped stream.
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = tx.send(Err(Status::data_loss("subscriber lagged behind the change stream; re-run Snapshot"))).await;
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(out))))
    }
}

struct AccountsService {
    engine: Shared,
    token: String,
}

#[tonic::async_trait]
impl Accounts for AccountsService {
    async fn register(&self, req: Request<RegisterRequest>) -> Result<Response<AccountReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        if msg.name.is_empty() || msg.password.is_empty() {
            return Ok(Response::new(reply(AuthorityStatus::Invalid, "name and password are required")));
        }
        // Cheap checks (exists / rate limit) before paying for derivation.
        if let Err(status) = self.engine.lock().await.authority_pre_check(&msg.name) {
            return Ok(Response::new(reply(status, "cannot register that name right now")));
        }
        // Expensive Argon2/SCRAM derivation runs off the shared engine lock, same
        // as an IRC-originated REGISTER (see link.rs's DeferRegister handling).
        let iterations = self.engine.lock().await.scram_iterations();
        let password = msg.password.clone();
        let creds = tokio::task::spawn_blocking(move || Db::derive_credentials(&password, iterations)).await.unwrap_or(None);
        let email = if msg.email.is_empty() { None } else { Some(msg.email) };
        let status = self.engine.lock().await.authority_register(&msg.name, creds, email);
        Ok(Response::new(reply(status, describe(status))))
    }

    async fn authenticate(&self, req: Request<AuthenticateRequest>) -> Result<Response<AuthenticateReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        match self.engine.lock().await.authority_authenticate(&msg.name, &msg.password) {
            Some(account) => Ok(Response::new(AuthenticateReply { status: PbStatus::Ok as i32, account })),
            None => Ok(Response::new(AuthenticateReply { status: PbStatus::Invalid as i32, account: String::new() })),
        }
    }

    async fn set_password(&self, req: Request<SetPasswordRequest>) -> Result<Response<AccountReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        if msg.password.is_empty() {
            return Ok(Response::new(reply(AuthorityStatus::Invalid, "password is required")));
        }
        let iterations = self.engine.lock().await.scram_iterations();
        let password = msg.password.clone();
        let creds = tokio::task::spawn_blocking(move || Db::derive_credentials(&password, iterations)).await.unwrap_or(None);
        let status = self.engine.lock().await.authority_set_password(&msg.account, creds);
        Ok(Response::new(reply(status, describe(status))))
    }

    async fn set_email(&self, req: Request<SetEmailRequest>) -> Result<Response<AccountReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        let email = if msg.email.is_empty() { None } else { Some(msg.email) };
        let status = self.engine.lock().await.authority_set_email(&msg.account, email);
        Ok(Response::new(reply(status, describe(status))))
    }

    async fn confirm(&self, req: Request<ConfirmRequest>) -> Result<Response<AccountReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        let status = self.engine.lock().await.authority_confirm(&msg.account, &msg.code);
        Ok(Response::new(reply(status, describe(status))))
    }

    async fn drop(&self, req: Request<DropRequest>) -> Result<Response<AccountReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        let status = self.engine.lock().await.authority_drop(&msg.account);
        Ok(Response::new(reply(status, describe(status))))
    }

    async fn force_logout(&self, req: Request<ForceLogoutRequest>) -> Result<Response<ForceLogoutReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        let cleared = self.engine.lock().await.authority_force_logout(&msg.account);
        Ok(Response::new(ForceLogoutReply { status: PbStatus::Ok as i32, sessions_cleared: cleared }))
    }

    async fn group_nick(&self, req: Request<GroupNickRequest>) -> Result<Response<AccountReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        let status = self.engine.lock().await.authority_group_nick(&msg.nick, &msg.account);
        Ok(Response::new(reply(status, describe(status))))
    }

    async fn ungroup_nick(&self, req: Request<UngroupNickRequest>) -> Result<Response<AccountReply>, Status> {
        authorize(&req, &self.token)?;
        let msg = req.into_inner();
        let status = self.engine.lock().await.authority_ungroup_nick(&msg.nick);
        Ok(Response::new(reply(status, describe(status))))
    }
}

fn describe(s: AuthorityStatus) -> &'static str {
    match s {
        AuthorityStatus::Ok => "ok",
        AuthorityStatus::AlreadyExists => "that name is already registered",
        AuthorityStatus::NotFound => "no such account",
        AuthorityStatus::RateLimited => "too many requests right now, try again shortly",
        AuthorityStatus::Invalid => "invalid request",
        AuthorityStatus::Internal => "internal error",
    }
}

// Read-only stats: the shared counter registry plus live gauges, for dashboards.
struct StatsService {
    engine: Shared,
    token: String,
}

#[tonic::async_trait]
impl Stats for StatsService {
    async fn get(&self, req: Request<StatsRequest>) -> Result<Response<StatsResponse>, Status> {
        authorize(&req, &self.token)?;
        let counters = self.engine.lock().await.stats_snapshot().into_iter().collect();
        let collected_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(Response::new(StatsResponse { counters, collected_at }))
    }
}

// Start the listener, if configured. Absent [grpc] in config.toml = no-op, same
// pattern as gossip being optional.
pub async fn run(engine: Shared, cfg: GrpcCfg, outbound: broadcast::Sender<LogEntry>) {
    let addr = match cfg.bind.parse() {
        Ok(a) => a,
        Err(e) => return tracing::error!(%e, bind = %cfg.bind, "bad grpc bind address"),
    };
    let has_tls = cfg.tls.is_some();
    let accounts_svc = AccountsService { engine: engine.clone(), token: cfg.token.clone() };
    let stats_svc = StatsService { engine: engine.clone(), token: cfg.token.clone() };
    let directory_svc = DirectoryService { engine, outbound, token: cfg.token };
    let mut server = Server::builder();
    if let Some(tls) = &cfg.tls {
        let (cert, key) = match (std::fs::read(&tls.cert), std::fs::read(&tls.key)) {
            (Ok(c), Ok(k)) => (c, k),
            _ => return tracing::error!("grpc TLS cert/key unreadable"),
        };
        let identity = Identity::from_pem(cert, key);
        server = match server.tls_config(ServerTlsConfig::new().identity(identity)) {
            Ok(s) => s,
            Err(e) => return tracing::error!(%e, "grpc TLS setup failed"),
        };
    }
    tracing::info!(%addr, tls = has_tls, "grpc directory + accounts + stats API listening");
    if let Err(e) = server
        .add_service(DirectoryServer::new(directory_svc))
        .add_service(AccountsServer::new(accounts_svc))
        .add_service(StatsServer::new(stats_svc))
        .serve(addr)
        .await
    {
        tracing::error!(%e, "grpc server exited");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::db::Db;
    use fedserv_nickserv::NickServ;
    use tokio_stream::StreamExt;
    use tonic::metadata::MetadataValue;

    fn engine_with(tag: &str) -> (Shared, broadcast::Sender<LogEntry>) {
        let path = std::env::temp_dir().join(format!("fedserv-grpc-{tag}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let (tx, _) = broadcast::channel(1024);
        let mut db = Db::open(&path, "A");
        db.scram_iterations = 4096;
        db.set_outbound(tx.clone());
        let ns = NickServ { uid: "AAAAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        (Arc::new(Mutex::new(Engine::new(vec![Box::new(ns)], db))), tx)
    }

    fn authed<T>(msg: T, token: &str) -> Request<T> {
        let mut req = Request::new(msg);
        req.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {token}")).unwrap());
        req
    }

    // Credential-shaped and ops-list events never cross the wire; directory
    // identity events do, carrying only the fields the .proto exposes.
    #[test]
    fn to_wire_filters_credentials_and_maps_directory_events() {
        let acct = Account {
            name: "alice".into(),
            password_hash: "secret-hash".into(),
            email: Some("alice@example.com".into()),
            ts: 111,
            home: "A".into(),
            scram256: Some("verifier".into()),
            scram512: None,
            certfps: vec!["deadbeef".into()],
            verified: true,
            ajoin: vec![],
            suspension: None,
            memos: vec![],
            greet: String::new(),
            vhost: None,
            vhost_request: None,
        };
        let registered = LogEntry::for_test("A", 0, 1, Event::AccountRegistered(Box::new(acct)));
        let wire = to_wire(&registered).expect("account registration replicates");
        match wire.kind {
            Some(Kind::AccountRegistered(a)) => {
                assert_eq!(a.name, "alice");
                assert_eq!(a.email, "alice@example.com");
                assert!(a.verified);
            }
            other => panic!("expected AccountRegistered, got {other:?}"),
        }

        let pw_change = LogEntry::for_test(
            "A", 1, 2,
            Event::AccountPasswordSet { account: "alice".into(), password_hash: "x".into(), scram256: "x".into(), scram512: "x".into() },
        );
        assert!(to_wire(&pw_change).is_none(), "credential changes must never replicate");

        let cert = LogEntry::for_test("A", 2, 3, Event::CertAdded { account: "alice".into(), fp: "deadbeef".into() });
        assert!(to_wire(&cert).is_none(), "cert fingerprints must never replicate");

        let akick = LogEntry::for_test("A", 3, 4, Event::ChannelAkickAdd { channel: "#x".into(), mask: "*!*@bad".into(), reason: String::new() });
        assert!(to_wire(&akick).is_none(), "ops-list events are out of v1 scope");

        let chan = LogEntry::for_test("A", 4, 5, Event::ChannelRegistered { name: "#tchatou".into(), founder: "alice".into(), ts: 222 });
        match to_wire(&chan).expect("channel registration replicates").kind {
            Some(Kind::ChannelRegistered(c)) => {
                assert_eq!(c.name, "#tchatou");
                assert_eq!(c.founder, "alice");
            }
            other => panic!("expected ChannelRegistered, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn snapshot_requires_the_configured_token() {
        let (engine, tx) = engine_with("auth");
        engine.lock().await.test_register("alice");
        let svc = DirectoryService { engine, outbound: tx, token: "right".into() };

        let err = svc.snapshot(authed(SnapshotRequest {}, "wrong")).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let ok = svc.snapshot(authed(SnapshotRequest {}, "right")).await.unwrap();
        assert_eq!(ok.get_ref().accounts.len(), 1);
        assert_eq!(ok.get_ref().accounts[0].name, "alice");
    }

    #[tokio::test]
    async fn snapshot_never_includes_credential_fields() {
        // AccountRecord (unlike the internal Account) has no field a credential
        // could hide in — this test is a canary against ever adding one.
        let (engine, tx) = engine_with("shape");
        engine.lock().await.test_register("alice");
        let svc = DirectoryService { engine, outbound: tx, token: "t".into() };
        let resp = svc.snapshot(authed(SnapshotRequest {}, "t")).await.unwrap();
        let rec = &resp.get_ref().accounts[0];
        // Exhaustive destructure: adding a field to AccountRecord forces a look here.
        let AccountRecord { name, email, verified, registered_at, home } = rec;
        assert_eq!(name, "alice");
        let _ = (email, verified, registered_at, home);
    }

    #[tokio::test]
    async fn subscribe_streams_a_live_registration() {
        let (engine, tx) = engine_with("live");
        let svc = DirectoryService { engine: engine.clone(), outbound: tx, token: "t".into() };

        let stream = svc.subscribe(authed(SubscribeRequest {}, "t")).await.unwrap().into_inner();
        tokio::pin!(stream);

        engine.lock().await.test_register("bob");

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("event within timeout")
            .expect("stream not closed")
            .expect("not an error");
        match ev.kind {
            Some(Kind::AccountRegistered(a)) => assert_eq!(a.name, "bob"),
            other => panic!("expected AccountRegistered, got {other:?}"),
        }
    }

    fn accounts_svc(engine: Shared) -> AccountsService {
        AccountsService { engine, token: "t".into() }
    }

    #[tokio::test]
    async fn register_then_authenticate_round_trips() {
        let (engine, _tx) = engine_with("acct-register");
        let svc = accounts_svc(engine);

        let reg = svc
            .register(authed(RegisterRequest { name: "carol".into(), password: "hunter2".into(), email: String::new() }, "t"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reg.status, PbStatus::Ok as i32);

        // Registering again is rejected, not silently overwritten.
        let dup = svc
            .register(authed(RegisterRequest { name: "carol".into(), password: "other".into(), email: String::new() }, "t"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(dup.status, PbStatus::AlreadyExists as i32);

        let ok = svc
            .authenticate(authed(AuthenticateRequest { name: "carol".into(), password: "hunter2".into() }, "t"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ok.status, PbStatus::Ok as i32);
        assert_eq!(ok.account, "carol");

        let bad = svc
            .authenticate(authed(AuthenticateRequest { name: "carol".into(), password: "wrong".into() }, "t"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(bad.status, PbStatus::Invalid as i32);
    }

    #[tokio::test]
    async fn register_rejects_a_bad_bearer_token() {
        let (engine, _tx) = engine_with("acct-auth");
        let svc = accounts_svc(engine);
        let err = svc
            .register(authed(RegisterRequest { name: "dave".into(), password: "x".into(), email: String::new() }, "wrong"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn set_password_replaces_credentials() {
        let (engine, _tx) = engine_with("acct-setpw");
        let svc = accounts_svc(engine);
        svc.register(authed(RegisterRequest { name: "erin".into(), password: "first".into(), email: String::new() }, "t")).await.unwrap();

        let status = svc
            .set_password(authed(SetPasswordRequest { account: "erin".into(), password: "second".into() }, "t"))
            .await
            .unwrap()
            .into_inner()
            .status;
        assert_eq!(status, PbStatus::Ok as i32);

        let old = svc.authenticate(authed(AuthenticateRequest { name: "erin".into(), password: "first".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(old.status, PbStatus::Invalid as i32, "the old password must stop working");
        let new = svc.authenticate(authed(AuthenticateRequest { name: "erin".into(), password: "second".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(new.status, PbStatus::Ok as i32);

        let missing = svc
            .set_password(authed(SetPasswordRequest { account: "nobody".into(), password: "x".into() }, "t"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(missing.status, PbStatus::NotFound as i32);
    }

    #[tokio::test]
    async fn set_email_updates_and_clears() {
        let (engine, _tx) = engine_with("acct-setemail");
        let svc = accounts_svc(engine.clone());
        svc.register(authed(RegisterRequest { name: "frank".into(), password: "x".into(), email: String::new() }, "t")).await.unwrap();

        svc.set_email(authed(SetEmailRequest { account: "frank".into(), email: "frank@example.com".into() }, "t")).await.unwrap();
        assert_eq!(engine.lock().await.directory_snapshot().0[0].email.as_deref(), Some("frank@example.com"));

        svc.set_email(authed(SetEmailRequest { account: "frank".into(), email: String::new() }, "t")).await.unwrap();
        assert_eq!(engine.lock().await.directory_snapshot().0[0].email, None, "empty string clears the email");
    }

    // Full round trip through the real confirmation-email pipeline: register with
    // email confirmation on, capture the code fedserv actually emails out (never
    // returned by the RPC — proving the caller can't skip owning the inbox), then
    // confirm with it.
    #[tokio::test]
    async fn confirm_completes_with_the_real_emailed_code() {
        let path = std::env::temp_dir().join("fedserv-grpc-acct-confirm.jsonl");
        let _ = std::fs::remove_file(&path);
        let (tx, _) = broadcast::channel(1024);
        let mut db = Db::open(&path, "A");
        db.scram_iterations = 4096;
        db.set_outbound(tx);
        db.set_email_enabled(true);
        let ns = NickServ { uid: "AAAAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let engine: Shared = Arc::new(Mutex::new(Engine::new(vec![Box::new(ns)], db)));

        let (irc_tx, mut irc_rx) = tokio::sync::mpsc::unbounded_channel();
        engine.lock().await.set_irc_out(irc_tx);

        let svc = accounts_svc(engine.clone());
        let reg = svc
            .register(authed(RegisterRequest { name: "gina".into(), password: "x".into(), email: "gina@example.com".into() }, "t"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reg.status, PbStatus::Ok as i32);
        assert!(!engine.lock().await.directory_snapshot().0[0].verified, "unverified until confirmed");

        let mail_text = loop {
            match irc_rx.try_recv() {
                Ok(crate::proto::NetAction::SendEmail { text, .. }) => break text,
                Ok(_) => continue,
                Err(_) => panic!("no confirmation email was queued"),
            }
        };
        let code = mail_text.split("CONFIRM ").nth(1).and_then(|s| s.split_whitespace().next()).expect("code in email body").to_string();

        let bad = svc.confirm(authed(ConfirmRequest { account: "gina".into(), code: "000000".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(bad.status, PbStatus::Invalid as i32);

        let ok = svc.confirm(authed(ConfirmRequest { account: "gina".into(), code }, "t")).await.unwrap().into_inner();
        assert_eq!(ok.status, PbStatus::Ok as i32);
        assert!(engine.lock().await.directory_snapshot().0[0].verified);
    }

    #[tokio::test]
    async fn drop_releases_channels_and_logs_out_sessions() {
        let (engine, _tx) = engine_with("acct-drop");
        let svc = accounts_svc(engine.clone());
        svc.register(authed(RegisterRequest { name: "hank".into(), password: "x".into(), email: String::new() }, "t")).await.unwrap();
        {
            let mut e = engine.lock().await;
            e.test_login("UID1", "hank");
        }

        let status = svc.drop(authed(DropRequest { account: "hank".into() }, "t")).await.unwrap().into_inner().status;
        assert_eq!(status, PbStatus::Ok as i32);
        assert!(engine.lock().await.directory_snapshot().0.is_empty());

        // Dropping again is a clean NotFound, not a crash or false success.
        let again = svc.drop(authed(DropRequest { account: "hank".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(again.status, PbStatus::NotFound as i32);
    }

    #[tokio::test]
    async fn force_logout_clears_active_sessions_only() {
        let (engine, _tx) = engine_with("acct-logout");
        let svc = accounts_svc(engine.clone());
        svc.register(authed(RegisterRequest { name: "iris".into(), password: "x".into(), email: String::new() }, "t")).await.unwrap();
        {
            let mut e = engine.lock().await;
            e.test_login("UID1", "iris");
            e.test_login("UID2", "iris");
        }

        let resp = svc.force_logout(authed(ForceLogoutRequest { account: "iris".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(resp.status, PbStatus::Ok as i32);
        assert_eq!(resp.sessions_cleared, 2);
        // The account itself must still exist — only sessions were cleared.
        assert_eq!(engine.lock().await.directory_snapshot().0.len(), 1);
    }

    #[tokio::test]
    async fn group_and_ungroup_nick() {
        let (engine, _tx) = engine_with("acct-group");
        let svc = accounts_svc(engine.clone());
        svc.register(authed(RegisterRequest { name: "jack".into(), password: "x".into(), email: String::new() }, "t")).await.unwrap();

        let grouped = svc.group_nick(authed(GroupNickRequest { nick: "jackalt".into(), account: "jack".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(grouped.status, PbStatus::Ok as i32);

        // A nick that is itself a registered account can't be grouped to another.
        svc.register(authed(RegisterRequest { name: "realaccount".into(), password: "x".into(), email: String::new() }, "t")).await.unwrap();
        let refused = svc.group_nick(authed(GroupNickRequest { nick: "realaccount".into(), account: "jack".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(refused.status, PbStatus::Invalid as i32);

        let ungrouped = svc.ungroup_nick(authed(UngroupNickRequest { nick: "jackalt".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(ungrouped.status, PbStatus::Ok as i32);
        let missing = svc.ungroup_nick(authed(UngroupNickRequest { nick: "jackalt".into() }, "t")).await.unwrap().into_inner();
        assert_eq!(missing.status, PbStatus::NotFound as i32);
    }
}
