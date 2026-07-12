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
use crate::engine::db::{Account, ChannelInfo, Event, LogEntry};
use crate::engine::Engine;

pub mod pb {
    tonic::include_proto!("fedserv.v1");
}

use pb::directory_server::{Directory, DirectoryServer};
use pb::replication_event::Kind;
use pb::{
    AccountDropped, AccountEmailSet, AccountRecord, AccountRegistered, AccountVerified, ChannelDescSet,
    ChannelDropped, ChannelFounderSet, ChannelRecord, ChannelRegistered, NickGrouped, NickUngrouped,
    ReplicationEvent, SnapshotRequest, SnapshotResponse, SubscribeRequest,
};

type Shared = Arc<Mutex<Engine>>;

// How many not-yet-sent events a slow subscriber may buffer before it starts
// blocking the broadcast (matches the gossip outbound channel's own sizing).
const SUBSCRIBER_BUFFER: usize = 1024;

struct DirectoryService {
    engine: Shared,
    outbound: broadcast::Sender<LogEntry>,
    token: String,
}

impl DirectoryService {
    // Every RPC needs `authorization: Bearer <token>` matching the configured
    // secret. Constant-time compare — same posture as password/secret checks
    // elsewhere in this codebase, cheap insurance against a timing side-channel.
    fn authorize<T>(&self, req: &Request<T>) -> Result<(), Status> {
        let got = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if got.as_bytes().ct_eq(self.token.as_bytes()).into() {
            Ok(())
        } else {
            Err(Status::unauthenticated("bad or missing bearer token"))
        }
    }
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
        | Event::ChannelMlock { .. }
        | Event::ChannelAccessAdd { .. }
        | Event::ChannelAccessDel { .. }
        | Event::ChannelAkickAdd { .. }
        | Event::ChannelAkickDel { .. }
        | Event::ChannelEntryMsgSet { .. } => return None,
    };
    Some(ReplicationEvent { origin: entry.origin().to_string(), seq: entry.seq(), lamport: entry.lamport(), kind: Some(kind) })
}

#[tonic::async_trait]
impl Directory for DirectoryService {
    async fn snapshot(&self, req: Request<SnapshotRequest>) -> Result<Response<SnapshotResponse>, Status> {
        self.authorize(&req)?;
        let (accounts, channels) = self.engine.lock().await.directory_snapshot();
        Ok(Response::new(SnapshotResponse {
            accounts: accounts.iter().map(account_record).collect(),
            channels: channels.iter().map(channel_record).collect(),
        }))
    }

    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<ReplicationEvent, Status>> + Send + 'static>>;

    async fn subscribe(&self, req: Request<SubscribeRequest>) -> Result<Response<Self::SubscribeStream>, Status> {
        self.authorize(&req)?;
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

// Start the listener, if configured. Absent [grpc] in config.toml = no-op, same
// pattern as gossip being optional.
pub async fn run(engine: Shared, cfg: GrpcCfg, outbound: broadcast::Sender<LogEntry>) {
    let addr = match cfg.bind.parse() {
        Ok(a) => a,
        Err(e) => return tracing::error!(%e, bind = %cfg.bind, "bad grpc bind address"),
    };
    let has_tls = cfg.tls.is_some();
    let svc = DirectoryService { engine, outbound, token: cfg.token };
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
    tracing::info!(%addr, tls = has_tls, "grpc directory API listening");
    if let Err(e) = server.add_service(DirectoryServer::new(svc)).serve(addr).await {
        tracing::error!(%e, "grpc server exited");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::db::Db;
    use crate::nickserv::NickServ;
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
        };
        let registered = LogEntry::for_test("A", 0, 1, Event::AccountRegistered(acct));
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
}
