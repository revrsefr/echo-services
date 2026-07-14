// Node-to-node account replication. Peers run anti-entropy: each side advertises
// its version vector and the other replies with the log entries it is missing.
// Ingest is idempotent, so re-delivery and reconnect after a split both converge.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::{Gossip, Peer, Tls};
use crate::engine::db::LogEntry;
use crate::engine::Engine;

type Shared = Arc<Mutex<Engine>>;
type Outbound = broadcast::Sender<LogEntry>;

const TICK: Duration = Duration::from_secs(10); // anti-entropy backstop; pushes handle the common case
const REDIAL: Duration = Duration::from_secs(5); // reconnect backoff for dialed peers

// Wire protocol: one JSON object per line.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum Msg {
    Hello { secret: String, origin: String },
    // A version vector. `reply` asks the peer to answer with its own digest, so a
    // node that dropped a push can pull back exactly what the peer is missing.
    Digest {
        versions: HashMap<String, u64>,
        #[serde(default)]
        reply: bool,
    },
    // Boxed: a LogEntry carries an Event, whose largest variant dwarfs the other
    // Msg variants.
    Entry { entry: Box<LogEntry> },
}

// Start the listener (if bound) and a dialer per configured peer. When TLS is
// configured, every peer link is mutually authenticated against the CA.
pub async fn run(engine: Shared, cfg: Gossip, peers: Vec<Peer>, origin: String, outbound: Outbound) {
    let tls = match cfg.tls.as_ref().map(build_tls).transpose() {
        Ok(t) => t,
        Err(e) => return tracing::error!(%e, "gossip TLS setup failed"),
    };
    let acceptor = tls.as_ref().map(|(a, _)| a.clone());
    let connector = tls.as_ref().map(|(_, c)| c.clone());
    if let Some(bind) = cfg.bind.clone() {
        tokio::spawn(listen(bind, engine.clone(), cfg.secret.clone(), origin.clone(), outbound.clone(), acceptor));
    }
    for peer in peers {
        tokio::spawn(dial(peer, engine.clone(), cfg.secret.clone(), origin.clone(), outbound.clone(), connector.clone()));
    }
}

async fn listen(bind: String, engine: Shared, secret: String, origin: String, outbound: Outbound, acceptor: Option<TlsAcceptor>) {
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => return tracing::error!(%e, %bind, "gossip bind failed"),
    };
    tracing::info!(%bind, tls = acceptor.is_some(), "gossip listening");
    loop {
        if let Ok((stream, addr)) = listener.accept().await {
            tracing::info!(%addr, "gossip peer accepted");
            let (engine, secret, origin, outbound, acceptor) =
                (engine.clone(), secret.clone(), origin.clone(), outbound.clone(), acceptor.clone());
            tokio::spawn(async move {
                let served = match acceptor {
                    Some(acc) => match acc.accept(stream).await {
                        Ok(tls) => session(tls, engine, secret, origin, outbound).await,
                        Err(e) => return tracing::debug!(%e, %addr, "gossip tls accept failed"),
                    },
                    None => session(stream, engine, secret, origin, outbound).await,
                };
                if let Err(e) = served {
                    tracing::debug!(%e, "gossip session ended");
                }
            });
        }
    }
}

async fn dial(peer: Peer, engine: Shared, secret: String, origin: String, outbound: Outbound, connector: Option<TlsConnector>) {
    loop {
        match TcpStream::connect(&peer.addr).await {
            Ok(stream) => {
                tracing::info!(addr = %peer.addr, "gossip dialed peer");
                let served = match &connector {
                    Some(conn) => match ServerName::try_from(peer.name.clone()) {
                        Ok(name) => match conn.connect(name, stream).await {
                            Ok(tls) => session(tls, engine.clone(), secret.clone(), origin.clone(), outbound.clone()).await,
                            Err(e) => Err(anyhow::anyhow!("tls connect: {e}")),
                        },
                        Err(e) => Err(anyhow::anyhow!("bad peer TLS name {:?}: {e}", peer.name)),
                    },
                    None => session(stream, engine.clone(), secret.clone(), origin.clone(), outbound.clone()).await,
                };
                if let Err(e) = served {
                    tracing::debug!(%e, addr = %peer.addr, "gossip session ended");
                }
            }
            Err(e) => tracing::debug!(%e, addr = %peer.addr, "gossip dial failed"),
        }
        tokio::time::sleep(REDIAL).await;
    }
}

// Build a mutual-TLS acceptor + connector from PEM files: we present our cert and
// require the peer to present one signed by the configured CA.
fn build_tls(tls: &Tls) -> anyhow::Result<(TlsAcceptor, TlsConnector)> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certs = load_certs(&tls.cert)?;
    let key = load_key(&tls.key)?;
    let roots = load_roots(&tls.ca)?;

    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots.clone())).build()?;
    let server = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs.clone(), key.clone_key())?;
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?;

    Ok((TlsAcceptor::from(Arc::new(server)), TlsConnector::from(Arc::new(client))))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path)?;
    Ok(rustls_pemfile::certs(&mut &data[..]).collect::<Result<Vec<_>, _>>()?)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path)?;
    rustls_pemfile::private_key(&mut &data[..])?.ok_or_else(|| anyhow::anyhow!("no private key in {path}"))
}

fn load_roots(path: &str) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(path)? {
        roots.add(cert)?;
    }
    Ok(roots)
}

// One peer connection: authenticate, then run anti-entropy until it drops.
async fn session<S>(stream: S, engine: Shared, secret: String, origin: String, outbound: Outbound) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read).lines();

    // A single writer task owns the socket; the reader and the ticker feed it.
    let (tx, mut rx) = mpsc::channel::<String>(1024);
    let writer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if write.write_all(line.as_bytes()).await.is_err() || write.write_all(b"\n").await.is_err() {
                break;
            }
        }
    });

    // Handshake: send our hello, require a matching secret back.
    let _ = send(&tx, &Msg::Hello { secret: secret.clone(), origin }).await;
    match reader.next_line().await? {
        Some(line) => match serde_json::from_str::<Msg>(&line) {
            Ok(Msg::Hello { secret: s, .. }) if s == secret => {}
            _ => {
                writer.abort();
                anyhow::bail!("bad gossip handshake");
            }
        },
        None => {
            writer.abort();
            anyhow::bail!("peer closed before handshake");
        }
    }

    // Re-advertise our version vector on a timer. The first tick fires an
    // immediate digest for initial sync; later ones are a backstop for anything
    // a push dropped.
    let ticker = {
        let (tx, engine) = (tx.clone(), engine.clone());
        tokio::spawn(async move {
            loop {
                let versions = engine.lock().await.gossip_digest();
                if send(&tx, &Msg::Digest { versions, reply: false }).await.is_err() {
                    break;
                }
                tokio::time::sleep(TICK).await;
            }
        })
    };

    // Push freshly committed entries straight to the peer, so a new registration
    // propagates in milliseconds instead of waiting for the next digest. Idempotent
    // ingest on the far side absorbs the echo of an entry the peer just sent us.
    let forwarder = {
        let (tx, engine, mut rx) = (tx.clone(), engine.clone(), outbound.subscribe());
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(entry) => {
                        if send(&tx, &Msg::Entry { entry: Box::new(entry) }).await.is_err() {
                            break;
                        }
                    }
                    // We fell behind and dropped pushes the peer now lacks. Ask it
                    // to reply with its digest so we re-send exactly what it is
                    // missing, rather than waiting out the timer.
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let versions = engine.lock().await.gossip_digest();
                        if send(&tx, &Msg::Digest { versions, reply: true }).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    };

    // Answer a peer's digest with what it lacks; apply the entries it sends us.
    let result = loop {
        match reader.next_line().await {
            Ok(Some(line)) => match serde_json::from_str::<Msg>(&line) {
                Ok(Msg::Digest { versions, reply }) => {
                    let missing = engine.lock().await.gossip_missing(&versions);
                    for entry in missing {
                        let _ = send(&tx, &Msg::Entry { entry: Box::new(entry) }).await;
                    }
                    if reply {
                        let versions = engine.lock().await.gossip_digest();
                        let _ = send(&tx, &Msg::Digest { versions, reply: false }).await;
                    }
                }
                Ok(Msg::Entry { entry }) => {
                    if let Err(e) = engine.lock().await.gossip_ingest(*entry) {
                        tracing::warn!(%e, "gossip ingest failed");
                    }
                }
                _ => {}
            },
            Ok(None) => break Ok(()),
            Err(e) => break Err(e.into()),
        }
    };

    ticker.abort();
    forwarder.abort();
    writer.abort();
    result
}

async fn send(tx: &mpsc::Sender<String>, msg: &Msg) -> Result<(), ()> {
    let line = serde_json::to_string(msg).map_err(|_| ())?;
    tx.send(line).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::db::Db;
    use echo_nickserv::NickServ;

    fn engine(origin: &str, tag: &str) -> (Shared, Outbound) {
        let path = std::env::temp_dir().join(format!("echo-gossip-{tag}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let (tx, _) = broadcast::channel(1024);
        let mut db = Db::open(&path, origin);
        db.scram_iterations = 4096;
        db.set_outbound(tx.clone());
        let ns = NickServ { uid: format!("{origin}AAAAAA"), guest_nick: "Guest".into(), guest_seq: 0 };
        (Arc::new(Mutex::new(Engine::new(vec![Box::new(ns)], db))), tx)
    }

    // An account that exists before the link comes up reaches the peer via the
    // initial digest exchange (the pull path).
    #[tokio::test]
    async fn two_nodes_converge_over_a_link() {
        let (a, atx) = engine("A", "conv-a");
        let (b, btx) = engine("B", "conv-b");
        a.lock().await.test_register("alice");

        let (ca, cb) = tokio::io::duplex(64 * 1024);
        let sa = tokio::spawn(session(ca, a.clone(), "s3cret".into(), "A".into(), atx));
        let sb = tokio::spawn(session(cb, b.clone(), "s3cret".into(), "B".into(), btx));

        let mut converged = false;
        for _ in 0..100 {
            if b.lock().await.test_has_account("alice") {
                converged = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        sa.abort();
        sb.abort();
        assert!(converged, "B should receive A's account over gossip");
    }

    // A write made after the link is up must arrive within the poll interval,
    // which only the push path can do (the digest backstop is 10s).
    #[tokio::test]
    async fn push_propagates_new_writes() {
        let (a, atx) = engine("A", "push-a");
        let (b, btx) = engine("B", "push-b");

        let (ca, cb) = tokio::io::duplex(64 * 1024);
        let sa = tokio::spawn(session(ca, a.clone(), "s3cret".into(), "A".into(), atx));
        let sb = tokio::spawn(session(cb, b.clone(), "s3cret".into(), "B".into(), btx));
        tokio::time::sleep(Duration::from_millis(200)).await; // let both subscribe

        a.lock().await.test_register("late");
        let mut got = false;
        for _ in 0..40 {
            if b.lock().await.test_has_account("late") {
                got = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        sa.abort();
        sb.abort();
        assert!(got, "a post-connect write should push to B well under the 10s digest");
    }

    // Two nodes registering the same name before they link must converge on one
    // owner — no split-brain. Both register "alice" with different passwords, then
    // the link resolves it deterministically to a single winner on both sides.
    #[tokio::test]
    async fn concurrent_registration_converges_to_one_owner() {
        let (a, atx) = engine("A", "conflict-a");
        let (b, btx) = engine("B", "conflict-b");
        a.lock().await.test_register_pw("alice", "from-a");
        b.lock().await.test_register_pw("alice", "from-b");

        let (ca, cb) = tokio::io::duplex(64 * 1024);
        let sa = tokio::spawn(session(ca, a.clone(), "s3cret".into(), "A".into(), atx));
        let sb = tokio::spawn(session(cb, b.clone(), "s3cret".into(), "B".into(), btx));

        let mut converged = false;
        for _ in 0..100 {
            let (ha, hb) = (a.lock().await.test_account_hash("alice"), b.lock().await.test_account_hash("alice"));
            if ha.is_some() && ha == hb {
                converged = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        sa.abort();
        sb.abort();
        assert!(converged, "both nodes must agree on a single owner of the contested name");
    }

    // Accounts federate, but channel registrations stay on the node that made
    // them: A registers both; B receives the account and never the channel.
    #[tokio::test]
    async fn channels_stay_node_local() {
        let (a, atx) = engine("A", "local-a");
        let (b, btx) = engine("B", "local-b");
        a.lock().await.test_register("alice");
        a.lock().await.test_register_channel("#secret", "alice");

        let (ca, cb) = tokio::io::duplex(64 * 1024);
        let sa = tokio::spawn(session(ca, a.clone(), "s3cret".into(), "A".into(), atx));
        let sb = tokio::spawn(session(cb, b.clone(), "s3cret".into(), "B".into(), btx));

        // Wait for the account to converge (proves the link works), then assert
        // the channel never crossed it.
        let mut got_account = false;
        for _ in 0..100 {
            if b.lock().await.test_has_account("alice") {
                got_account = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Give any (erroneous) channel replication ample time to arrive too.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let leaked_channel = b.lock().await.test_has_channel("#secret");
        sa.abort();
        sb.abort();
        assert!(got_account, "the account should federate");
        assert!(!leaked_channel, "the channel must NOT federate to a node that never saw it registered");
    }

    // A wrong secret is rejected before any state is exchanged.
    #[tokio::test]
    async fn bad_secret_is_rejected() {
        let (a, atx) = engine("A", "auth-a");
        let (b, btx) = engine("B", "auth-b");
        a.lock().await.test_register("alice");

        let (ca, cb) = tokio::io::duplex(64 * 1024);
        let sa = tokio::spawn(session(ca, a.clone(), "right".into(), "A".into(), atx));
        let sb = tokio::spawn(session(cb, b.clone(), "wrong".into(), "B".into(), btx));

        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            let _ = sa.await;
            let _ = sb.await;
        })
        .await;
        assert!(!b.lock().await.test_has_account("alice"), "no state should cross a bad handshake");
    }

    // Generate a CA + node cert with openssl into a temp dir; None if unavailable.
    fn gen_certs() -> Option<String> {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("echo-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let d = dir.to_str()?.to_string();
        let run = |args: &[&str]| Command::new("openssl").args(args).status().map(|s| s.success()).unwrap_or(false);
        let ok = run(&["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", &format!("{d}/ca.key"), "-out", &format!("{d}/ca.crt"), "-days", "1", "-subj", "/CN=echo-ca"])
            && run(&["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", &format!("{d}/node.key"), "-out", &format!("{d}/node.csr"), "-subj", "/CN=echo"]);
        if !ok {
            return None;
        }
        std::fs::write(format!("{d}/ext"), "subjectAltName=DNS:echo,IP:127.0.0.1\n").ok()?;
        run(&["x509", "-req", "-in", &format!("{d}/node.csr"), "-CA", &format!("{d}/ca.crt"),
            "-CAkey", &format!("{d}/ca.key"), "-CAcreateserial", "-out", &format!("{d}/node.crt"),
            "-days", "1", "-extfile", &format!("{d}/ext")])
            .then_some(d)
    }

    // Convergence over a mutually authenticated TLS link. Skips if openssl is absent.
    #[tokio::test]
    async fn tls_link_converges() {
        let Some(d) = gen_certs() else { return };
        let tls = Tls { cert: format!("{d}/node.crt"), key: format!("{d}/node.key"), ca: format!("{d}/ca.crt") };
        let (acceptor, connector) = build_tls(&tls).expect("tls config");

        let (a, atx) = engine("A", "tls-a");
        let (b, btx) = engine("B", "tls-b");
        a.lock().await.test_register("alice");

        let (sside, cside) = tokio::io::duplex(64 * 1024);
        let name = ServerName::try_from("echo").unwrap();
        let (server, client) = tokio::join!(acceptor.accept(sside), connector.connect(name, cside));
        let sa = tokio::spawn(session(server.expect("tls accept"), a.clone(), "s3cret".into(), "A".into(), atx));
        let sb = tokio::spawn(session(client.expect("tls connect"), b.clone(), "s3cret".into(), "B".into(), btx));

        let mut converged = false;
        for _ in 0..100 {
            if b.lock().await.test_has_account("alice") {
                converged = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        sa.abort();
        sb.abort();
        assert!(converged, "B should converge over the TLS link");
    }
}
