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

use crate::config::{Gossip, Peer};
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
    Digest { versions: HashMap<String, u64> },
    Entry { entry: LogEntry },
}

// Start the listener (if bound) and a dialer per configured peer.
pub async fn run(engine: Shared, cfg: Gossip, peers: Vec<Peer>, origin: String, outbound: Outbound) {
    if let Some(bind) = cfg.bind.clone() {
        tokio::spawn(listen(bind, engine.clone(), cfg.secret.clone(), origin.clone(), outbound.clone()));
    }
    for peer in peers {
        tokio::spawn(dial(peer.addr, engine.clone(), cfg.secret.clone(), origin.clone(), outbound.clone()));
    }
}

async fn listen(bind: String, engine: Shared, secret: String, origin: String, outbound: Outbound) {
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => return tracing::error!(%e, %bind, "gossip bind failed"),
    };
    tracing::info!(%bind, "gossip listening");
    loop {
        if let Ok((stream, addr)) = listener.accept().await {
            tracing::info!(%addr, "gossip peer accepted");
            let (engine, secret, origin, outbound) = (engine.clone(), secret.clone(), origin.clone(), outbound.clone());
            tokio::spawn(async move {
                if let Err(e) = session(stream, engine, secret, origin, outbound).await {
                    tracing::debug!(%e, "gossip session ended");
                }
            });
        }
    }
}

async fn dial(addr: String, engine: Shared, secret: String, origin: String, outbound: Outbound) {
    loop {
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                tracing::info!(%addr, "gossip dialed peer");
                if let Err(e) = session(stream, engine.clone(), secret.clone(), origin.clone(), outbound.clone()).await {
                    tracing::debug!(%e, %addr, "gossip session ended");
                }
            }
            Err(e) => tracing::debug!(%e, %addr, "gossip dial failed"),
        }
        tokio::time::sleep(REDIAL).await;
    }
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
                if send(&tx, &Msg::Digest { versions }).await.is_err() {
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
        let (tx, mut rx) = (tx.clone(), outbound.subscribe());
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(entry) => {
                        if send(&tx, &Msg::Entry { entry }).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue, // digest backstop catches up
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    };

    // Answer a peer's digest with what it lacks; apply the entries it sends us.
    let result = loop {
        match reader.next_line().await {
            Ok(Some(line)) => match serde_json::from_str::<Msg>(&line) {
                Ok(Msg::Digest { versions }) => {
                    let missing = engine.lock().await.gossip_missing(&versions);
                    for entry in missing {
                        let _ = send(&tx, &Msg::Entry { entry }).await;
                    }
                }
                Ok(Msg::Entry { entry }) => {
                    if let Err(e) = engine.lock().await.gossip_ingest(entry) {
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
    use crate::services::nickserv::NickServ;

    fn engine(origin: &str, tag: &str) -> (Shared, Outbound) {
        let path = std::env::temp_dir().join(format!("fedserv-gossip-{tag}.jsonl"));
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
}
