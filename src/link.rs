use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::engine::db::Db;
use crate::engine::Engine;
use crate::proto::{NetAction, Protocol};

// One uplink session: connect, handshake + burst, then translate lines forever.
pub async fn run(mut proto: Box<dyn Protocol>, mut engine: Engine, addr: &str) -> Result<()> {
    let stream = TcpStream::connect(addr).await?;
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

    for line in proto.handshake() {
        send(&mut write, &line).await?;
    }
    for action in engine.startup_actions() {
        for line in proto.serialize(&action) {
            send(&mut write, &line).await?;
        }
    }

    while let Some(line) = lines.next_line().await? {
        tracing::debug!(dir = "<<", %line);
        for event in proto.parse(&line) {
            for action in engine.handle(event) {
                let outs = match action {
                    // Registration: derive the password off the reactor so the
                    // ~1s of key stretching can't stall the link, after a cheap
                    // gate that rejects taken names and rate-limits floods.
                    NetAction::DeferRegister { account, password, email, reply } => {
                        match engine.pre_register_check(&account, &reply) {
                            Some(rejection) => rejection,
                            None => {
                                let iterations = engine.scram_iterations();
                                let creds = tokio::task::spawn_blocking(move || {
                                    Db::derive_credentials(&password, iterations)
                                })
                                .await?;
                                engine.complete_register(&account, creds, email, reply)
                            }
                        }
                    }
                    action => vec![action],
                };
                for act in outs {
                    for out in proto.serialize(&act) {
                        send(&mut write, &out).await?;
                    }
                }
            }
        }
    }

    tracing::warn!("uplink closed the connection");
    Ok(())
}

async fn send(write: &mut (impl AsyncWriteExt + Unpin), line: &str) -> Result<()> {
    tracing::debug!(dir = ">>", %line);
    write.write_all(line.as_bytes()).await?;
    write.write_all(b"\r\n").await?;
    Ok(())
}
