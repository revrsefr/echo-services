# fedserv

A federated IRC services daemon in Rust. Protocol-agnostic core, InspIRCd link first.

Clean-room, inspired by the ideas behind modern event-log/gossip services, not
derived from any project's source.

## Design

- **`proto/`** the ircd link layer. A `Protocol` trait maps raw server-to-server
  lines to and from a normalized `NetEvent`/`NetAction` model, so the engine never
  touches a raw line and a new ircd is one new module. InspIRCd is the first.
- **`engine/`** the services engine: live network `state`, the account store, and
  the `Service` trait. The store is event-sourced: every change is an `Event`
  appended to a per-node log, and state is a fold over that log.
- **`gossip/`** node-to-node replication over the logs.
- **`services/`** the pseudo-clients: NickServ first, then ChanServ / OperServ.

## Replication

Each log entry carries an `origin`, a per-origin `seq`, and a Lamport clock. Peers
connect, exchange version vectors, and send each other the entries the other
lacks; a freshly committed entry is also pushed immediately, so a registration
propagates in milliseconds. Ingest is idempotent, so re-delivery and reconnect
after a split both converge. The log is compacted to one entry per account as it
grows. An account registered on any node works on all of them.

## Config

```toml
[uplink]
host = "127.0.0.1"
port = 7000
password = "linkpw"

[server]
name = "services.example"
sid = "42S"

[gossip]                 # omit to run a single, non-replicating node
bind = "0.0.0.0:16700"
secret = "shared-secret"

[gossip.tls]             # omit for a plaintext link
cert = "certs/nodeA.crt"
key  = "certs/nodeA.key"
ca   = "certs/ca.crt"    # a peer must present a certificate signed by this CA

[[peer]]
addr = "nodeB.example:16700"
name = "nodeB"           # TLS name to expect; must match the peer certificate
```

Generate certificates with `scripts/gen-certs.sh`.

## Run

```sh
cp config.example.toml config.toml   # edit uplink + link password
cargo run -- config.toml
```

## Status

Links to an InspIRCd uplink and runs NickServ (REGISTER, IDENTIFY, LOGOUT, CERT,
and SASL PLAIN / SCRAM-SHA-256/512 / EXTERNAL) over an event-sourced account store
replicated between nodes by gossip, with an optional mutually authenticated TLS
peer link. Next: ChanServ.
