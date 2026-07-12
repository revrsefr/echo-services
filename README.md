# fedserv

A federated IRC services daemon in Rust. Protocol-agnostic core, InspIRCd link first.

Clean-room, inspired by the ideas behind modern event-log/gossip services, not
derived from any project's source.

## Design

The core lives in `src/`; the pluggable parts live in `modules/` (see
`modules/README.md`).

- **`src/engine/`** the services engine: live network `state`, the account store,
  and the `Service` trait. The store is event-sourced: every change is an `Event`
  appended to a per-node log, and state is a fold over that log.
- **`src/gossip.rs`** node-to-node replication over the logs.
- **`modules/protocol/`** the ircd link layer. A `Protocol` trait maps raw
  server-to-server lines to and from a normalized `NetEvent`/`NetAction` model, so
  the engine never touches a raw line and a new ircd is one new module. InspIRCd is
  the first.
- **`modules/nickserv/`, `modules/chanserv/`** the pseudo-clients, one directory
  each. OperServ and others follow the same shape.

## Replication

Each log entry carries an `origin`, a per-origin `seq`, and a Lamport clock. Peers
connect, exchange version vectors, and send each other the entries the other
lacks; a freshly committed entry is also pushed immediately, so a registration
propagates in milliseconds. Ingest is idempotent, so re-delivery and reconnect
after a split both converge. The log is compacted to one entry per account as it
grows. An account registered on any node works on all of them.

## Directory API (gRPC)

**`src/grpc.rs`** exposes the account/channel directory over gRPC (see
`proto/fedserv.proto`) so a website can mirror it without touching IRC: a
one-shot `Snapshot` for the initial load, then `Subscribe` for a live stream of
every change from that point on. It subscribes to the same committed-entry
channel gossip does, so a change reaches a subscriber in the same push, no
polling. Deliberately excludes anything credential-shaped (password hashes,
SCRAM verifiers, cert fingerprints) and the finer channel-ops-list events
(access/akick/mlock/entrymsg) — identity and metadata only. Bearer-token
authenticated, optional server TLS. Omit `[grpc]` in config.toml to run
without it.

The same port also serves **`Accounts`**, the write side: `Register`,
`Authenticate`, `SetPassword`, `SetEmail`, `Confirm`, `Drop`, `ForceLogout`,
`GroupNick`, `UngroupNick` — a trusted caller (e.g. a website's own backend,
already having done its own login/session check) managing accounts the same
way an IRC user does through NickServ, minus the command syntax. The bearer
token *is* the authorization: unlike the NickServ commands these mirror, most
calls do not re-check the account's own password (an admin-level override, the
same trust model a JSON-RPC integration to another services package would
use) — `Register` and `Authenticate` are the two exceptions, since the
password is the actual input there. A write committed this way replicates to
every other fedserv node exactly like an IRC-originated one does — gossip
doesn't know or care where it came from.

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
and SASL PLAIN / SCRAM-SHA-256/512 / EXTERNAL) and ChanServ over an event-sourced
account store replicated between nodes by gossip, with an optional mutually
authenticated TLS peer link, plus a gRPC directory API for websites to mirror
the account/channel directory (bearer-token authenticated, optional TLS).
