# fedserv

A federated IRC services daemon in Rust. Protocol-agnostic core, InspIRCd link first.

Clean-room — inspired by the ideas behind modern event-log/gossip services, not
derived from any project's source.

## Design

- **`proto/`** — the ircd link layer. A `Protocol` trait maps raw server-to-server
  lines to/from a normalized `NetEvent`/`NetAction` model. The engine never touches
  a raw line, so a new ircd = one new module. InspIRCd is the first.
- **`engine/`** — the services engine: live network `state`, an `EventLog` (every
  persistent change is an `Event`; state is a fold over the log — this is what makes
  replicating across nodes a later addition, not a rewrite), and the `Service` trait.
- **`services/`** — the pseudo-clients: NickServ first, then ChanServ / OperServ / …

## Run

```sh
cp config.example.toml config.toml   # edit uplink + link password
cargo run -- config.toml
```

## Status

Early scaffold: links to an InspIRCd uplink and introduces NickServ. Burst/mode
handling and account persistence are next.
