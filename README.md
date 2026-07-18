# Echo

A federated IRC services daemon, written in Rust.

Echo runs the services side of an IRC network, the accounts, channels, and operator tooling, as a set of pseudo-clients (NickServ, ChanServ, and the rest) linked to an ircd over its server-to-server protocol. State is an append-only event log folded into memory, and that log gossips between nodes, so several Echo instances on different servers share one account and channel database with no central store.

Clean-room work, informed by the ideas behind modern event-log and gossip services, not derived from any project's source.

## Highlights

- **Federated.** Every change is an event; nodes exchange logs and converge. Account identity is global across the network, while channel state stays with the node that owns it.
- **Event-sourced.** State is a fold over an append-only log. Restart replays it, compaction folds it, replication ships it, all through one code path.
- **Modular.** The core is one crate. Each service and each ircd protocol is a separate crate depending only on the `echo-api` SDK, so a new service or a new ircd is one new crate.
- **Memory-safe.** No manual memory management and no data races, in a domain that has historically shipped both.

## Quick start

```sh
git clone https://git.devtronic.pro/fedserv/echo.git
cd echo
cp config.example.toml config.toml   # set the uplink host and link password
cargo run --release -- config.toml
```

Echo links to an InspIRCd uplink out of the box. Point `config.toml` at your ircd's server port and add a matching `<link>` block on the ircd side. The full reference is on the [Configuration](https://git.devtronic.pro/fedserv/echo/wiki/Configuration) page.

## Services

Every service is a first-class pseudo-client, all started by default.

| Service | Role |
| --- | --- |
| NickServ | account registration, identification, grouped nicks, SASL |
| ChanServ | channel registration, access lists, mode-lock, auto-op |
| BotServ | per-channel bots, fantasy commands, kickers |
| HostServ | virtual hosts, self-serve and operator-approved |
| MemoServ | messages to accounts, delivered online or not |
| OperServ | akills, DEFCON, jupes, session limits, log search |
| StatServ | network and channel statistics |
| GroupServ | account groups whose members inherit channel access |
| ChanFix | reop an opless channel from accumulated op-time |
| HelpServ | a help-desk ticket queue for operators |
| InfoServ | network bulletins shown on connect and login |
| ReportServ | user abuse reports feeding the operator audit trail |
| DiceServ | dice and math for tabletop games |
| DictServ | dictionary, thesaurus and reference lookups (dict.org), opt-in |

## Architecture

Three layers, each a clean boundary:

- **Protocol** turns raw server-to-server lines into a normalized event and action vocabulary. The engine never sees a raw line, so supporting another ircd is one new crate.
- **Engine** holds the live network view and the event-sourced store, and routes messages to services. Services reach it only through the `Store` and `NetView` traits, keeping the log, gossip, and credential material out of a module's reach.
- **Services** are pseudo-clients, one crate each, implementing a single `Service` trait.

The full write-up is in the wiki: [Architecture](https://git.devtronic.pro/fedserv/echo/wiki/Architecture) and [Federation](https://git.devtronic.pro/fedserv/echo/wiki/Federation).

## Documentation

The [wiki](https://git.devtronic.pro/fedserv/echo/wiki) has the detail:

- [Architecture](https://git.devtronic.pro/fedserv/echo/wiki/Architecture) — the engine, the store, the module boundary
- [Federation](https://git.devtronic.pro/fedserv/echo/wiki/Federation) — gossip, the global/local scope model, conflict resolution
- [Services](https://git.devtronic.pro/fedserv/echo/wiki/Services) — every service and its commands
- [Configuration](https://git.devtronic.pro/fedserv/echo/wiki/Configuration) — the `config.toml` reference
- [Directory API](https://git.devtronic.pro/fedserv/echo/wiki/Directory-API) — the gRPC account and channel directory for websites
- [Writing a Module](https://git.devtronic.pro/fedserv/echo/wiki/Writing-a-Module) — build your own service or ircd link
- [Deployment](https://git.devtronic.pro/fedserv/echo/wiki/Deployment) — running Echo in production: install, durability, backups

## Status

Echo links to a live InspIRCd uplink and runs the full service suite over an event-sourced, gossip-replicated store. It supports SASL (PLAIN, SCRAM-SHA-256/512, EXTERNAL), an optional mutually-authenticated TLS peer link, an email subsystem for registration confirmation and password recovery, and a gRPC directory API for websites to mirror accounts and channels. It is verified against a real ircd with the irctest compliance suite.

## License

Not yet declared. This is original, clean-room work; a license will be set before any public release.
