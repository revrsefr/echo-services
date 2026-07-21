# echo

Services for an IRC network, built for InspIRCd, in Rust.

echo runs the pseudo-clients a network's accounts and channels depend on: NickServ, ChanServ, and about a dozen more. It links to an InspIRCd server over the server-to-server protocol and does the job Anope or Atheme would, keeping everything in an append-only event log rather than a database. It's running in production on a live network.

Anope and Atheme both work. echo makes some different bets. State lives in one append-only log instead of a database. The engine handles one event at a time and skips locks entirely. Services are separate crates, walled off from each other and from anything that holds a password.

## Services

All of these start by default. A config section can trim the list.

| Service | What it does |
| --- | --- |
| **NickServ** | Account registration and login by password, TLS certificate, or SASL. Grouped nicks, nick enforcement, auto-join, per-account settings. |
| **ChanServ** | Channel registration, access by XOP tier or granular flags, mode locks, auto-op, kept topics, akick. |
| **MemoServ** | Messages to an account, delivered on the spot or held until the next login. |
| **HostServ** | Virtual hosts, taken self-service from an operator-offered list or assigned directly. |
| **OperServ** | Akills and other X-lines, forbidden nicks and channels, session limits, spam filters, an operator watch list, a searchable incident log. |
| **BotServ** | A bot in a channel with fantasy commands (`!op`, `!kick`), greetings, and keyword responders. |
| **GroupServ** | Account groups whose members inherit the group's channel access. |
| **StatServ** | Network and per-channel activity counters. |
| **ChanFix** | Reop a channel that lost all its ops, from op-time it earned earlier. |
| **HelpServ** | An operator help-desk queue. |
| **InfoServ** | Network bulletins shown on connect and at login. |
| **ReportServ** | User abuse reports that feed the operator audit trail. |
| **GameServ** | A server-side referee for tic-tac-toe, Connect Four, and chess, with a ranked ladder. |
| **DiceServ** | Dice rolls and math for tabletop play. |
| **DictServ** | Dictionary and reference lookups over dict.org (opt-in). |
| **DebugServ** | A live feed of services activity to a staff channel. |

## Running it

```sh
git clone https://git.devtronic.pro/fedserv/echo.git
cd echo
cp config.example.toml config.toml    # set the uplink host, port, and link password
cargo build --release
./target/release/echo config.toml
```

echo dials an InspIRCd uplink. Add a matching `<link>` block on the ircd for the SID and password in your config. Every option is documented inline in `config.example.toml`. The link is plaintext to a loopback ircd by default; it can also run over TLS, pinning the server's public-key (SPKI) fingerprint instead of trusting a CA.

## How it's built

There is no database. Every change is one event appended to a JSON-lines log, and the running state is a fold over that log. Startup replays it; a background compaction rewrites it as a snapshot. The code that applies an event on replay is the same code that applies it live, so what's on disk and what's in memory can't drift apart. A crash loses nothing that was already fsync'd.

The engine is single-threaded on purpose. One event is handled to completion before the next begins, so there are no locks on the shared state and no data races to reason about. The I/O around it (the uplink, the optional gRPC API, email) runs on Tokio.

echo is a Cargo workspace of small crates. The engine is one. Each service is another (`echo-nickserv`, `echo-chanserv`, and so on), and each ircd protocol is another (`echo-inspircd`). A service reaches the engine through exactly two traits, `Store` and `NetView`: it can read and change accounts and channels, but it never touches the log, the replication layer, or a password hash. Adding a service, or support for a different ircd, is one new crate against the `echo-api` SDK.

## Protocol and IRCv3

echo speaks the InspIRCd 4 link protocol and learns the server's modes, extbans, and capabilities from `CAPAB` at link time rather than assuming them. For clients it supports SASL PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, and EXTERNAL (certificate) login, and IRCv3 account registration.

Where the ircd relays them, service replies carry message tags: a reply threads under the command that triggered it (`+draft/reply`), and a notice about a channel names that channel (`+draft/channel-context`). FAIL/WARN/NOTE standard replies give a client a machine-readable outcome instead of parsing prose.

## Coming from Anope

echo imports an Anope 2.x database, folding accounts, channels, access lists, vhosts, and the rest into its own log, so a network can cut over in place.

## Languages

Every user-facing string is an English message id resolved against per-language catalogs. echo ships French, German, Spanish (with a separate Argentine variant), and Portuguese (Portugal and Brazil). A CI check fails the build if a catalog falls out of sync with the code.

## Directory API

echo can expose a gRPC directory of accounts and channels for a website to mirror who is registered, and, with a bearer token, to register or confirm accounts on the server's behalf. It carries identity and metadata only, never credentials, and it stays off unless you configure it. The schema is in `proto/echo.proto`.

## Running more than one node

echo can run as several nodes that replicate their event logs and share one account and channel database. This is optional. A single node is the usual setup and never needs it; the wiki has the details if you do.

## Building

Stable Rust (2021 edition) and Cargo, then `cargo build --release`. echo is checked against a real ircd with the irctest compliance suite.

## Documentation

`config.example.toml` and `proto/echo.proto` are the authoritative references for configuration and the API. The [wiki](https://git.devtronic.pro/fedserv/echo/wiki) covers each service's commands, the module API, and deployment.

## License

AGPL-3.0-or-later; see [LICENSE](LICENSE). Original, clean-room work, not derived from another services project's source.
