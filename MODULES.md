# Writing a module

fedserv is a small core plus a set of module crates. A module depends on one
crate — `fedserv-api` — and nothing else: not the engine, not the storage, not
the network code. That crate carries the traits a module implements and the
normalized vocabulary the engine speaks. If your module compiles against
`fedserv-api`, the core can run it.

There are two kinds of module.

- A **service** (a pseudo-client like NickServ) implements `Service`.
- A **protocol** (an ircd link like InspIRCd) implements `Protocol`.

Both live in their own crate under `modules/`. `modules/example/` is a complete,
minimal service to copy from; `modules/protocol/inspircd/` is the reference protocol.

## A service, end to end

**1. The crate.** One dependency:

```toml
# modules/mymod/Cargo.toml
[package]
name = "fedserv-mymod"
version = "0.0.1"
edition = "2021"

[dependencies]
fedserv-api = { path = "../../api" }
```

**2. The service.** A plain struct implementing `Service`:

```rust
use fedserv_api::{NetView, Sender, Service, ServiceCtx, Store};

pub struct MyServ {
    pub uid: String, // assigned by the daemon
}

impl Service for MyServ {
    fn nick(&self) -> &str { "MyServ" }
    fn uid(&self) -> &str { &self.uid }
    fn gecos(&self) -> &str { "My Service" }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, store: &mut dyn Store) {
        // args[0] is the command; reply by pushing onto ctx.
        ctx.notice(&self.uid, from.uid, "hello");
    }
}
```

`on_command` is the whole surface. What you are handed:

- **`from: &Sender`** — who sent it: `uid`, `nick`, and `account` (set when the
  user is logged in).
- **`args: &[&str]`** — the message split on spaces; `args[0]` is the command.
- **`ctx: &mut ServiceCtx`** — the only way to affect anything. You push
  *intents* and the engine performs them: `notice`, `login` / `logout`,
  `channel_mode`, `kick`, `topic`, `invite`, `force_nick`, `send_email`, and the
  deferred `defer_register` / `defer_password` (whose expensive key derivation
  the engine runs off-thread).
- **`net: &dyn NetView`** — a read-only view of the live network: `uid_by_nick`,
  `nick_of`, `host_of`, `account_of`, `is_op`, `channel_members`, `last_seen`.
- **`store: &mut dyn Store`** — the account and channel store. Reads hand back
  plain views (`AccountView`, `ChannelView`, ...) that carry only non-secret
  fields — never a password hash or SCRAM verifier. Writes are ordinary methods
  (`set_email`, `register_channel`, `access_add`, ...). The event log, gossip and
  credential material are not reachable from here, by design.

A change you commit through `store` replicates to every other node the same way
an IRC-originated one does — you do not write any replication code.

**3. Register it.** Add the crate to the workspace and to the daemon:

```toml
# Cargo.toml
[workspace]
members = [..., "modules/mymod"]

[dependencies]
fedserv-mymod = { path = "modules/mymod" }
```

Construct it in `src/main.rs` alongside the others, behind its config name:

```rust
if enabled("mymod") {
    services.push(Box::new(fedserv_mymod::MyServ {
        uid: format!("{}AAAAAD", cfg.server.sid), // a stable, unique suffix
    }));
}
```

**4. Enable it.** In the config:

```toml
[modules]
services = ["nickserv", "chanserv", "mymod"]
```

Omitting `[modules]` starts the full standard suite (every pseudo-client). A
name that isn't built in is ignored.

## A protocol module

A protocol crate implements `Protocol`: it turns raw server-to-server lines into
the normalized `NetEvent`s the engine understands, and turns the engine's
`NetAction`s back into raw lines. The engine never sees a raw line, so supporting
another ircd is one new crate under `modules/protocol/` — see
`modules/protocol/inspircd/`. Wire it in `src/main.rs` where `InspIrcd` is
constructed.

## What the SDK deliberately does not give you

A module cannot reach the append-only log, the gossip layer, the storage engine,
or any credential material. It reads through views and writes through curated
methods. This is the boundary: a module can be wrong without being dangerous.
