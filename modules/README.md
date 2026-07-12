# modules/

The pluggable parts of fedserv: one directory per protocol and per pseudoclient.
The core (engine, event log, gossip, link loop) stays in `../src/`.

```
modules/
  protocol/     ircd link protocols   (inspircd.rs)
  nickserv/     NickServ pseudoclient
  chanserv/     ChanServ pseudoclient
```

`src/main.rs` pulls each in with `#[path = "../modules/..."]`, so crate paths
stay flat (`crate::proto`, `crate::nickserv`, `crate::chanserv`).

## Naming

A service directory holds its pseudoclient file plus, as commands are split out,
one file per command with the service prefix: `ns_register.rs`, `cs_mode.rs`, etc.
