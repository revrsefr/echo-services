# Federation (gossip) — deployment and trust model

Echo runs perfectly as a **single node**; gossip is off unless you configure it.
Only enable it if you actually need more than one node. This document explains
the three deployment tiers and how to run each one safely.

## TL;DR

| You want… | Do this |
|---|---|
| One services node (almost everyone) | Nothing — leave `[gossip]` out of the config. |
| Redundancy/geo, **your** nodes only | `[gossip]` + shared secret + **mutual TLS** + firewall. |
| Link with **another operator's** network | `[gossip.signing]` (per-origin signatures) **and** TLS. |

## How gossip works

Each node owns an append-only event log. The log is split into two scopes:

- **Global** events (account identity: register, password/cert, oper grants,
  suspensions, network bans) — these replicate to peers.
- **Local** events (channel state, moderation queues, news) — these never leave
  the node.

Nodes sync via anti-entropy: each advertises a per-origin version vector, and
peers send whatever Global entries the other is missing. Delivery is idempotent,
so a re-sent entry is dropped, and each account event is an idempotent upsert.

Entries are applied **strictly in order per origin**, tracked by a `(epoch, seq)`
cursor. Each node's seq increments per event; a **compaction** bumps that node's
`epoch` and resets its seq to 0. A receiver therefore distinguishes the two forward
jumps cleanly:

- **A relay gap** (same epoch, a seq ahead of the receiver's) is *deferred* — the
  cursor doesn't advance, so the digest re-requests the missing seqs in order. This
  keeps a 3+-node relay mesh from silently dropping updates.
- **A compaction** (a higher epoch beginning at seq 0) is *adopted* — the receiver
  takes the reset as the new authoritative baseline, so a peer converges across a
  compaction even if it was mid-sync.

## The trust model

Authentication has two independent layers:

1. **The shared secret + TLS** authenticate the *connection* — who may link at
   all.
2. **Per-origin signatures** (optional) authenticate each *record* — which node
   is allowed to assert a given account/oper/ban change.

Without layer 2, trust is **flat**: any node that completes the handshake is
believed completely. That is fine when every node is yours, and unsafe when a
peer is run by someone else (a malicious or compromised peer could forge your
accounts, grant itself oper, or push a network-wide ban). Layer 2 removes that:
a peer can only assert changes to records authored by an origin whose key you
trust, and only if the signature verifies.

## Tier A — single node (default)

Leave `[gossip]` out entirely. Nothing to secure. This is the recommended
posture for any network that doesn't specifically need multiple nodes.

## Tier B — multiple nodes, one operator (HA / geo)

Flat trust is acceptable because every node is yours. Required hardening:

```toml
[gossip]
bind   = "10.0.0.1:7400"      # where this node listens for peers
secret = "<32+ random bytes>" # e.g. `openssl rand -base64 32`

[gossip.tls]                  # MANDATORY across any real network
cert = "/etc/echo/gossip.pem"
key  = "/etc/echo/gossip.key"
ca   = "/etc/echo/peer-ca.pem" # a peer's cert must be signed by this CA

[[peer]]
addr = "10.0.0.2:7400"
name = "node-b"               # must match the peer cert's name
```

Rules:

- **Never run gossip in plaintext over an untrusted network** — the secret and
  all account data are on that wire. Echo warns loudly at startup if TLS is off.
- **Firewall** the `bind` port to your peer nodes' IPs only.
- Use a strong random `secret` and rotate it periodically.
- 3+-node relay meshes converge correctly (out-of-order delivery is deferred and
  re-requested; compaction is handled by the epoch cursor — see "How gossip
  works"). The 2-node path is still the most exercised, so test your topology.

## Tier C — cross-operator federation (per-origin signing)

To link with a network you do **not** fully control, add signatures. Each node
holds an Ed25519 keypair; it signs every Global entry it authors, and verifies
every Global entry it receives against the author's public key. A peer therefore
cannot forge records for an origin whose private key it doesn't hold.

### 1. Generate a keypair on each node

```
echo --gen-gossip-key
# prints:  secret = "<base64>"   public = "<base64>"   (keep the secret private)
```

### 2. Configure signing

```toml
[gossip]
bind   = "..."
secret = "..."
[gossip.tls]
# ... (still required)

[gossip.signing]
# This node's PRIVATE key (from --gen-gossip-key). Keep it secret.
key = "<base64 ed25519 secret key>"

# Every origin whose entries you accept -> its PUBLIC key. Include your OWN
# origin (your server SID) so your entries verify after a restart, plus each
# partner's SID -> their public key.
[gossip.signing.trust]
"1AA" = "<this node's public key>"
"2BB" = "<partner node's public key>"
```

Behavior when `[gossip.signing]` is present:

- Global entries this node authors are signed with `key`.
- An incoming Global entry is **rejected** unless its `origin` is listed in
  `trust` and its signature verifies against that public key.
- Local entries are never signed or gossiped.

### Bootstrapping note

Signing is **greenfield-clean**: a network that enables signing from day one
signs every entry and verifies cleanly. Retrofitting signing onto a node whose
log already contains **unsigned** entries requires re-signing that log first
(unsigned Global entries won't verify at a signing peer). Enable signing before
you first federate, not after.

## What is intentionally out of scope

- A public/anonymous federation directory. Peers are explicit config.
- Byzantine consensus. Signing proves *who authored* a record; it does not
  resolve a node that legitimately signs conflicting records — last-writer-wins
  by `(ts, home)` still applies for account/channel registration conflicts.
