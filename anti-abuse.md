# echo — native anti-abuse

echo has a native anti-abuse subsystem built into the engine core (**not** a service
pseudo-client). It watches the connect / nick / join / part / quit / message events
echo already processes as a linked pseudo-server and, when armed, enforces bans
server-side. The detection algorithms are modelled on Sigyn/ozone (the bot that
guarded freenode/Libera), but because echo *is* a linked server it receives those
events first-class and issues bans over S2S — none of that bot's oper-login,
snote-scraping or IP-resolution plumbing is needed.

It ships **inert** (`enabled = false`). Turned on, it defaults to **report-only**:
every trigger is announced to the log channel but nothing is killed or banned, so
thresholds can be trusted before the engine is armed.

---

## Enforcement model

```
enabled = false                → the whole subsystem does nothing (default)
enabled = true, report_only = true   → detect + alert only (never kill/ban)  ← start here
enabled = true, report_only = false  → armed: also KILL + lay a timed G-line
```

A trigger always writes a `[SECURITY]` line to the log channel (rate-limited, see
`announce_*`). When **armed**, it additionally `KILL`s the offender and adds a
`ban_duration`-second G-line on the offending IP/range (or drops it to a kill-only
action when `ban_duration = 0`).

**Exemptions** (checked before any detector runs):

- `exempt_ips` — IPs/CIDRs never screened. **Defaults to loopback** so an armed
  connection-flood can't G-line `127.0.0.1` and cut off local bots/services. Widen
  it to cover every trusted infra IP (gateways, bouncers, web-chat) before arming.
- `exempt_opers` (default on) — network operators are never screened.
- `exempt_accounts` (default off) — logged-in accounts; off because a compromised
  account can still spam.
- `exempt_voice` (default on) — for *content* checks, voiced/opped channel members
  are trusted.

---

## Detectors

| Group | Detector | Fires on | Keyed by |
|---|---|---|---|
| Connection | connection flood | connect | IP, and its /24 (v4) / /64 (v6) |
| Connection | pattern DB | connect | `nick!ident@host(#gecos)` glob/regex |
| Behavioural | nick-change flood | NICK | uid |
| Behavioural | join/part cycle | PART | uid |
| Behavioural | join-spam-part | JOIN→PART | uid (quick part after join) |
| Behavioural | mass-join | JOIN | channel × /24-//64 (clone raid) |
| Behavioural | broken-client quit-flood | QUIT | IP (reason contains a marker) |
| Content¹ | highlight-spam | channel message | uid (distinct members pinged) |
| Content¹ | bad-unicode | channel message | uid (zalgo / zero-width fraction) |
| Content¹ | repeat-wave | channel message | channel × line-hash (copy-paste spam) |
| Behavioural | channel-crawl | JOIN | uid (join rate across many channels) |
| Auth | login brute-force | failed IDENTIFY/SASL | IP |
| Auth | registration flood | REGISTER | IP |
| Auth | ban-evasion | account login | account (re-kill if recently security-banned) |

The behavioural/content detectors are **suppressed for `netsplit_grace` seconds after any
server split or link** — a netsplit rejoin re-joins/re-nicks everyone at once and would
otherwise trip mass-join/nick/quit in a false-positive storm. This is what makes arming safe.

¹ Content detectors only see channels where an echo bot is present (the same limit
as the kickers). For *network-wide* content filtering use OperServ SPAMFILTER
(pushed to the ircd's `m_filter`); the repeat-wave alert surfaces the offending line
as a ready-made filter pattern. Connection-time DNSBL is the ircd's job, not echo's.

Every detector uses one sliding-window counter engine: "more than *permit* events
keyed by *K* within *life* seconds → trip". Windows self-expire; a periodic GC keeps
the key set bounded.

---

## Configuration

All keys have safe defaults — set only what you want to change. Reload with OperServ
REHASH (counters and in-flight state survive; thresholds and patterns re-apply).

### `[security]`

```toml
[security]
enabled       = true      # false (default) = subsystem off
report_only   = true      # true (default when enabled) = alert only, never enforce
exempt_ips    = ["127.0.0.0/8", "::1"]   # default; add trusted infra before arming
exempt_opers  = true      # never screen network operators
exempt_accounts = false   # screen logged-in accounts too (compromised = spam)
exempt_voice  = true      # content: skip voiced/opped members
announce_permit = 8       # at most N [SECURITY] alerts to the log channel...
announce_life   = 10      # ...per this many seconds (a flood can't spam it)
cascade_permit  = 15      # > N total triggers within cascade_life...
cascade_life    = 30      # ...raises a one-shot "consider raising DEFCON" alert
```

### `[security.connect]` — connection screening

```toml
[security.connect]
enabled      = true
flood_permit = 6    # > N connections from one IP within flood_life
flood_life   = 10
range_permit = 12   # ...or > N across its /24 (v4) / /64 (v6) within range_life
range_life   = 20
ban_duration = 3600 # G-line seconds when armed (0 = kill the connection only)
```

### `[[security.pattern]]` — connection pattern DB (repeatable)

```toml
[[security.pattern]]
mask   = "*!*@*.knownbad.example"   # glob (default) or regex
field  = "mask"    # mask (nick!ident@host, default) | full (…#gecos) | nick | ident | host | gecos
regex  = false     # true = treat `mask` as a case-insensitive regex
reason = "known spam host"
ban    = 86400     # G-line seconds when armed (0 = kill only)
```

### `[security.behavior]` — behavioural heuristics

```toml
[security.behavior]
enabled         = true
nick_permit     = 5     # nick-change flood: > N changes...
nick_life       = 30    # ...within this many seconds
cycle_permit    = 6     # join/part cycling
cycle_life      = 20
joinpart_permit = 4     # join-spam-part (a quick part after joining)
joinpart_life   = 30
joinpart_grace  = 10    # "quick" = parted within this many seconds of joining
massjoin_permit = 8     # per channel × /24-//64 (clone raid)
massjoin_life   = 8
quit_permit     = 4     # broken-client quit flood, from one IP
quit_life       = 30
quit_reasons    = ["Excess Flood", "Max SendQ exceeded"]   # markers (case-insensitive substring)
ban_duration    = 3600
```

### `[security.content]` — channel content (bot channels)

```toml
[security.content]
enabled           = true
highlight_nicks   = 6     # a line pinging >= N distinct members...
highlight_min_len = 3     # ...each nick at least this many chars
highlight_permit  = 1     # more than N such lines from one user...
highlight_life    = 15    # ...within this window
badunicode_score  = 0.30  # combining-mark/zalgo + invisible fraction that flags a line
badunicode_min    = 8     # minimum length to consider
badunicode_permit = 1
badunicode_life   = 20
repeat_min        = 10    # min length of a line to track for repeat-wave
repeat_permit     = 5     # same line > N times in a channel...
repeat_life       = 20    # ...within this window
ban_duration      = 3600
```

### `[security.auth]` — login/registration abuse

echo is NickServ and a linked server, so it sees failed logins, registrations, and
account logins first-class — no oper-snote scraping.

```toml
[security.auth]
enabled         = true
fail_permit     = 8       # > N failed password logins from one IP within fail_life s → ban
fail_life       = 60
register_permit = 3       # > N REGISTERs from one IP within register_life s → reject
register_life   = 300
evade_ttl       = 172800  # remember a security-banned account this long; re-kill on re-login
ban_duration    = 3600
```

Also on `[security]`: `netsplit_grace = 60` (suppression window after a split/link), and on
`[security.behavior]`: `crawl_permit = 12` / `crawl_life = 15` (the channel-crawl detector).

### `[mxbl]` — registration MX-blacklist

Rejects a signup when the **email domain's mail servers** are blocklisted — the
stable way to stop disposable-email abuse (spammers rotate domains but reuse a small
set of mail servers). Resolved with echo's native async DNS, off the engine lock;
the account is never created. Default off.

```toml
[mxbl]
enabled    = true
resolver   = ""    # "ip[:port]"; empty = first nameserver in /etc/resolv.conf
mx_globs   = ["*.disposable-mail.example"]   # MX hostname globs to block
ip_cidrs   = ["203.0.113.0/24"]              # MX-server IP CIDRs (costs an extra A/AAAA lookup)
timeout_ms = 2000
```

To persist a specific bad address (skip the lookup next time), an operator can also
`OperServ FORBID EMAIL <glob> <reason>` — checked in the same register path.

---

## Arming: report-only → enforcing

1. Run `report_only = true` and watch the `[SECURITY]` lines in the log channel for
   a while — confirm the thresholds only trip on real abuse.
2. Make sure `exempt_ips` covers **every** trusted infrastructure IP (loopback is
   covered by default; add gateways, bouncers, web-chat, other services hosts).
3. Set `report_only = false`. Keep an eye on the log channel; the `announce_*`
   limit stops a flood from drowning it, and an "ABUSE CASCADE" line recommends
   DEFCON if triggers spike.

DEFCON is **not** auto-raised — echo's existing `defcon(1)` lockdown handles the
severe case, and auto-escalation is risky; the cascade alert recommends, the
operator acts.

---

## Observing it

- **Metrics** (Prometheus, the `[health]` endpoint): each trip bumps a counter
  surfaced as `echo_security_<detector>_trips` — e.g. `echo_security_connect_trips`,
  `echo_security_nick_trips`, `echo_security_massjoin_trips`,
  `echo_security_highlight_trips`, `echo_security_pattern_hits`. These are cumulative
  and **persist across restarts** — compare a delta, not absolute presence.
- **Log channel**: `[SECURITY]` lines describe each trigger (`report-only` vs
  `acting on`), the offender, and why.

---

## Design notes

- **Engine-core, not a module.** Detectors are called directly at the event sites in
  `Engine::handle` (like the kickers), not fanned to a pseudo-client — the engine
  already has every event.
- **Report-only, exemptions, rate-limit first.** The subsystem was built so that
  arming is safe: loopback/oper exemptions, an announce rate-limit, and no
  auto-DEFCON.
- **Mining, not auto-filtering.** The repeat-wave detector *surfaces* a mined spam
  line as a suggested filter rather than auto-pushing it network-wide — that pipe
  (m_filter) is owned by OperServ SPAMFILTER, and auto-pushing without review is
  risky.
- **No new i18n.** The `[SECURITY]` feed is an operator audit log (English, like the
  rest of the DebugServ feed); the MX-reject reuses NickServ's existing localized
  "forbidden email" reply. There are no new end-user-facing strings.
