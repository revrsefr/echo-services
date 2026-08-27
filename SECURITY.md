# echo — anti-abuse subsystem

echo has a native, engine-core anti-abuse subsystem (not a pseudo-client). It
watches the connect / nick / join / part / quit / message events echo already
processes as a linked pseudo-server and, per the `[security]` config, **reports**
or (when armed) **enforces** — killing the offender and laying a timed G-line.

The detection heuristics are modelled on Sigyn (the anti-abuse bot that guarded
freenode/Libera); because echo is a linked server it receives these events
first-class and issues bans server-side, so none of that bot's oper-login or
server-notice scraping is needed.

## Posture: report-only by default

- `enabled = false` (default) — the subsystem is completely inert.
- `enabled = true, report_only = true` — detectors run and **announce** to the log
  channel, but never kill or ban. Run here until the thresholds are trusted.
- `enabled = true, report_only = false` — **armed**: a trigger also kills the user
  and lays a `ban_duration`-second G-line.

Every triggered stat is exposed on the metrics endpoint as
`echo_security_<detector>_trips` (e.g. `echo_security_connect_trips`); the counters
are cumulative and survive restarts.

## Arming checklist (`report_only = false`)

Do all of this first, or you risk banning legitimate infrastructure:

1. **`exempt_ips` covers every trusted IP** — loopback is exempt by default; add
   your gateways, bouncers, and any webchat host. An armed connection-flood from an
   un-exempted local IP would G-line it.
2. `exempt_opers` is on (staff are never screened).
3. You have watched `#services` under report-only long enough to trust the
   thresholds and the `announce_*` rate-limit hasn't been drowning out real signal.

## Configuration reference

```toml
[security]
enabled     = true          # run the subsystem
report_only = true          # detect + alert only; do NOT kill/ban
exempt_ips  = ["127.0.0.0/8", "::1"]   # never screened (bare IP or CIDR)
exempt_opers    = true      # never screen network operators
exempt_accounts = false     # a compromised account can still spam
exempt_voice    = true      # for content checks, trust voiced/opped members
announce_permit = 8         # at most N [SECURITY] alerts to the log channel...
announce_life   = 10        # ...per this many seconds (enforcement is NOT throttled)
cascade_permit  = 15        # total triggers within cascade_life that raises a...
cascade_life    = 30        # ..."consider raising DEFCON" one-shot alert

# Connection screening (per-IP and per-/24//64-range flood).
[security.connect]
enabled      = true
flood_permit = 6            # > N connections from one IP within flood_life...
flood_life   = 10
range_permit = 12           # ...or > N across its /24 (v4) / /64 (v6) within range_life
range_life   = 20
ban_duration = 3600         # G-line seconds when armed (0 = kill only)

# Operator connection-pattern DB (globs by default, regex opt-in), matched against
# nick!ident@host(#gecos) on connect. Repeat the block per pattern.
[[security.pattern]]
mask   = "*!*@*.known-botnet.example"
field  = "mask"             # mask | full | nick | ident | host | gecos
regex  = false
reason = "known botnet host"
ban    = 86400

# Behavioural heuristics on join/part/quit/nick.
[security.behavior]
enabled          = true
nick_permit      = 5        # nick-change flood (per user / nick_life s)
nick_life        = 30
cycle_permit     = 6        # join/part cycling (parts per user / cycle_life s)
cycle_life       = 20
joinpart_permit  = 4        # join-then-quick-part, within joinpart_grace s of the join
joinpart_life    = 30
joinpart_grace   = 10
massjoin_permit  = 8        # joins to one channel from a single /24//64 (clone raid)
massjoin_life    = 8
quit_permit      = 4        # broken-client quit flood (per IP), reason matching below
quit_life        = 30
quit_reasons     = ["Excess Flood", "Max SendQ exceeded"]
ban_duration     = 3600

# Content heuristics on channel messages echo sees (a bot is present) — the
# additive ones the ChanServ kickers don't do.
[security.content]
enabled          = true
highlight_nicks  = 6        # a line pinging >= N distinct members = mass-ping...
highlight_min_len = 3       # ...counting only nicks at least this long
highlight_permit = 1        # such messages per user / highlight_life s
highlight_life   = 15
badunicode_score = 0.30     # combining-mark (zalgo) + zero-width fraction threshold
badunicode_min   = 8        # only score messages at least this long
badunicode_permit = 1
badunicode_life  = 20
repeat_min       = 10       # copy-paste "repeat wave": same normalised line...
repeat_permit    = 5        # ...more than N times in a channel / repeat_life s
repeat_life      = 20
ban_duration     = 3600
```

Content caps/flood/repeat/badwords per bot-channel are already handled by the
ChanServ kickers; network-wide content regex is OperServ `SPAMFILTER` (→ the ircd's
`m_filter`). The security subsystem adds only what those don't cover.

## Registration MX-blacklist

Stops disposable-email signup abuse by blocking the mail infrastructure rather than
the (endless, rotating) domains: it resolves the registration email's domain MX
records (and, if IP rules are set, their A/AAAA) with a native DNS resolver and
rejects the signup when a mail server matches. Off by default.

```toml
[mxbl]
enabled    = true
resolver   = ""             # "ip[:port]"; empty = first nameserver in /etc/resolv.conf
mx_globs   = ["*.disposable-mail.example"]   # MX hostname globs to block
ip_cidrs   = ["203.0.113.0/24"]              # MX-server IP CIDRs (extra A/AAAA lookup)
timeout_ms = 2000
```

A blocked signup is rejected before the account row is created (and before any
verification email is sent), with the same outcome as an operator `FORBID EMAIL`.
The DNS lookup runs off the engine lock, so it never stalls services. Connection-
time DNSBL is handled by the ircd, not here.
