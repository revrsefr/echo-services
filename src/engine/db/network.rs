use super::*;

impl Db {
    /// Add (or refresh) a `kind` network ban. Returns whether it was newly added.
    pub fn akill_add(&mut self, kind: XlineKind, mask: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError> {
        // Storage/gossip keep the ircd's line token; the API is typed.
        let wire = kind.wire();
        // One timestamp for the logged event AND the in-memory record: two `now()`
        // calls could straddle a second, so a peer replaying the event would store a
        // different ts than us and gossip state would never converge.
        let ts = now();
        let same = |a: &Akill| a.kind == wire && a.mask.eq_ignore_ascii_case(mask);
        let fresh = !self.net.akills.iter().any(|a| same(a) && a.expires.is_none_or(|e| e > ts));
        self.log
            .append(Event::AkillAdded { kind: wire.to_string(), mask: mask.to_string(), setter: setter.to_string(), reason: reason.to_string(), ts, expires })
            .map_err(|_| RegError::Internal)?;
        self.net.akills.retain(|a| !same(a));
        self.net.akills.push(Akill { kind: wire.to_string(), mask: mask.to_string(), setter: setter.to_string(), reason: reason.to_string(), ts, expires });
        Ok(fresh)
    }

    /// Lift a `kind` network ban. Returns whether a live one was removed.
    pub fn akill_del(&mut self, kind: XlineKind, mask: &str) -> Result<bool, RegError> {
        let wire = kind.wire();
        let same = |a: &Akill| a.kind == wire && a.mask.eq_ignore_ascii_case(mask);
        let existed = self.net.akills.iter().any(|a| same(a) && a.expires.is_none_or(|e| e > now()));
        if !existed {
            return Ok(false);
        }
        self.log.append(Event::AkillRemoved { kind: wire.to_string(), mask: mask.to_string() }).map_err(|_| RegError::Internal)?;
        self.net.akills.retain(|a| !same(a));
        Ok(true)
    }

    /// The live network bans (expired ones hidden lazily), oldest first. A stored
    /// kind we don't model (peer-gossiped) is skipped from the typed view.
    pub fn akills(&self) -> Vec<AkillView> {
        let now = now();
        self.net.akills
            .iter()
            .filter(|a| a.expires.is_none_or(|e| e > now))
            .filter_map(|a| {
                XlineKind::from_wire(&a.kind).map(|kind| AkillView { kind, mask: a.mask.clone(), setter: a.setter.clone(), reason: a.reason.clone(), ts: a.ts, expires: a.expires })
            })
            .collect()
    }

    /// Add (or refresh) a spam filter. Returns whether it was newly added.
    pub fn filter_add(&mut self, pattern: &str, action: &str, flags: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError> {
        // One timestamp for the event and the in-memory record (see akill_add).
        let ts = now();
        let same = |f: &Filter| f.pattern.eq_ignore_ascii_case(pattern);
        let fresh = !self.net.filters.iter().any(|f| same(f) && f.expires.is_none_or(|e| e > ts));
        self.log
            .append(Event::FilterAdded { pattern: pattern.to_string(), action: action.to_string(), flags: flags.to_string(), reason: reason.to_string(), setter: setter.to_string(), ts, expires })
            .map_err(|_| RegError::Internal)?;
        self.net.filters.retain(|f| !same(f));
        self.net.filters.push(Filter { pattern: pattern.to_string(), action: action.to_string(), flags: flags.to_string(), reason: reason.to_string(), setter: setter.to_string(), ts, expires });
        Ok(fresh)
    }

    /// Remove a spam filter by pattern. Returns whether a live one existed.
    pub fn filter_del(&mut self, pattern: &str) -> Result<bool, RegError> {
        let same = |f: &Filter| f.pattern.eq_ignore_ascii_case(pattern);
        let existed = self.net.filters.iter().any(|f| same(f) && f.expires.is_none_or(|e| e > now()));
        if !existed {
            return Ok(false);
        }
        self.log.append(Event::FilterRemoved { pattern: pattern.to_string() }).map_err(|_| RegError::Internal)?;
        self.net.filters.retain(|f| !same(f));
        Ok(true)
    }

    /// The live spam filters (expired ones hidden lazily), oldest first.
    pub fn filters(&self) -> Vec<echo_api::FilterView> {
        let now = now();
        self.net.filters
            .iter()
            .filter(|f| f.expires.is_none_or(|e| e > now))
            .map(|f| echo_api::FilterView { pattern: f.pattern.clone(), action: f.action.clone(), flags: f.flags.clone(), reason: f.reason.clone(), setter: f.setter.clone(), ts: f.ts, expires: f.expires })
            .collect()
    }

    /// Add a registration ban of `kind` ("NICK"/"CHAN"/"EMAIL") for `mask`.
    /// Returns whether it was new.
    pub fn forbid_add(&mut self, kind: ForbidKind, mask: &str, setter: &str, reason: &str) -> Result<bool, RegError> {
        // The store persists/gossips the wire token; the API is typed.
        let wire = kind.wire();
        // One timestamp for the event AND the in-memory record (see akill_add).
        let ts = now();
        let same = |f: &Forbid| f.kind == wire && f.mask.eq_ignore_ascii_case(mask);
        let fresh = !self.net.forbids.iter().any(same);
        self.log
            .append(Event::ForbidAdded { kind: wire.to_string(), mask: mask.to_string(), setter: setter.to_string(), reason: reason.to_string(), ts })
            .map_err(|_| RegError::Internal)?;
        self.net.forbids.retain(|f| !same(f));
        self.net.forbids.push(Forbid { kind: wire.to_string(), mask: mask.to_string(), setter: setter.to_string(), reason: reason.to_string(), ts });
        Ok(fresh)
    }

    /// Remove a registration ban of `kind` for `mask`. Returns whether one existed.
    pub fn forbid_del(&mut self, kind: ForbidKind, mask: &str) -> Result<bool, RegError> {
        let wire = kind.wire();
        let same = |f: &Forbid| f.kind == wire && f.mask.eq_ignore_ascii_case(mask);
        if !self.net.forbids.iter().any(same) {
            return Ok(false);
        }
        self.log.append(Event::ForbidRemoved { kind: wire.to_string(), mask: mask.to_string() }).map_err(|_| RegError::Internal)?;
        self.net.forbids.retain(|f| !same(f));
        Ok(true)
    }

    /// All registration bans, oldest first. A stored kind that no longer parses
    /// (corrupt/old log) is skipped rather than shown.
    pub fn forbids(&self) -> Vec<ForbidView> {
        self.net.forbids
            .iter()
            .filter_map(|f| {
                ForbidKind::from_name(&f.kind).map(|kind| ForbidView { kind, mask: f.mask.clone(), setter: f.setter.clone(), reason: f.reason.clone(), ts: f.ts })
            })
            .collect()
    }

    /// The reason `name` is forbidden for `kind` registration (glob), if it is.
    pub fn is_forbidden(&self, kind: ForbidKind, name: &str) -> Option<String> {
        let wire = kind.wire();
        self.net.forbids
            .iter()
            .find(|f| f.kind == wire && glob_match(&f.mask, name))
            .map(|f| f.reason.clone())
    }

    /// Add (or replace) an OperServ NOTIFY watch. Returns whether it was new.
    pub fn notify_add(&mut self, mask: &str, flags: &str, reason: &str, setter: &str, expires: Option<u64>) -> Result<bool, RegError> {
        let ts = now();
        let same = |n: &Notify| n.mask.eq_ignore_ascii_case(mask);
        let fresh = !self.net.notifies.iter().any(same);
        self.log
            .append(Event::NotifyAdded { mask: mask.to_string(), flags: flags.to_string(), reason: reason.to_string(), setter: setter.to_string(), ts, expires })
            .map_err(|_| RegError::Internal)?;
        self.net.notifies.retain(|n| !same(n));
        self.net.notifies.push(Notify { mask: mask.to_string(), flags: flags.to_string(), reason: reason.to_string(), setter: setter.to_string(), ts, expires });
        Ok(fresh)
    }

    /// Remove a NOTIFY watch by exact mask. Returns whether one existed.
    pub fn notify_del(&mut self, mask: &str) -> Result<bool, RegError> {
        let same = |n: &Notify| n.mask.eq_ignore_ascii_case(mask);
        if !self.net.notifies.iter().any(same) {
            return Ok(false);
        }
        self.log.append(Event::NotifyRemoved { mask: mask.to_string() }).map_err(|_| RegError::Internal)?;
        self.net.notifies.retain(|n| !same(n));
        Ok(true)
    }

    /// Drop every NOTIFY watch. Returns how many were removed. One event per entry
    /// so a peer replaying the log folds to the same empty state.
    pub fn notify_clear(&mut self) -> Result<usize, RegError> {
        let masks: Vec<String> = self.net.notifies.iter().map(|n| n.mask.clone()).collect();
        let count = masks.len();
        for mask in masks {
            self.log.append(Event::NotifyRemoved { mask }).map_err(|_| RegError::Internal)?;
        }
        self.net.notifies.clear();
        Ok(count)
    }

    /// All live (unexpired) NOTIFY watches, oldest first.
    pub fn notifies(&self) -> Vec<NotifyView> {
        let now = now();
        self.net.notifies
            .iter()
            .filter(|n| n.expires.is_none_or(|e| e > now))
            .map(|n| NotifyView { mask: n.mask.clone(), flags: n.flags.clone(), reason: n.reason.clone(), setter: n.setter.clone(), ts: n.ts, expires: n.expires })
            .collect()
    }

    /// Whether any live watch exists — a cheap gate so the engine can skip the
    /// per-event identity lookup when the list is empty.
    pub fn any_notifies(&self) -> bool {
        let now = now();
        self.net.notifies.iter().any(|n| n.expires.is_none_or(|e| e > now))
    }

    /// Union of the flag letters of every live watch matching this user and/or
    /// channel: a `#`/`&` mask tests the channel name, any other tests the user's
    /// identity. The engine tests the result for a given event's letter.
    pub fn notify_flags(&self, target: Option<&echo_api::BanTarget>, chan: Option<&str>) -> String {
        // Exclusions come first, same mask grammar as a watch: a `#channel` mask
        // mutes events in that channel, any other mask mutes a user (e.g. `*/*` for
        // PyLink relay clients). A match means the event never reaches the feed.
        let excluded = self.notify_exclude.iter().any(|m| {
            if let Some(srv) = m.strip_prefix("server:").or_else(|| m.strip_prefix("via:")) {
                // `server:<glob>` mutes everyone on a matching server — the only handle
                // on a relay whose users carry clean nicks (no /network suffix).
                target.is_some_and(|t| glob_match(&srv.to_ascii_lowercase(), &t.server.to_ascii_lowercase()))
            } else if m.starts_with('#') || m.starts_with('&') {
                chan.is_some_and(|c| glob_match(m, c))
            } else {
                target.is_some_and(|t| echo_api::akick_matches(m, t) || (!m.contains(['@', '!']) && glob_match(m, t.nick)))
            }
        });
        if excluded {
            return String::new();
        }
        let now = now();
        let mut flags = String::new();
        for n in self.net.notifies.iter().filter(|n| n.expires.is_none_or(|e| e > now)) {
            let hit = if n.mask.starts_with('#') || n.mask.starts_with('&') {
                chan.is_some_and(|c| glob_match(&n.mask, c))
            } else {
                // Host/extban masks go through the ban matcher; a bare nick glob
                // (no '@'/'!') also matches the nick, so `baddie*` works too.
                target.is_some_and(|t| {
                    echo_api::akick_matches(&n.mask, t)
                        || (!n.mask.contains(['@', '!']) && glob_match(&n.mask, t.nick))
                })
            };
            if hit {
                flags.push_str(&n.flags);
            }
        }
        flags
    }

    /// Add (or replace) a session-limit exception for an IP-mask.
    pub fn session_except_add(&mut self, mask: &str, limit: u32, reason: &str) {
        let _ = self.log.append(Event::SessionExceptionAdded { mask: mask.to_string(), limit, reason: reason.to_string() });
        self.net.sess_exceptions.retain(|e| !e.mask.eq_ignore_ascii_case(mask));
        self.net.sess_exceptions.push(SessionException { mask: mask.to_string(), limit, reason: reason.to_string() });
    }

    /// Remove a session-limit exception. Returns whether one existed.
    pub fn session_except_del(&mut self, mask: &str) -> bool {
        let existed = self.net.sess_exceptions.iter().any(|e| e.mask.eq_ignore_ascii_case(mask));
        if existed {
            let _ = self.log.append(Event::SessionExceptionRemoved { mask: mask.to_string() });
            self.net.sess_exceptions.retain(|e| !e.mask.eq_ignore_ascii_case(mask));
        }
        existed
    }

    /// The session-limit exceptions, as (mask, limit, reason).
    pub fn session_exceptions(&self) -> Vec<(String, u32, String)> {
        self.net.sess_exceptions.iter().map(|e| (e.mask.clone(), e.limit, e.reason.clone())).collect()
    }

    /// The session allowance for `ip` from any matching exception (the most
    /// permissive wins), or None if none matches. A limit of 0 means unlimited.
    pub fn session_exception_for(&self, ip: &str) -> Option<u32> {
        self.net
            .sess_exceptions
            .iter()
            .filter(|e| glob_match(&e.mask.to_ascii_lowercase(), &ip.to_ascii_lowercase()))
            .map(|e| e.limit)
            .max_by_key(|&l| if l == 0 { u32::MAX } else { l })
    }

    /// Grant runtime operator privileges to an account (replaces any existing),
    /// optionally expiring at an absolute unix time.
    pub fn oper_grant(&mut self, account: &str, privs: Vec<String>, expires: Option<u64>) {
        let _ = self.log.append(Event::OperGranted { account: account.to_string(), privs: privs.clone(), expires });
        self.net.opers.insert(key(account), OperGrant { privs, expires });
    }

    /// Revoke a runtime operator grant. Returns whether one existed.
    pub fn oper_revoke(&mut self, account: &str) -> bool {
        if !self.net.opers.contains_key(&key(account)) {
            return false;
        }
        let _ = self.log.append(Event::OperRevoked { account: account.to_string() });
        self.net.opers.remove(&key(account));
        true
    }

    /// The live runtime operator grants, as (account, privilege-names, expiry);
    /// expired ones are hidden.
    pub fn opers_list(&self) -> Vec<(String, Vec<String>, Option<u64>)> {
        let now = now();
        self.net
            .opers
            .iter()
            .filter(|(_, g)| g.expires.is_none_or(|e| e > now))
            .map(|(a, g)| (a.clone(), g.privs.clone(), g.expires))
            .collect()
    }

    /// The runtime privileges granted to an account as of `now`, if the grant is
    /// present and unexpired (config opers are merged in separately by the engine).
    pub fn oper_privs_of(&self, account: &str, now: u64) -> Option<Privs> {
        self.net
            .opers
            .get(&key(account))
            .filter(|g| g.expires.is_none_or(|e| e > now))
            .map(|g| Privs::from_names(&g.privs))
    }

    /// Add a news item of `kind`. Returns its stable id.
    pub fn news_add(&mut self, kind: NewsKind, text: &str, setter: &str) -> u64 {
        let id = self.net.news_seq;
        let ts = now();
        let wire = kind.wire();
        let _ = self.log.append(Event::NewsAdded { id, kind: wire.to_string(), text: text.to_string(), setter: setter.to_string(), ts });
        self.net.news_seq = id + 1;
        self.net.news.push(News { id, kind: wire.to_string(), text: text.to_string(), setter: setter.to_string(), ts });
        id
    }

    /// Delete a news item by id. Returns whether one existed.
    pub fn news_del(&mut self, id: u64) -> bool {
        let existed = self.net.news.iter().any(|n| n.id == id);
        if existed {
            let _ = self.log.append(Event::NewsDeleted { id });
            self.net.news.retain(|n| n.id != id);
        }
        existed
    }

    /// The news items of `kind`, oldest first.
    pub fn news(&self, kind: NewsKind) -> Vec<NewsView> {
        let wire = kind.wire();
        self.net
            .news
            .iter()
            .filter(|n| n.kind == wire)
            .map(|n| NewsView { id: n.id, text: n.text.clone(), setter: n.setter.clone(), ts: n.ts })
            .collect()
    }

    /// Whether account identity is owned by an external authority.
    pub fn external_accounts(&self) -> bool {
        self.external_accounts
    }

    /// Set external-account mode (from config, at startup).
    pub fn set_external_accounts(&mut self, on: bool) {
        self.external_accounts = on;
    }

    /// The network defence level (5 = normal, 1 = full lockdown).
    pub fn defcon(&self) -> u8 {
        self.defcon
    }

    /// Set the defence level, clamped to 1..=5.
    pub fn set_defcon(&mut self, level: u8) {
        self.defcon = level.clamp(1, 5);
    }

    /// Whether the services are in operator read-only lockdown.
    pub fn readonly(&self) -> bool {
        self.log.readonly
    }

    /// Enter or leave read-only lockdown: while on, locally-authored writes are
    /// refused. Ephemeral (never persisted); gossip ingestion is unaffected.
    pub fn set_readonly(&mut self, on: bool) {
        self.log.readonly = on;
    }

    /// Whether new nick/account registrations are frozen (defcon 3 or lower).
    pub fn registrations_frozen(&self) -> bool {
        self.defcon <= 3
    }

    /// Whether new channel registrations are frozen (defcon 4 or lower).
    pub fn channel_regs_frozen(&self) -> bool {
        self.defcon <= 4
    }

    /// Jupe a server name: allocate a fake sid, store it, return the sid to
    /// introduce (or the existing sid if the name is already juped).
    pub fn jupe_add(&mut self, name: &str, reason: &str) -> String {
        if let Some(j) = self.net.jupes.iter().find(|j| j.name.eq_ignore_ascii_case(name)) {
            return j.sid.clone();
        }
        let sid = jupe_sid(self.net.jupe_seq);
        // Persisted (Local scope) so a juped server stays juped across a restart.
        let _ = self.log.append(Event::JupeAdded { name: name.to_string(), sid: sid.clone(), reason: reason.to_string() });
        self.net.jupe_seq += 1;
        self.net.jupes.push(Jupe { name: name.to_string(), sid: sid.clone(), reason: reason.to_string() });
        sid
    }

    /// Lift a jupe. Returns the sid to squit if it existed.
    pub fn jupe_del(&mut self, name: &str) -> Option<String> {
        let sid = self.net.jupes.iter().find(|j| j.name.eq_ignore_ascii_case(name)).map(|j| j.sid.clone())?;
        let _ = self.log.append(Event::JupeRemoved { name: name.to_string() });
        self.net.jupes.retain(|j| !j.name.eq_ignore_ascii_case(name));
        Some(sid)
    }

    /// The juped servers, as (name, sid, reason).
    pub fn jupes(&self) -> Vec<(String, String, String)> {
        self.net.jupes.iter().map(|j| (j.name.clone(), j.sid.clone(), j.reason.clone())).collect()
    }

    /// The persisted stat counters, to seed the live registry on startup.
    pub fn persisted_stats(&self) -> std::collections::BTreeMap<String, u64> {
        self.net.stats.clone()
    }

    /// The persisted per-channel activity, to seed BOTSTATS on startup.
    pub fn persisted_chan_stats(&self) -> ChanStats {
        self.net.chan_stats.clone()
    }

    /// Snapshot the live stats (shared counters + per-channel activity) to the log
    /// so they survive a restart.
    pub fn persist_stats(
        &mut self,
        counters: &std::collections::BTreeMap<String, u64>,
        chan_stats: ChanStats,
    ) -> std::io::Result<()> {
        self.log.append(Event::StatsSet {
            counters: counters.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            channels: chan_stats.clone(),
        })?;
        self.net.stats = counters.clone();
        self.net.chan_stats = chan_stats;
        Ok(())
    }

    /// File an abuse report, rate-limited per reporter. Returns the new report's
    /// id, or None if the reporter filed one too recently.
    pub fn report_file(&mut self, reporter: &str, target: &str, reason: &str) -> Option<u64> {
        const COOLDOWN: u64 = 30;
        let now = now();
        let key = reporter.to_ascii_lowercase();
        if self.report_times.get(&key).is_some_and(|&t| now.saturating_sub(t) < COOLDOWN) {
            return None;
        }
        self.report_times.insert(key, now);
        let id = self.net.report_seq;
        let _ = self.log.append(Event::ReportFiled { id, reporter: reporter.to_string(), target: target.to_string(), reason: reason.to_string(), ts: now });
        self.net.report_seq = id + 1;
        self.net.reports.push(Report { id, reporter: reporter.to_string(), target: target.to_string(), reason: reason.to_string(), ts: now, open: true });
        Some(id)
    }

    /// Close (resolve) a report. Returns whether an open one was closed.
    pub fn report_close(&mut self, id: u64) -> bool {
        let closed = self.net.reports.iter().any(|r| r.id == id && r.open);
        if closed {
            let _ = self.log.append(Event::ReportClosed { id });
            if let Some(r) = self.net.reports.iter_mut().find(|r| r.id == id) {
                r.open = false;
            }
        }
        closed
    }

    /// Delete a report entirely. Returns whether one existed.
    pub fn report_del(&mut self, id: u64) -> bool {
        let existed = self.net.reports.iter().any(|r| r.id == id);
        if existed {
            let _ = self.log.append(Event::ReportDeleted { id });
            self.net.reports.retain(|r| r.id != id);
        }
        existed
    }

    /// The reports, newest first. `open_only` hides closed ones.
    pub fn reports(&self, open_only: bool) -> Vec<ReportView> {
        self.net
            .reports
            .iter()
            .rev()
            .filter(|r| !open_only || r.open)
            .map(|r| ReportView { id: r.id, reporter: r.reporter.clone(), target: r.target.clone(), reason: r.reason.clone(), ts: r.ts, open: r.open })
            .collect()
    }

    /// A single report by id, if present.
    pub fn report(&self, id: u64) -> Option<ReportView> {
        self.net.reports.iter().find(|r| r.id == id).map(|r| ReportView { id: r.id, reporter: r.reporter.clone(), target: r.target.clone(), reason: r.reason.clone(), ts: r.ts, open: r.open })
    }

    /// Open a help-desk ticket, rate-limited per requester (shares the report
    /// throttle namespace). Returns the new ticket's id, or None if too soon.
    pub fn help_request(&mut self, requester: &str, message: &str) -> Option<u64> {
        const COOLDOWN: u64 = 30;
        let now = now();
        let tkey = format!("help:{}", requester.to_ascii_lowercase());
        if self.report_times.get(&tkey).is_some_and(|&t| now.saturating_sub(t) < COOLDOWN) {
            return None;
        }
        self.report_times.insert(tkey, now);
        let id = self.net.help_seq;
        let _ = self.log.append(Event::HelpRequested { id, requester: requester.to_string(), message: message.to_string(), ts: now });
        self.net.help_seq = id + 1;
        self.net.help.push(HelpTicket { id, requester: requester.to_string(), message: message.to_string(), ts: now, handler: None, open: true });
        Some(id)
    }

    /// Assign an open ticket to a handler. Returns whether an open one was taken.
    pub fn help_take(&mut self, id: u64, handler: &str) -> bool {
        let ok = self.net.help.iter().any(|t| t.id == id && t.open);
        if ok {
            let _ = self.log.append(Event::HelpTaken { id, handler: handler.to_string() });
            if let Some(t) = self.net.help.iter_mut().find(|t| t.id == id) {
                t.handler = Some(handler.to_string());
            }
        }
        ok
    }

    /// Close a ticket. Returns whether an open one was closed.
    pub fn help_close(&mut self, id: u64) -> bool {
        let ok = self.net.help.iter().any(|t| t.id == id && t.open);
        if ok {
            let _ = self.log.append(Event::HelpClosed { id });
            if let Some(t) = self.net.help.iter_mut().find(|t| t.id == id) {
                t.open = false;
            }
        }
        ok
    }

    /// The tickets, newest first. `open_only` hides closed ones.
    pub fn help_tickets(&self, open_only: bool) -> Vec<HelpView> {
        self.net
            .help
            .iter()
            .rev()
            .filter(|t| !open_only || t.open)
            .map(|t| HelpView { id: t.id, requester: t.requester.clone(), message: t.message.clone(), ts: t.ts, handler: t.handler.clone(), open: t.open })
            .collect()
    }

    /// A single ticket by id.
    pub fn help_ticket(&self, id: u64) -> Option<HelpView> {
        self.net.help.iter().find(|t| t.id == id).map(|t| HelpView { id: t.id, requester: t.requester.clone(), message: t.message.clone(), ts: t.ts, handler: t.handler.clone(), open: t.open })
    }

    /// The id of the oldest open, unassigned ticket (for HelpServ NEXT).
    pub fn help_next_open(&self) -> Option<u64> {
        self.net.help.iter().find(|t| t.open && t.handler.is_none()).map(|t| t.id)
    }

    /// Register a new group (name must start with `!`). Founder is an account.
    pub fn group_register(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        if !name.starts_with('!') || name.len() < 2 {
            return Err(ChanError::InvalidPattern);
        }
        if self.group(name).is_some() {
            return Err(ChanError::Exists);
        }
        let ts = now();
        self.log.append(Event::GroupRegistered { name: name.to_string(), founder: founder.to_string(), ts }).map_err(|_| ChanError::Internal)?;
        self.net.groups.push(Group { name: name.to_string(), founder: founder.to_string(), ts, members: Vec::new() });
        Ok(())
    }

    /// Drop a group.
    pub fn group_drop(&mut self, name: &str) -> Result<(), ChanError> {
        if self.group(name).is_none() {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::GroupDropped { name: name.to_string() }).map_err(|_| ChanError::Internal)?;
        let k = key(name);
        self.net.groups.retain(|g| key(&g.name) != k);
        Ok(())
    }

    /// Upsert a group member with `flags` (empty = a plain member).
    pub fn group_set_flags(&mut self, name: &str, account: &str, flags: &str) -> Result<(), ChanError> {
        let k = key(name);
        let Some(g) = self.net.groups.iter_mut().find(|g| key(&g.name) == k) else {
            return Err(ChanError::NoChannel);
        };
        self.log.append(Event::GroupFlagsSet { name: name.to_string(), account: account.to_string(), flags: flags.to_string() }).map_err(|_| ChanError::Internal)?;
        g.members.retain(|m| !m.account.eq_ignore_ascii_case(account));
        g.members.push(GroupMember { account: account.to_string(), flags: flags.to_string() });
        Ok(())
    }

    /// Remove a member from a group. Returns whether one was present.
    pub fn group_del_member(&mut self, name: &str, account: &str) -> Result<bool, ChanError> {
        let k = key(name);
        let Some(g) = self.net.groups.iter_mut().find(|g| key(&g.name) == k) else {
            return Err(ChanError::NoChannel);
        };
        if !g.members.iter().any(|m| m.account.eq_ignore_ascii_case(account)) {
            return Ok(false);
        }
        self.log.append(Event::GroupMemberDel { name: name.to_string(), account: account.to_string() }).map_err(|_| ChanError::Internal)?;
        g.members.retain(|m| !m.account.eq_ignore_ascii_case(account));
        Ok(true)
    }

    /// Transfer a group's founder to another account.
    pub fn group_set_founder(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        let k = key(name);
        let Some(g) = self.net.groups.iter_mut().find(|g| key(&g.name) == k) else {
            return Err(ChanError::NoChannel);
        };
        self.log.append(Event::GroupFounderSet { name: name.to_string(), founder: founder.to_string() }).map_err(|_| ChanError::Internal)?;
        g.founder = founder.to_string();
        Ok(())
    }

    /// A group view (founder + members), if it exists.
    pub fn group(&self, name: &str) -> Option<GroupView> {
        let k = key(name);
        self.net.groups.iter().find(|g| key(&g.name) == k).map(|g| GroupView {
            name: g.name.clone(),
            founder: g.founder.clone(),
            members: g.members.iter().map(|m| echo_api::GroupMemberView { account: m.account.clone(), flags: m.flags.clone() }).collect(),
        })
    }

    /// Every group's name, sorted.
    pub fn groups(&self) -> Vec<String> {
        let mut names: Vec<String> = self.net.groups.iter().map(|g| g.name.clone()).collect();
        names.sort();
        names
    }

    /// The groups an account belongs to (founder or member).
    pub fn groups_of(&self, account: &str) -> Vec<String> {
        self.net
            .groups
            .iter()
            .filter(|g| g.founder.eq_ignore_ascii_case(account) || g.members.iter().any(|m| m.account.eq_ignore_ascii_case(account)))
            .map(|g| g.name.clone())
            .collect()
    }

    /// Whether an account is in a group (its founder or a member).
    // Whether `account` inherits a group's channel access (when the group is on a
    // channel's access list): the group's founder, or a member holding the 'c'
    // (channel-access) flag. Plain membership is not enough — the flag gates it.
    fn group_grants_channel_access(&self, name: &str, account: &str) -> bool {
        let k = key(name);
        self.net.groups.iter().find(|g| key(&g.name) == k).is_some_and(|g| {
            g.founder.eq_ignore_ascii_case(account)
                || g.members.iter().any(|m| {
                    m.account.eq_ignore_ascii_case(account) && echo_api::GroupFlags::parse(&m.flags).has(echo_api::GroupFlag::Channel)
                })
        })
    }

    /// An account's effective channel capabilities, combining its direct access
    /// entry with any `!group` access entry it belongs to (the interconnection
    /// that lets a channel grant access to a whole group).
    pub fn channel_caps(&self, channel: &str, account: &str) -> Caps {
        let Some(c) = self.channels.get(&key(channel)) else { return Caps::default() };
        if c.founder.eq_ignore_ascii_case(account) {
            return echo_api::level_caps("founder");
        }
        let mut caps = Caps::default();
        for a in &c.access {
            let applies = match a.account.strip_prefix('!') {
                Some(g) => self.group_grants_channel_access(&format!("!{g}"), account),
                None => a.account.eq_ignore_ascii_case(account),
            };
            if applies {
                caps = caps.union(echo_api::level_caps(&a.level));
            }
        }
        caps
    }

    /// A user's join status mode for a channel, group-aware.
    pub fn channel_join_mode(&self, channel: &str, account: &str) -> Option<&'static str> {
        self.channel_caps(channel, account).auto
    }

    /// Add a services ignore, replacing any existing entry for the same mask.
    pub fn ignore_add(&mut self, mask: &str, reason: &str, expires: Option<u64>) {
        self.ignores.retain(|i| !i.mask.eq_ignore_ascii_case(mask));
        self.ignores.push(Ignore { mask: mask.to_string(), reason: reason.to_string(), expires });
    }

    /// Remove a services ignore. Returns whether a live one was removed.
    pub fn ignore_del(&mut self, mask: &str) -> bool {
        let now = now();
        let existed = self.ignores.iter().any(|i| i.mask.eq_ignore_ascii_case(mask) && i.expires.is_none_or(|e| e > now));
        self.ignores.retain(|i| !i.mask.eq_ignore_ascii_case(mask));
        existed
    }

    /// The live services ignores (expired hidden lazily), oldest first.
    pub fn ignores(&self) -> Vec<IgnoreView> {
        let now = now();
        self.ignores
            .iter()
            .filter(|i| i.expires.is_none_or(|e| e > now))
            .map(|i| IgnoreView { mask: i.mask.clone(), reason: i.reason.clone(), expires: i.expires })
            .collect()
    }

    /// Whether a user is currently ignored by services. A mask with an `@` is
    /// matched against `nick!*@host` (we don't track ident); a bare mask against
    /// the nick. Expired entries are swept as they're encountered.
    pub fn is_ignored(&mut self, nick: &str, host: &str) -> bool {
        let now = now();
        self.ignores.retain(|i| i.expires.is_none_or(|e| e > now));
        let full = format!("{}!*@{}", nick.to_ascii_lowercase(), host.to_ascii_lowercase());
        let nick_lc = nick.to_ascii_lowercase();
        self.ignores.iter().any(|i| {
            let m = i.mask.to_ascii_lowercase();
            if m.contains('@') {
                glob_match(&m, &full)
            } else {
                glob_match(&m, &nick_lc)
            }
        })
    }

    /// The account's suspension record, if any (shown in INFO even once expired).
    pub fn suspension(&self, account: &str) -> Option<SuspensionView> {
        self.accounts
            .get(&key(account))
            .and_then(|a| a.suspension.as_ref())
            .map(|s| SuspensionView { by: s.by.clone(), reason: s.reason.clone(), ts: s.ts, expires: s.expires })
    }

}
