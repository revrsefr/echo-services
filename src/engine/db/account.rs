use super::*;

impl Db {
    /// Commit pre-derived credentials as a new account. Cheap: no key stretching.
    pub fn register_prepared(&mut self, name: &str, creds: Credentials, email: Option<String>) -> Result<(), RegError> {
        if self.exists(name) {
            return Err(RegError::Exists);
        }
        // Unverified only when email confirmation actually applies (email is
        // configured and an address was given); otherwise verified immediately.
        let verified = !(self.email_enabled && email.is_some());
        let ts = now(); // one timestamp: registered-at == last-seen at creation
        let account = Account {
            name: name.to_string(),
            email,
            ts,
            home: self.log.origin.clone(),
            scram256: Some(creds.scram256),
            scram512: Some(creds.scram512),
            certfps: Vec::new(),
            verified,
            ajoin: Vec::new(),
            suspension: None,
            memos: Vec::new(), memo_ignore: Vec::new(), memo_notify: true, memo_limit: None,
            greet: String::new(), no_autoop: false, no_protect: false, hide_status: false, snotice: false,
            vhost: None,
            vhost_request: None,
            last_seen: ts,
            noexpire: false,
            expiry_warned: false,
            oper_note: None,
        };
        self.log.append(Event::AccountRegistered(Box::new(account.clone()))).map_err(|_| RegError::Internal)?;
        self.accounts.insert(key(name), account);
        Ok(())
    }

    /// Provision a new account directly from pre-derived SCRAM verifiers (no
    /// plaintext), for bulk backfill from an external authority that stores
    /// verifiers rather than passwords. The verifier is the account's sole
    /// password credential, so SCRAM, PLAIN, and IDENTIFY all work at once (see
    /// `authenticate`). Refuses if the account already exists (so a backfill
    /// can't clobber a fully-credentialed account). `scram512` empty =
    /// SCRAM-SHA-512 unavailable for this account (it falls back to 256).
    pub fn provision_account(&mut self, name: &str, scram256: &str, scram512: &str, email: Option<String>) -> Result<(), RegError> {
        if name.is_empty() || scram256.is_empty() {
            return Err(RegError::Internal);
        }
        // The account may already exist without a verifier — an Anope import
        // creates accounts (channel ownership, vhosts, etc.) but can't carry the
        // one-way password hash. When the external authority then asserts a
        // verifier, set it in place rather than refusing, or migrated users could
        // never log in. Keyed by name, so all imported data stays attached.
        if self.exists(name) {
            self.log
                .append(Event::AccountPasswordSet {
                    account: name.to_string(),
                    scram256: scram256.to_string(),
                    scram512: scram512.to_string(),
                })
                .map_err(|_| RegError::Internal)?;
            if let Some(acct) = self.accounts.get_mut(&key(name)) {
                acct.scram256 = Some(scram256.to_string());
                acct.scram512 = (!scram512.is_empty()).then(|| scram512.to_string());
            }
            return Ok(());
        }
        let ts = now(); // one timestamp: registered-at == last-seen at creation
        let account = Account {
            name: name.to_string(),
            email,
            ts,
            home: self.log.origin.clone(),
            scram256: Some(scram256.to_string()),
            scram512: (!scram512.is_empty()).then(|| scram512.to_string()),
            certfps: Vec::new(),
            verified: true, // the external authority vouches for it
            ajoin: Vec::new(),
            suspension: None,
            memos: Vec::new(), memo_ignore: Vec::new(), memo_notify: true, memo_limit: None,
            greet: String::new(), no_autoop: false, no_protect: false, hide_status: false, snotice: false,
            vhost: None,
            vhost_request: None,
            last_seen: ts,
            noexpire: false,
            expiry_warned: false,
            oper_note: None,
        };
        self.log.append(Event::AccountRegistered(Box::new(account.clone()))).map_err(|_| RegError::Internal)?;
        self.accounts.insert(key(name), account);
        Ok(())
    }

    /// Register synchronously, deriving and committing in one call. A test helper;
    /// the live paths derive off-thread via `derive_credentials` + `register_prepared`.
    #[cfg(test)]
    pub fn register(&mut self, name: &str, password: &str, email: Option<String>) -> Result<(), RegError> {
        let creds = Self::derive_credentials(password, self.scram_iterations).ok_or(RegError::Internal)?;
        self.register_prepared(name, creds, email)
    }

    #[cfg(test)]
    pub(crate) fn test_verifier(&self, name: &str) -> Option<String> {
        self.accounts.get(&key(name)).and_then(|a| a.scram256.clone())
    }

    /// Check credentials; on success return the account's canonical name (its
    /// stored casing), else None. The SCRAM-SHA-256 verifier is the sole password
    /// credential, so PLAIN and IDENTIFY verify the plaintext against it exactly
    /// as a SCRAM login proves knowledge of it (see `scram::verify_plain`).
    pub fn authenticate(&self, name: &str, password: &str) -> Option<&str> {
        let account = self.accounts.get(&self.resolved_key(name)?)?;
        let verifier = account.scram256.as_deref()?;
        crate::engine::scram::verify_plain(crate::engine::scram::Hash::Sha256, verifier, password)
            .then_some(account.name.as_str())
    }

    /// The account's canonical name and its SCRAM verifier for `mech`, if any.
    pub fn scram_lookup(&self, name: &str, mech: &str) -> Option<(&str, &str)> {
        let account = self.accounts.get(&self.resolved_key(name)?)?;
        let verifier = match mech {
            "SCRAM-SHA-256" => account.scram256.as_deref(),
            "SCRAM-SHA-512" => account.scram512.as_deref(),
            _ => None,
        }?;
        Some((account.name.as_str(), verifier))
    }

    /// The canonical name of the account owning `fp`, if any. Fingerprints are
    /// globally unique, so this is unambiguous.
    pub fn certfp_owner(&self, fp: &str) -> Option<&str> {
        let fp = fp.to_ascii_lowercase();
        self.accounts.values().find(|a| a.certfps.contains(&fp)).map(|a| a.name.as_str())
    }

    /// The fingerprints registered to an account (empty if unknown/none).
    pub fn certfps(&self, account: &str) -> &[String] {
        self.accounts.get(&key(account)).map_or(&[], |a| a.certfps.as_slice())
    }

    /// Whether outbound email is configured.
    pub fn email_enabled(&self) -> bool {
        self.email_enabled
    }

    /// Whether `account`'s email is confirmed (true for unknown/legacy accounts).
    pub fn is_verified(&self, account: &str) -> bool {
        self.account(account).is_none_or(|a| a.verified)
    }

    /// Mark `account`'s email confirmed.
    pub fn verify_account(&mut self, account: &str) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountVerified { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().verified = true;
        Ok(())
    }

    pub fn set_email_enabled(&mut self, on: bool) {
        self.email_enabled = on;
    }

    /// Restrict which extbans AKICK accepts to the configured set (`[extban]
    /// enabled`). An empty list leaves the default (all extbans echo knows).
    pub fn set_extban_enabled(&mut self, names: Vec<String>) {
        if !names.is_empty() {
            self.extban_enabled = Some(names.into_iter().map(|n| n.to_ascii_lowercase()).collect());
        }
    }

    /// Whether `name` is an enabled extban (all, unless narrowed by config).
    pub fn extban_allowed(&self, name: &str) -> bool {
        self.extban_enabled.as_ref().is_none_or(|set| set.contains(&name.to_ascii_lowercase()))
    }

    /// Masks whose users NOTIFY never matches (`[log] notify_exclude`). Replaces
    /// the list wholesale so a REHASH can shrink it, not only grow it.
    pub fn set_notify_exclude(&mut self, masks: Vec<String>) {
        self.notify_exclude = masks;
    }

    /// Record the ircd's live extban set (its CAPAB EXTBANS burst).
    pub fn set_live_extbans(&mut self, entries: Vec<echo_api::ExtbanCap>) {
        self.live_extbans = Some(entries);
    }

    /// Whether this ircd actually offers `name`. True until the ircd tells us its
    /// set (we don't second-guess before the burst).
    pub fn extban_offered(&self, name: &str) -> bool {
        self.live_extbans.as_ref().is_none_or(|set| set.iter().any(|e| e.name.eq_ignore_ascii_case(name)))
    }

    /// The ircd's live extban set (empty until we link and get its CAPAB burst).
    pub fn extbans(&self) -> Vec<echo_api::ExtbanCap> {
        self.live_extbans.clone().unwrap_or_default()
    }

    /// Record the ircd's live channel-mode set (its CAPAB CHANMODES burst).
    pub fn set_live_chanmodes(&mut self, modes: Vec<echo_api::ChanModeCap>) {
        self.live_chanmodes = Some(modes);
    }

    /// Whether channel mode `m` takes a parameter in the given direction — from
    /// the ircd's advertised set if known, else the static fallback.
    pub fn chanmode_takes_param(&self, m: char, adding: bool) -> bool {
        match self.live_chanmodes.as_ref().and_then(|v| v.iter().find(|c| c.letter == m)) {
            Some(cap) => cap.takes_param(adding),
            None => echo_api::chanmode_takes_param(m, adding),
        }
    }

    /// The channel prefix (status) mode letters the ircd advertises (incl custom
    /// ones like ojoin's `Y`), or the static fallback until we've linked.
    pub fn status_modes(&self) -> String {
        match &self.live_chanmodes {
            Some(v) => v.iter().filter(|c| c.is_prefix()).map(|c| c.letter).collect(),
            None => echo_api::STATUS_MODES.to_string(),
        }
    }

    /// Resolve an extban token (name, case-insensitive; or single letter, case-
    /// sensitive) against the ircd's live set. For extbans echo's static table lacks.
    pub fn extban_lookup(&self, token: &str) -> Option<echo_api::ExtbanCap> {
        let live = self.live_extbans.as_ref()?;
        let mut chars = token.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => live.iter().find(|e| e.letter == Some(c)).cloned(),
            _ => live.iter().find(|e| e.name.eq_ignore_ascii_case(token)).cloned(),
        }
    }

    /// Display name used in email templates.
    pub fn email_brand(&self) -> &str {
        &self.email_brand
    }

    /// Accent colour used in email templates.
    pub fn email_accent(&self) -> &str {
        &self.email_accent
    }

    /// Logo image URL for email templates (empty = show the brand name as text).
    pub fn email_logo(&self) -> &str {
        &self.email_logo
    }

    pub fn set_email_brand(&mut self, brand: &str) {
        self.email_brand = brand.to_string();
    }

    pub fn set_email_accent(&mut self, accent: &str) {
        self.email_accent = accent.to_string();
    }

    pub fn set_email_logo(&mut self, logo: &str) {
        self.email_logo = logo.to_string();
    }

    /// Issue a fresh emailed code for `account` and purpose, valid for 15 minutes.
    pub fn issue_code(&mut self, account: &str, kind: CodeKind) -> String {
        let code = gen_code();
        self.codes.insert(
            key(account),
            PendingCode { kind, code: code.clone(), issued: Instant::now(), deadline: Instant::now() + Duration::from_secs(900), tries_left: CODE_TRIES },
        );
        code
    }

    /// Seconds the caller must wait before another emailed code for `account`
    /// (0 = allowed now). Throttles RESEND/RESETPASS against email-bombing.
    pub fn code_issue_wait(&self, account: &str) -> u64 {
        self.codes.get(&key(account)).map_or(0, |pc| {
            let ready = pc.issued + CODE_ISSUE_COOLDOWN;
            ready.checked_duration_since(Instant::now()).map_or(0, |d| d.as_secs() + 1)
        })
    }

    /// Consume a code for `account`: true if the purpose and code match and it
    /// hasn't expired. A wrong guess burns a try and the code is dropped once
    /// they run out, so it can't be ground down online.
    pub fn take_code(&mut self, account: &str, kind: CodeKind, code: &str) -> bool {
        let k = key(account);
        let Some(pc) = self.codes.get_mut(&k) else { return false };
        if pc.deadline <= Instant::now() {
            self.codes.remove(&k);
            return false;
        }
        if pc.kind == kind && pc.code == code {
            self.codes.remove(&k);
            return true;
        }
        pc.tries_left = pc.tries_left.saturating_sub(1);
        if pc.tries_left == 0 {
            self.codes.remove(&k);
        }
        false
    }

    /// Seconds the caller must wait before another password attempt on `account`,
    /// or None if it is not currently throttled.
    pub fn auth_lockout(&self, account: &str) -> Option<u64> {
        // Key the throttle by the resolved account, so every grouped-nick alias of
        // one account shares a single lockout bucket (else each spelling is its own).
        let k = self.resolved_key(account).unwrap_or_else(|| key(account));
        let until = self.auth_fails.get(&k)?.locked_until?;
        let now = Instant::now();
        (until > now).then(|| (until - now).as_secs() + 1)
    }

    /// Record the outcome of a password attempt against `account`. Success clears
    /// the counter; each failure past a few free tries grows an exponential
    /// backoff, throttling guessing without a hard lockout a griefer could abuse.
    pub fn note_auth(&mut self, account: &str, success: bool) {
        let k = self.resolved_key(account).unwrap_or_else(|| key(account));
        if success {
            self.auth_fails.remove(&k);
            return;
        }
        let t = self.auth_fails.entry(k).or_insert(AuthThrottle { fails: 0, locked_until: None });
        t.fails += 1;
        if t.fails > AUTH_FREE_TRIES {
            let shift = (t.fails - AUTH_FREE_TRIES - 1).min(9);
            let secs = (1u64 << shift).min(AUTH_MAX_BACKOFF_SECS);
            t.locked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    /// Set (or clear) `account`'s email.
    pub fn set_email(&mut self, account: &str, email: Option<String>) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountEmailSet { account: account.to_string(), email: email.clone() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().email = email;
        Ok(())
    }

    /// Assign a vhost to `account`. `setter` is who did it; `ttl` is seconds until
    /// it expires, or None for a permanent vhost.
    pub fn set_vhost(&mut self, account: &str, host: &str, setter: &str, ttl: Option<u64>) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        let ts = now();
        let expires = ttl.map(|t| ts + t);
        self.log.append(Event::VhostSet { account: account.to_string(), host: host.to_string(), setter: setter.to_string(), ts, expires }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().vhost = Some(Vhost { host: host.to_string(), setter: setter.to_string(), ts, expires });
        Ok(())
    }

    /// Remove `account`'s vhost. Returns whether one was set.
    pub fn del_vhost(&mut self, account: &str) -> Result<bool, RegError> {
        let k = key(account);
        match self.accounts.get(&k) {
            Some(a) if a.vhost.is_some() => {}
            Some(_) => return Ok(false),
            None => return Err(RegError::Internal),
        }
        self.log.append(Event::VhostDeleted { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().vhost = None;
        Ok(true)
    }


    /// Record a pending vhost request for `account` (awaiting approval).
    pub fn request_vhost(&mut self, account: &str, host: &str) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        let ts = now();
        self.log.append(Event::VhostRequested { account: account.to_string(), host: host.to_string(), ts }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().vhost_request = Some(PendingVhost { host: host.to_string(), ts });
        self.vhost_req_times.insert(k, ts);
        Ok(())
    }

    /// Seconds a member must wait before requesting another vhost (0 = allowed).
    pub fn vhost_request_wait(&self, account: &str) -> u64 {
        const COOLDOWN: u64 = 60;
        match self.vhost_req_times.get(&key(account)) {
            Some(&last) => COOLDOWN.saturating_sub(now().saturating_sub(last)),
            None => 0,
        }
    }

    /// Clear a pending vhost request (on approval or rejection). Returns the
    /// requested host, if there was one.
    pub fn take_vhost_request(&mut self, account: &str) -> Result<Option<String>, RegError> {
        let k = key(account);
        let host = match self.accounts.get(&k) {
            Some(a) => a.vhost_request.as_ref().map(|r| r.host.clone()),
            None => return Err(RegError::Internal),
        };
        if host.is_some() {
            self.log.append(Event::VhostRequestCleared { account: account.to_string() }).map_err(|_| RegError::Internal)?;
            self.accounts.get_mut(&k).unwrap().vhost_request = None;
        }
        Ok(host)
    }

    /// Every account with a pending vhost request, as (account, host).
    pub fn vhost_requests(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .accounts
            .values()
            .filter_map(|a| a.vhost_request.as_ref().map(|r| (a.name.clone(), r.host.clone())))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Add a vhost offer to the self-serve menu. Ok(false) if already offered.
    pub fn vhost_offer_add(&mut self, host: &str) -> Result<bool, RegError> {
        if self.host_cfg.offers.iter().any(|o| o == host) {
            return Ok(false);
        }
        self.log.append(Event::VhostOfferAdded { host: host.to_string() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.offers.push(host.to_string());
        Ok(true)
    }

    /// Remove the offer at 1-based `index`. Returns the removed spec, if valid.
    pub fn vhost_offer_del(&mut self, index: usize) -> Result<Option<String>, RegError> {
        if index == 0 || index > self.host_cfg.offers.len() {
            return Ok(None);
        }
        let host = self.host_cfg.offers[index - 1].clone();
        self.log.append(Event::VhostOfferRemoved { host: host.clone() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.offers.retain(|o| o != &host);
        Ok(Some(host))
    }

    /// The self-serve vhost offer menu.
    pub fn vhost_offers(&self) -> &[String] {
        &self.host_cfg.offers
    }

    /// Add a forbidden vhost regex (anti-impersonation). Validates it compiles;
    /// Ok(false) if already present.
    pub fn vhost_forbid_add(&mut self, pattern: &str) -> Result<bool, RegError> {
        if regex::RegexBuilder::new(pattern).size_limit(BADWORD_SIZE_LIMIT).build().is_err() {
            return Err(RegError::Internal);
        }
        if self.host_cfg.forbidden.iter().any(|p| p == pattern) {
            return Ok(false);
        }
        self.log.append(Event::VhostForbidAdded { pattern: pattern.to_string() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.forbidden.push(pattern.to_string());
        Ok(true)
    }

    /// Remove the forbidden pattern at 1-based `index`; returns it if valid.
    pub fn vhost_forbid_del(&mut self, index: usize) -> Result<Option<String>, RegError> {
        if index == 0 || index > self.host_cfg.forbidden.len() {
            return Ok(None);
        }
        let pattern = self.host_cfg.forbidden[index - 1].clone();
        self.log.append(Event::VhostForbidRemoved { pattern: pattern.clone() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.forbidden.retain(|p| p != &pattern);
        Ok(Some(pattern))
    }

    pub fn vhost_forbidden(&self) -> &[String] {
        &self.host_cfg.forbidden
    }

    /// Whether `host` matches a forbidden pattern (case-insensitive).
    pub fn vhost_is_forbidden(&self, host: &str) -> bool {
        !self.host_cfg.forbidden.is_empty() && build_badword_set(&self.host_cfg.forbidden).is_match(host)
    }

    /// Set (or clear) the auto-vhost template, e.g. "$account.users.example".
    pub fn set_vhost_template(&mut self, template: Option<String>) -> Result<(), RegError> {
        self.log.append(Event::VhostTemplateSet { template: template.clone() }).map_err(|_| RegError::Internal)?;
        self.host_cfg.template = template;
        Ok(())
    }

    pub fn vhost_template(&self) -> Option<&str> {
        self.host_cfg.template.as_deref()
    }

    /// `account`'s current (non-expired) vhost host string, if it has one.
    pub fn active_vhost(&self, account: &str) -> Option<String> {
        self.accounts
            .get(&key(account))
            .and_then(|a| a.vhost.as_ref().filter(|v| v.expires.is_none_or(|e| e > now())).map(|v| v.host.clone()))
    }

    /// The account whose current (non-expired) vhost is `host`, if any — so a
    /// vhost can't be assigned to two accounts and collide on the network.
    pub fn vhost_owner(&self, host: &str) -> Option<String> {
        self.accounts
            .values()
            .find(|a| a.vhost.as_ref().is_some_and(|v| v.host.eq_ignore_ascii_case(host) && v.expires.is_none_or(|e| e > now())))
            .map(|a| a.name.clone())
    }

    /// Every account that has a vhost, as (account, host, setter, expires).
    pub fn vhosts(&self) -> Vec<(String, String, String, Option<u64>)> {
        let mut out: Vec<(String, String, String, Option<u64>)> = self
            .accounts
            .values()
            .filter_map(|a| a.vhost.as_ref().map(|v| (a.name.clone(), v.host.clone(), v.setter.clone(), v.expires)))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Set (or clear, when empty) `account`'s personal greet.
    pub fn set_greet(&mut self, account: &str, greet: &str) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountGreetSet { account: account.to_string(), greet: greet.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().greet = greet.to_string();
        Ok(())
    }

    /// Set whether `account` wants to be auto-opped on join (NickServ SET AUTOOP).
    pub fn set_account_autoop(&mut self, account: &str, on: bool) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountAutoOpSet { account: account.to_string(), on }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().no_autoop = !on;
        Ok(())
    }

    /// Whether `account` wants auto-op on join (default true). Unknown = true.
    pub fn account_wants_autoop(&self, account: &str) -> bool {
        self.accounts.get(&key(account)).is_none_or(|a| !a.no_autoop)
    }

    /// Set whether `account`'s nicks are protected by the enforcer (SET KILL).
    pub fn set_account_kill(&mut self, account: &str, on: bool) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountKillSet { account: account.to_string(), on }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().no_protect = !on;
        Ok(())
    }

    /// Whether `account`'s nicks are protected by the enforcer (default true).
    pub fn account_wants_protect(&self, account: &str) -> bool {
        self.accounts.get(&key(account)).is_none_or(|a| !a.no_protect)
    }

    /// Set whether `account` hides its last-seen/online line from other users.
    pub fn set_account_hide_status(&mut self, account: &str, on: bool) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountHideStatusSet { account: account.to_string(), on }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().hide_status = on;
        Ok(())
    }

    /// Whether `account` hides its last-seen/online line from others (default false).
    pub fn account_hides_status(&self, account: &str) -> bool {
        self.accounts.get(&key(account)).is_some_and(|a| a.hide_status)
    }

    /// NickServ SET SNOTICE: whether service replies come as a server notice.
    pub fn set_account_snotice(&mut self, account: &str, on: bool) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountSnoticeSet { account: account.to_string(), on }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().snotice = on;
        Ok(())
    }

    /// Whether `account` wants server-notice-style service replies (default false).
    pub fn account_wants_snotice(&self, account: &str) -> bool {
        self.accounts.get(&key(account)).is_some_and(|a| a.snotice)
    }

    /// Replace `account`'s password with freshly derived credentials.
    pub fn set_credentials(&mut self, account: &str, creds: Credentials) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log
            .append(Event::AccountPasswordSet {
                account: account.to_string(),
                scram256: creds.scram256.clone(),
                scram512: creds.scram512.clone(),
            })
            .map_err(|_| RegError::Internal)?;
        let a = self.accounts.get_mut(&k).unwrap();
        a.scram256 = Some(creds.scram256);
        a.scram512 = Some(creds.scram512);
        Ok(())
    }

    /// Delete `account`. Ok(false) if it wasn't registered.
    pub fn drop_account(&mut self, account: &str) -> Result<bool, RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Ok(false);
        }
        self.log.append(Event::AccountDropped { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.remove(&k);
        // Keep live state in step with what the AccountDropped fold does on replay:
        // erase every reference so a re-registration can't inherit the account's
        // channel access, successorship, or group standing.
        super::event::purge_account_refs(account, &mut self.channels, &mut self.grouped, &mut self.net.groups);
        Ok(true)
    }

    /// Register `fp` to `account`. Fingerprints are one-to-one with accounts.
    pub fn certfp_add(&mut self, account: &str, fp: &str) -> Result<(), CertError> {
        let fp = fp.to_ascii_lowercase();
        if !valid_fp(&fp) {
            return Err(CertError::Invalid);
        }
        if self.certfp_owner(&fp).is_some() {
            return Err(CertError::InUse);
        }
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(CertError::NoAccount);
        }
        self.log.append(Event::CertAdded { account: account.to_string(), fp: fp.clone() }).map_err(|_| CertError::Internal)?;
        self.accounts.get_mut(&k).unwrap().certfps.push(fp);
        Ok(())
    }

    /// Remove `fp` from `account`. Ok(false) if the account had no such fingerprint.
    pub fn certfp_del(&mut self, account: &str, fp: &str) -> Result<bool, CertError> {
        let fp = fp.to_ascii_lowercase();
        let k = key(account);
        match self.accounts.get(&k) {
            None => return Err(CertError::NoAccount),
            Some(a) if !a.certfps.contains(&fp) => return Ok(false),
            Some(_) => {}
        }
        self.log.append(Event::CertRemoved { account: account.to_string(), fp: fp.clone() }).map_err(|_| CertError::Internal)?;
        self.accounts.get_mut(&k).unwrap().certfps.retain(|c| *c != fp);
        Ok(true)
    }

    /// The account's auto-join list.
    pub fn ajoin_list(&self, account: &str) -> &[AjoinEntry] {
        self.accounts.get(&key(account)).map_or(&[], |a| a.ajoin.as_slice())
    }

    /// Add a channel to the account's auto-join list (updating the key if it was
    /// already listed). Returns whether it was newly added.
    pub fn ajoin_add(&mut self, account: &str, channel: &str, join_key: &str) -> Result<bool, RegError> {
        let k = key(account);
        let Some(a) = self.accounts.get(&k) else { return Err(RegError::Internal) };
        let existed = a.ajoin.iter().any(|e| e.channel.eq_ignore_ascii_case(channel));
        self.log
            .append(Event::AjoinAdded { account: account.to_string(), channel: channel.to_string(), key: join_key.to_string() })
            .map_err(|_| RegError::Internal)?;
        let a = self.accounts.get_mut(&k).unwrap();
        a.ajoin.retain(|e| !e.channel.eq_ignore_ascii_case(channel));
        a.ajoin.push(AjoinEntry { channel: channel.to_string(), key: join_key.to_string() });
        Ok(!existed)
    }

    /// Remove a channel from the account's auto-join list. Returns whether it was present.
    pub fn ajoin_del(&mut self, account: &str, channel: &str) -> Result<bool, RegError> {
        let k = key(account);
        let Some(a) = self.accounts.get(&k) else { return Err(RegError::Internal) };
        if !a.ajoin.iter().any(|e| e.channel.eq_ignore_ascii_case(channel)) {
            return Ok(false);
        }
        self.log
            .append(Event::AjoinRemoved { account: account.to_string(), channel: channel.to_string() })
            .map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().ajoin.retain(|e| !e.channel.eq_ignore_ascii_case(channel));
        Ok(true)
    }

    /// Suspend an account. `expires` is an absolute unix time (None = permanent).
    pub fn suspend_account(&mut self, account: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        let ts = now();
        self.log
            .append(Event::AccountSuspended { account: account.to_string(), by: by.to_string(), reason: reason.to_string(), ts, expires })
            .map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().suspension = Some(Suspension { by: by.to_string(), reason: reason.to_string(), ts, expires });
        Ok(())
    }

    /// Lift a suspension. Returns whether one was set.
    pub fn unsuspend_account(&mut self, account: &str) -> Result<bool, RegError> {
        let k = key(account);
        match self.accounts.get(&k) {
            None => return Err(RegError::Internal),
            Some(a) if a.suspension.is_none() => return Ok(false),
            Some(_) => {}
        }
        self.log.append(Event::AccountUnsuspended { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().suspension = None;
        Ok(true)
    }

    /// Whether an account has a set, unexpired suspension (evaluated lazily — no timer).
    pub fn is_suspended(&self, account: &str) -> bool {
        self.accounts
            .get(&key(account))
            .and_then(|a| a.suspension.as_ref())
            .is_some_and(|s| s.expires.is_none_or(|e| e > now()))
    }

    /// Stamp an account as active at `now`, coalesced: a fresh stamp is logged
    /// only once its last one is a day old, so routine logins don't flood the
    /// log. No-op for an account that doesn't exist.
    pub fn mark_account_seen(&mut self, account: &str, now: u64) {
        const COALESCE: u64 = 86_400;
        let k = key(account);
        let stale = self.accounts.get(&k).is_some_and(|a| now.saturating_sub(a.last_seen.max(a.ts)) >= COALESCE);
        if stale {
            let _ = self.log.append(Event::AccountSeen { account: account.to_string(), ts: now });
            if let Some(a) = self.accounts.get_mut(&k) {
                a.last_seen = a.last_seen.max(now);
            }
        }
    }

    /// Stamp a channel as used at `now`, coalesced like [`mark_account_seen`].
    pub fn mark_channel_used(&mut self, channel: &str, now: u64) {
        const COALESCE: u64 = 86_400;
        let k = key(channel);
        let stale = self.channels.get(&k).is_some_and(|c| now.saturating_sub(c.last_used.max(c.ts)) >= COALESCE);
        if stale {
            let _ = self.log.append(Event::ChannelUsed { channel: channel.to_string(), ts: now });
            if let Some(c) = self.channels.get_mut(&k) {
                c.last_used = c.last_used.max(now);
            }
        }
    }

    /// Pin or unpin an account against inactivity-expiry. Returns whether the
    /// flag actually changed.
    pub fn set_account_noexpire(&mut self, account: &str, on: bool) -> Result<bool, RegError> {
        let k = key(account);
        match self.accounts.get(&k) {
            None => Err(RegError::Internal),
            Some(a) if a.noexpire == on => Ok(false),
            Some(_) => {
                self.log.append(Event::AccountNoExpire { account: account.to_string(), on }).map_err(|_| RegError::Internal)?;
                self.accounts.get_mut(&k).unwrap().noexpire = on;
                Ok(true)
            }
        }
    }

    /// Pin or unpin a channel against inactivity-expiry.
    pub fn set_channel_noexpire(&mut self, channel: &str, on: bool) -> Result<bool, ChanError> {
        let k = key(channel);
        match self.channels.get(&k) {
            None => Err(ChanError::NoChannel),
            Some(c) if c.noexpire == on => Ok(false),
            Some(_) => {
                self.log.append(Event::ChannelNoExpire { channel: channel.to_string(), on }).map_err(|_| ChanError::Internal)?;
                self.channels.get_mut(&k).unwrap().noexpire = on;
                Ok(true)
            }
        }
    }

    /// Accounts inactive longer than `ttl` seconds as of `now` and eligible to be
    /// expired: not pinned (NOEXPIRE) and not currently suspended. Callers apply
    /// their own further guards (skip opers and live sessions) before dropping.
    pub fn expired_accounts(&self, now: u64, ttl: u64) -> Vec<String> {
        self.accounts
            .values()
            .filter(|a| !a.noexpire && a.suspension.is_none() && now.saturating_sub(a.last_seen.max(a.ts)) > ttl)
            .map(|a| a.name.clone())
            .collect()
    }

    /// Channels unused longer than `ttl` seconds as of `now` and eligible to be
    /// expired: not pinned and not suspended.
    pub fn expired_channels(&self, now: u64, ttl: u64) -> Vec<String> {
        self.channels
            .values()
            .filter(|c| !c.noexpire && c.suspension.is_none() && now.saturating_sub(c.last_used.max(c.ts)) > ttl)
            .map(|c| c.name.clone())
            .collect()
    }

    /// Accounts entering the warning window — inactive past `ttl - lead` but not
    /// yet past `ttl` — that have an email, aren't pinned or suspended, and
    /// haven't already been warned this idle spell. Returns (account, email,
    /// seconds until expiry).
    pub fn accounts_to_warn(&self, now: u64, ttl: u64, lead: u64) -> Vec<(String, String, u64)> {
        let floor = ttl.saturating_sub(lead);
        self.accounts
            .values()
            .filter(|a| !a.noexpire && !a.expiry_warned && a.suspension.is_none() && a.email.is_some())
            .filter_map(|a| {
                let idle = now.saturating_sub(a.last_seen.max(a.ts));
                (idle > floor && idle <= ttl).then(|| (a.name.clone(), a.email.clone().unwrap_or_default(), ttl - idle))
            })
            .collect()
    }

    /// Channels entering the warning window, paired with their founder's email
    /// (skipped when the founder has none). Returns (channel, email, seconds left).
    pub fn channels_to_warn(&self, now: u64, ttl: u64, lead: u64) -> Vec<(String, String, u64)> {
        let floor = ttl.saturating_sub(lead);
        self.channels
            .values()
            .filter(|c| !c.noexpire && !c.expiry_warned && c.suspension.is_none())
            .filter_map(|c| {
                let idle = now.saturating_sub(c.last_used.max(c.ts));
                if idle <= floor || idle > ttl {
                    return None;
                }
                let email = self.accounts.get(&key(&c.founder)).and_then(|a| a.email.clone())?;
                Some((c.name.clone(), email, ttl - idle))
            })
            .collect()
    }

    /// Record that an account has been warned about impending expiry.
    pub fn mark_account_warned(&mut self, account: &str) {
        let k = key(account);
        if self.accounts.contains_key(&k) {
            let _ = self.log.append(Event::AccountExpiryWarned { account: account.to_string() });
            if let Some(a) = self.accounts.get_mut(&k) {
                a.expiry_warned = true;
            }
        }
    }

    /// Record that a channel has been warned about impending expiry.
    pub fn mark_channel_warned(&mut self, channel: &str) {
        let k = key(channel);
        if self.channels.contains_key(&k) {
            let _ = self.log.append(Event::ChannelExpiryWarned { channel: channel.to_string() });
            if let Some(c) = self.channels.get_mut(&k) {
                c.expiry_warned = true;
            }
        }
    }

    /// Set or clear an account's staff note. Returns whether the account exists.
    pub fn set_account_note(&mut self, account: &str, note: Option<String>) -> bool {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return false;
        }
        let _ = self.log.append(Event::AccountOperNoteSet { account: account.to_string(), note: note.clone() });
        self.accounts.get_mut(&k).unwrap().oper_note = note;
        true
    }

    /// An account's staff note, if any.
    pub fn account_note(&self, account: &str) -> Option<String> {
        self.accounts.get(&key(account)).and_then(|a| a.oper_note.clone())
    }

    /// Set or clear a channel's staff note. Returns whether the channel exists.
    pub fn set_channel_note(&mut self, channel: &str, note: Option<String>) -> bool {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return false;
        }
        let _ = self.log.append(Event::ChannelOperNoteSet { channel: channel.to_string(), note: note.clone() });
        self.channels.get_mut(&k).unwrap().oper_note = note;
        true
    }

    /// A channel's staff note, if any.
    pub fn channel_note(&self, channel: &str) -> Option<String> {
        self.channels.get(&key(channel)).and_then(|c| c.oper_note.clone())
    }

}
