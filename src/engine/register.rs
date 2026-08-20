use super::*;

impl Engine {
    // ── Account authority (see grpc.rs) ─────────────────────────────────────
    // A trusted caller (e.g. a website backend that already did its own login
    // check) managing accounts the same way an IRC user does through NickServ,
    // minus the command syntax. The bearer token on the gRPC side IS the
    // authorization: unlike the mirrored NickServ commands, these do NOT
    // re-check the account's own password — Register and Authenticate are the
    // two exceptions, since the password is the actual input there.

    pub fn authority_pre_check(&mut self, name: &str) -> Result<(), AuthorityStatus> {
        if self.db.exists(name) {
            return Err(AuthorityStatus::AlreadyExists);
        }
        // A website write must obey the same namespace guards as an IRC REGISTER, or
        // it becomes a hole around them (a look-alike "аdmin" that impersonates, a
        // FORBIDden/reserved nick, or a registration created while frozen).
        if self.db.registrations_frozen() || self.db.readonly() {
            return Err(AuthorityStatus::Invalid);
        }
        self.authority_name_ok(name)?;
        if !self.reg_limiter.allow() {
            return Err(AuthorityStatus::RateLimited);
        }
        Ok(())
    }

    // The namespace guards the IRC REGISTER path enforces (FORBID list + look-alike/
    // confusable check), applied to every authority write so it can't create a name
    // IRC would have rejected.
    fn authority_name_ok(&self, name: &str) -> Result<(), AuthorityStatus> {
        // A control char in the name would inject into the confirmation email's
        // Subject/body (the name is interpolated there); IRC nicks can't carry one,
        // but a website-provided name must be checked.
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(AuthorityStatus::Invalid);
        }
        if self.db.is_forbidden(echo_api::ForbidKind::Nick, name).is_some() {
            return Err(AuthorityStatus::Invalid);
        }
        if self.db.confusable_check_enabled() && echo_api::confusable_reason(name).is_some() {
            return Err(AuthorityStatus::Invalid);
        }
        Ok(())
    }

    // Provision an account from pre-derived SCRAM verifiers (bulk backfill from
    // the authority). No email confirmation — the authority already vouches for it.
    pub fn authority_provision(&mut self, name: &str, scram256: &str, scram512: &str, email: Option<String>) -> AuthorityStatus {
        // Backfill still can't mint a forbidden/look-alike name (skip only the
        // frozen/rate-limit gates, which don't apply to an authority backfill).
        if !self.db.exists(name) {
            if let Err(status) = self.authority_name_ok(name) {
                return status;
            }
        }
        if let Some(addr) = &email {
            if !echo_api::valid_email(addr) {
                return AuthorityStatus::Invalid;
            }
        }
        // The verifiers are attacker-influenced if the authority is compromised:
        // reject an absurd iteration count that would DoS later logins.
        if !super::scram::verifier_ok(scram256) || (!scram512.is_empty() && !super::scram::verifier_ok(scram512)) {
            return AuthorityStatus::Invalid;
        }
        match self.db.provision_account(name, scram256, scram512, email) {
            Ok(()) => AuthorityStatus::Ok,
            Err(RegError::Exists) => AuthorityStatus::AlreadyExists,
            Err(_) => AuthorityStatus::Internal,
        }
    }

    pub fn authority_register(&mut self, name: &str, creds: Option<db::Credentials>, email: Option<String>) -> AuthorityStatus {
        let Some(creds) = creds else { return AuthorityStatus::Internal };
        // Re-check the freeze pre_check saw: defcon may have frozen registrations
        // during the ~1s off-lock derivation between the two calls.
        if self.db.registrations_frozen() || self.db.readonly() {
            return AuthorityStatus::Invalid;
        }
        // The IRC REGISTER rejects a FORBIDden email; a website write must too —
        // and must reject a malformed/CRLF-bearing one before it reaches a mail header.
        if let Some(addr) = &email {
            if !echo_api::valid_email(addr) || self.db.is_forbidden(echo_api::ForbidKind::Email, addr).is_some() {
                return AuthorityStatus::Invalid;
            }
        }
        let addr = email.clone();
        let status = match self.db.register_prepared(name, creds, email) {
            Ok(()) => AuthorityStatus::Ok,
            Err(RegError::Exists) => AuthorityStatus::AlreadyExists,
            Err(RegError::Internal) => AuthorityStatus::Internal,
        };
        if status == AuthorityStatus::Ok && !self.db.is_verified(name) {
            if let Some(addr) = addr {
                let code = self.db.issue_code(name, db::CodeKind::Confirm);
                let mail = echo_api::email::confirm(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), name, &code, self.db.email_confirm_url(), &self.lang_for_account(name));
                self.emit_irc(NetAction::SendEmail { to: addr, subject: mail.subject, text: mail.text, html: Some(mail.html) });
            }
        }
        status
    }

    /// The account's canonical name and its SHA-256 verifier (owned), so a caller
    /// can run the PBKDF2 verify OFF the engine lock. At production iteration
    /// counts that derivation is ~1s of CPU — never run it while holding the lock
    /// (it would freeze the whole daemon); fetch here, then `scram::verify_plain`
    /// on a blocking thread.
    pub fn scram_verifier(&self, name: &str) -> Option<(String, String)> {
        self.db.scram_lookup(name, "SCRAM-SHA-256").map(|(a, v)| (a.to_string(), v.to_string()))
    }

    /// gRPC login pre-check: apply the same guards the IRC IDENTIFY/SASL paths do
    /// before the ~1s verify. Refuses a suspended or throttled account — the
    /// website only sees a plain failure, so it can't tell these from a bad
    /// password — and otherwise returns the canonical name + verifier to check
    /// off the engine lock. Feed the result back through [`Self::authority_note_auth`].
    pub fn authority_auth_begin(&self, name: &str) -> Option<(String, String)> {
        if let Some(acc) = self.db.resolve_account(name) {
            if self.db.is_suspended(acc) {
                return None;
            }
        }
        if self.db.auth_lockout(name).is_some() {
            return None;
        }
        self.scram_verifier(name)
    }

    /// Record a gRPC login attempt in the brute-force backoff, exactly like IDENTIFY.
    pub fn authority_note_auth(&mut self, name: &str, ok: bool) {
        self.db.note_auth(name, ok);
    }

    pub fn authority_set_password(&mut self, account: &str, creds: Option<db::Credentials>) -> AuthorityStatus {
        let Some(creds) = creds else { return AuthorityStatus::Internal };
        // set_credentials's only Err is Internal, which here always means "no such account".
        match self.db.set_credentials(account, creds) {
            Ok(()) => AuthorityStatus::Ok,
            Err(_) => AuthorityStatus::NotFound,
        }
    }

    pub fn authority_set_email(&mut self, account: &str, email: Option<String>) -> AuthorityStatus {
        if let Some(addr) = &email {
            if !echo_api::valid_email(addr) {
                return AuthorityStatus::Invalid; // no CRLF/garbage into a mail header
            }
            if self.db.is_forbidden(echo_api::ForbidKind::Email, addr).is_some() {
                return AuthorityStatus::Invalid; // same email-forbid policy as IRC SET
            }
        }
        match self.db.set_email(account, email) {
            Ok(()) => AuthorityStatus::Ok,
            Err(_) => AuthorityStatus::NotFound,
        }
    }

    pub fn authority_confirm(&mut self, account: &str, code: &str) -> AuthorityStatus {
        if !self.db.exists(account) {
            return AuthorityStatus::NotFound;
        }
        if self.db.is_verified(account) {
            return AuthorityStatus::Ok; // already confirmed — idempotent, not an error
        }
        if !self.db.take_code(account, db::CodeKind::Confirm, code) {
            return AuthorityStatus::Invalid;
        }
        match self.db.verify_account(account) {
            Ok(()) => AuthorityStatus::Ok,
            Err(_) => AuthorityStatus::Internal,
        }
    }

    // Drop reuses the exact cleanup a peer's gossiped drop already triggers
    // locally (channel release + session logout) — see `handle_account_gone`.
    pub fn authority_drop(&mut self, account: &str) -> AuthorityStatus {
        match self.db.drop_account(account) {
            Ok(true) => {
                self.handle_account_gone(account, "was dropped", true);
                AuthorityStatus::Ok
            }
            Ok(false) => AuthorityStatus::NotFound,
            Err(_) => AuthorityStatus::Internal,
        }
    }

    // Unlike Drop, the account itself is untouched — only its active IRC
    // sessions are logged out (no channel cleanup, this isn't "account gone").
    pub fn authority_force_logout(&mut self, account: &str) -> u32 {
        let victims = self.network.uids_logged_into(account);
        let n = victims.len() as u32;
        let ns = self.nick_service.clone();
        for uid in victims {
            self.network.clear_account(&uid);
            self.emit_irc(NetAction::Metadata { target: uid.clone(), key: "accountname".to_string(), value: String::new() });
            if let Some(ns) = &ns {
                let text = echo_api::render(&self.lang_for_account(account), "You have been logged out of \x02{account}\x02.", &[("account", account.to_string())]);
                self.emit_irc(NetAction::Notice { from: ns.clone(), to: uid, text });
            }
        }
        n
    }

    pub fn authority_group_nick(&mut self, nick: &str, account: &str) -> AuthorityStatus {
        if self.db.account(nick).is_some() {
            return AuthorityStatus::Invalid; // nick is itself a registered account
        }
        // Same namespace guards as REGISTER: grouping reserves the nick, so a website
        // can't group a look-alike/forbidden nick, and one account can't squat many.
        if let Err(status) = self.authority_name_ok(nick) {
            return status;
        }
        if self.db.grouped_nicks(account).len() >= 25 {
            return AuthorityStatus::Invalid;
        }
        match self.db.group_nick(nick, account) {
            Ok(()) => AuthorityStatus::Ok,
            Err(_) => AuthorityStatus::NotFound, // group_nick's only Err means the account doesn't exist
        }
    }

    pub fn authority_ungroup_nick(&mut self, nick: &str) -> AuthorityStatus {
        match self.db.ungroup_nick(nick) {
            Ok(true) => AuthorityStatus::Ok,
            Ok(false) => AuthorityStatus::NotFound,
            Err(_) => AuthorityStatus::Internal,
        }
    }

    // Authority side of the IRCv3 account-registration relay (draft/account-
    // registration). REGISTER hands off to the link layer (which derives the
    // password off-thread) via DeferRegister; VERIFY/RESEND/STATUS are answered
    // here directly against the emailed-code flow.
    pub(crate) fn account_request(&mut self, reqid: String, origin: String, kind: String, account: String, p2: String, p3: String) -> Vec<NetAction> {
        if kind.eq_ignore_ascii_case("REGISTER") {
            let email = if p2.is_empty() || p2 == "*" { None } else { Some(p2) };
            return vec![NetAction::DeferRegister { account, password: p3, email, reply: RegReply::Relay { reqid, kind, origin } }];
        }

        // Relay-only replies, built directly (REGISTER goes through complete_register).
        let resp = |status: &str, code: &str, message: &str| {
            vec![NetAction::AccountResponse {
                reqid: reqid.clone(),
                origin: origin.clone(),
                kind: kind.clone(),
                account: account.clone(),
                status: status.to_string(),
                code: code.to_string(),
                message: message.to_string(),
            }]
        };
        // Identity is the website's in external mode; the relay shouldn't manage it.
        if self.db.external_accounts() {
            return resp("error", "ACCOUNT_REGISTRATION_DISABLED", "Accounts are managed on the website.");
        }

        match kind.to_ascii_uppercase().as_str() {
            // VERIFY <account> <code> — confirm the emailed code.
            "VERIFY" => {
                let code = if !p2.is_empty() { p2 } else { p3 };
                if self.db.account(&account).is_none() {
                    resp("error", "ACCOUNT_UNKNOWN", "No such account.")
                } else if self.db.take_code(&account, db::CodeKind::Confirm, &code) {
                    let _ = self.db.verify_account(&account);
                    resp("success", "*", "Account verified.")
                } else {
                    resp("error", "INVALID_CODE", "That verification code is wrong or has expired.")
                }
            }
            // RESEND <account> — issue and email a fresh confirmation code.
            "RESEND" => match self.db.account(&account).map(|a| (a.verified, a.email.clone())) {
                None => resp("error", "ACCOUNT_UNKNOWN", "No such account."),
                Some((true, _)) => resp("error", "ALREADY_VERIFIED", "That account is already verified."),
                Some((false, None)) => resp("error", "NO_EMAIL", "No email address is on file for that account."),
                Some((false, Some(_))) if self.db.code_issue_wait(&account) > 0 => {
                    resp("error", "TEMPORARILY_UNAVAILABLE", "A code was just sent — please wait a moment before requesting another.")
                }
                Some((false, Some(addr))) => {
                    let code = self.db.issue_code(&account, db::CodeKind::Confirm);
                    let mail = echo_api::email::confirm(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), &account, &code, self.db.email_confirm_url(), &self.lang_for_account(&account));
                    let mut out = resp("verification_required", "VERIFICATION_REQUIRED", "A new confirmation code has been emailed.");
                    out.push(NetAction::SendEmail { to: addr, subject: mail.subject, text: mail.text, html: Some(mail.html) });
                    out
                }
            },
            // STATUS <account> — report registration/verification state.
            "STATUS" => match self.db.account(&account).map(|a| a.verified) {
                None => resp("error", "ACCOUNT_UNKNOWN", "No such account."),
                Some(true) => resp("success", "VERIFIED", "Account is registered and verified."),
                Some(false) => resp("verification_required", "VERIFICATION_REQUIRED", "Account is registered but not yet verified."),
            },
            _ => Vec::new(),
        }
    }

    // Cheap gate run before the expensive derivation: reject an already-taken name
    // outright, and rate-limit the rest so a REGISTER flood can't pin CPU. Returns
    // the rejection response if refused, or None to proceed (spending a token).
    pub fn pre_register_check(&mut self, account: &str, reply: &RegReply) -> Option<Vec<NetAction>> {
        if self.db.external_accounts() {
            return Some(reg_reply(reply, RegOutcome::External, account));
        }
        if self.db.registrations_frozen() || self.db.readonly() {
            return Some(reg_reply(reply, RegOutcome::Frozen, account));
        }
        if self.db.exists(account) {
            return Some(reg_reply(reply, RegOutcome::Exists, account));
        }
        if self.db.is_forbidden(echo_api::ForbidKind::Nick, account).is_some() {
            return Some(reg_reply(reply, RegOutcome::Forbidden, account));
        }
        if !self.reg_limiter.allow() {
            return Some(reg_reply(reply, RegOutcome::RateLimited, account));
        }
        None
    }

    // Commit credentials the link layer derived off-thread, then answer `reply`.
    pub fn complete_register(&mut self, account: &str, creds: Option<db::Credentials>, email: Option<String>, reply: RegReply) -> Vec<NetAction> {
        let Some(creds) = creds else {
            return reg_reply(&reply, RegOutcome::Internal, account);
        };
        // A forbidden email pattern (OperServ FORBID EMAIL) blocks registration.
        if let Some(addr) = &email {
            if self.db.is_forbidden(echo_api::ForbidKind::Email, addr).is_some() {
                return reg_reply(&reply, RegOutcome::ForbiddenEmail, account);
            }
        }
        let addr = email.clone();
        let outcome = match self.db.register_prepared(account, creds, email) {
            Ok(()) if self.db.is_verified(account) => RegOutcome::Ok,
            Ok(()) => RegOutcome::VerifyRequired,
            Err(RegError::Exists) => RegOutcome::Exists,
            Err(RegError::Internal) => RegOutcome::Internal,
        };
        let needs_verify = matches!(outcome, RegOutcome::VerifyRequired);
        let mut out = reg_reply(&reply, outcome, account);
        self.track_accounts(&out);
        // Unverified (email confirmation applies): email a code, on either the
        // NickServ or the account-registration relay path. The relay reply
        // already carries verification_required; NickServ users get a notice.
        if needs_verify {
            if self.db.registration_vouch() {
                // Invite-only: the account waits for a member to VOUCH, not an email code.
                if let RegReply::NickServ { agent, uid, .. } = &reply {
                    out.push(NetAction::Notice { from: agent.clone(), to: uid.clone(), text: echo_api::render(&self.lang_for_account(account), "Your account is pending. Ask an existing member to vouch for you with \x02/msg NickServ VOUCH {account}\x02.", &[("account", account.to_string())]) });
                }
            } else if let Some(addr) = addr {
                let code = self.db.issue_code(account, db::CodeKind::Confirm);
                let mail = echo_api::email::confirm(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), account, &code, self.db.email_confirm_url(), &self.lang_for_account(account));
                out.push(NetAction::SendEmail { to: addr, subject: mail.subject, text: mail.text, html: Some(mail.html) });
                if let RegReply::NickServ { agent, uid, .. } = &reply {
                    out.push(NetAction::Notice { from: agent.clone(), to: uid.clone(), text: echo_api::render(&self.lang_for_account(account), "A confirmation code has been emailed to you. Confirm with \x02CONFIRM <code>\x02.", &[]) });
                }
            }
        }
        out
    }

    // Commit a password change the link layer derived off-thread, then notice the user.
    pub fn complete_password_change(&mut self, account: &str, creds: Option<db::Credentials>, agent: &str, uid: &str) -> Vec<NetAction> {
        let lang = self.lang_for_account(account);
        let text = match creds.and_then(|c| self.db.set_credentials(account, c).ok()) {
            Some(()) => echo_api::render(&lang, "Your password for \x02{account}\x02 has been changed.", &[("account", account.to_string())]),
            None => echo_api::render(&lang, "Sorry, that didn't work. Please try again in a moment.", &[]),
        };
        vec![NetAction::Notice { from: agent.to_string(), to: uid.to_string(), text }]
    }

    /// Finish a deferred password verify once the off-thread `verify_plain` gave
    /// `ok`. The cheap pre-checks (exists/suspended/lockout) already ran in the
    /// caller; this is only the success/failure finish. IDENTIFY reuses the same
    /// ctx helpers the inline path did, so its login side-effects (login, notice,
    /// AJOIN, vhost, memo notice) stay identical.
    pub fn complete_authenticate(&mut self, ok: bool, then: AuthThen) -> Vec<NetAction> {
        let actions = match then {
            AuthThen::Identify { uid, agent, name, account } => self.finish_identify(ok, uid, agent, name, account),
            AuthThen::Login { uid, agent, name, account, nick } => {
                let mut out = self.finish_identify(ok, uid.clone(), agent, name, account);
                if ok {
                    out.extend(self.recover_nick(&uid, &nick));
                }
                out
            }
            AuthThen::Sasl { agent, client, account, password } => {
                // Feed the same brute-force throttle IDENTIFY uses (success clears it,
                // failure grows the backoff) — but ONLY for a password verify; a failed
                // one-time keycard redemption must not lock out the account's password.
                if password {
                    self.db.note_auth(&account, ok);
                }
                if ok {
                    self.sasl_login("SASL PLAIN", &agent, &client, account)
                } else {
                    self.sasl_deny("SASL PLAIN", &agent, &client, Some(&account), "bad password")
                }
            }
        };
        // This runs in the link layer, off the handle() path, so the login's
        // accountname metadata never reaches track_accounts in handle(). Apply it
        // here so echo's own account map is authoritative and doesn't depend on the
        // ircd reflecting the metadata back — which is a no-op when re-authenticating
        // an already-logged-in user after a services relink, leaving the user unable
        // to use their access despite a successful login.
        self.track_accounts(&actions);
        actions
    }

    // The login side-effects shared by IDENTIFY and LOGIN: throttle bookkeeping,
    // the welcome + auto-join + vhost + waiting-memo notice, and the auth-feed line.
    fn finish_identify(&mut self, ok: bool, uid: String, agent: String, name: String, account: String) -> Vec<NetAction> {
        self.db.note_auth(&name, ok);
        let lang = self.lang_for_account(&account);
        let mut ctx = ServiceCtx { lang: lang.clone(), ..Default::default() };
        if !ok {
            ctx.count("nickserv.identify_fail");
            ctx.fail(&agent, &uid, "IDENTIFY", "INVALID_CREDENTIALS", "Invalid password. Please try again.");
        } else {
            ctx.login(&uid, &account);
            ctx.count("nickserv.identify");
            ctx.notice(&agent, &uid, echo_api::render(&lang, "You're now identified as \x02{account}\x02. Welcome back!", &[("account", account.clone())]));
            for entry in self.db.ajoin_list(&account) {
                ctx.force_join(&uid, &entry.channel, &entry.key);
            }
            let now = self.now_secs();
            let vhost = self.db.account(&account).and_then(|a| {
                a.vhost.as_ref().filter(|v| v.expires.is_none_or(|e| e > now)).map(|v| v.host.clone())
            });
            if let Some(host) = vhost {
                ctx.apply_vhost(&uid, &host);
            }
            // Publish the account's public profile as IRCv3 metadata to this session.
            for field in echo_api::ProfileField::ALL {
                if let Some(v) = self.db.profile_field(&account, field) {
                    ctx.metadata(&uid, field.meta_key(), &v);
                }
            }
            // Re-apply the account's OperServ SWHOIS line (per-connection on the ircd).
            if let Some(swhois) = self.db.swhois(&account) {
                ctx.metadata(&uid, "swhois", &swhois);
            }
            // Re-apply the account's persistent SIGNORE list (per-connection too).
            let signore = self.db.signore(&account);
            if !signore.is_empty() {
                ctx.metadata(&uid, "signore", &signore.join(" "));
            }
            let unread = self.db.unread_memos(&account);
            if unread > 0 && self.db.memo_notify_on(&account) {
                ctx.notice(&agent, &uid, echo_api::render_plural(&lang, unread as u64, "You have \x02{unread}\x02 new memo. Read it with \x02/msg MemoServ READ NEW\x02.", "You have \x02{unread}\x02 new memos. Read them with \x02/msg MemoServ READ NEW\x02.", &[("unread", unread.to_string())]));
            }
        }
        for key in std::mem::take(&mut ctx.stats) {
            self.bump(&key);
        }
        let feed = if ok {
            self.auth_report(true, Some(&account), "NickServ IDENTIFY", &uid, None)
        } else {
            self.auth_report(false, Some(&name), "NickServ IDENTIFY", &uid, Some("bad password"))
        };
        let mut actions = ctx.actions;
        actions.extend(feed);
        actions
    }

    // Reclaim `nick` for `uid` after a LOGIN: rename any other session off it (to a
    // guest nick), then move the caller onto it.
    fn recover_nick(&mut self, uid: &str, nick: &str) -> Vec<NetAction> {
        let mut out = Vec::new();
        if let Some(ghost) = self.network.uid_by_nick(nick).map(str::to_string) {
            if ghost != uid {
                let guest = echo_api::next_guest_nick(&self.guest_nick, &mut self.enforce_seq, &self.network, &self.db);
                out.push(NetAction::ForceNick { uid: ghost, nick: guest });
            }
        }
        if self.network.nick_of(uid) != Some(nick) {
            out.push(NetAction::ForceNick { uid: uid.to_string(), nick: nick.to_string() });
        }
        out
    }
}
