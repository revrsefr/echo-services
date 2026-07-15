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
        if !self.reg_limiter.allow() {
            return Err(AuthorityStatus::RateLimited);
        }
        Ok(())
    }

    // Provision an account from pre-derived SCRAM verifiers (bulk backfill from
    // the authority). No email confirmation — the authority already vouches for it.
    pub fn authority_provision(&mut self, name: &str, scram256: &str, scram512: &str, email: Option<String>) -> AuthorityStatus {
        match self.db.provision_account(name, scram256, scram512, email) {
            Ok(()) => AuthorityStatus::Ok,
            Err(RegError::Exists) => AuthorityStatus::AlreadyExists,
            Err(_) => AuthorityStatus::Internal,
        }
    }

    pub fn authority_register(&mut self, name: &str, creds: Option<db::Credentials>, email: Option<String>) -> AuthorityStatus {
        let Some(creds) = creds else { return AuthorityStatus::Internal };
        let addr = email.clone();
        let status = match self.db.register_prepared(name, creds, email) {
            Ok(()) => AuthorityStatus::Ok,
            Err(RegError::Exists) => AuthorityStatus::AlreadyExists,
            Err(RegError::Internal) => AuthorityStatus::Internal,
        };
        if status == AuthorityStatus::Ok && !self.db.is_verified(name) {
            if let Some(addr) = addr {
                let code = self.db.issue_code(name, db::CodeKind::Confirm);
                let mail = echo_api::email::confirm(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), name, &code);
                self.emit_irc(NetAction::SendEmail { to: addr, subject: mail.subject, text: mail.text, html: Some(mail.html) });
            }
        }
        status
    }

    pub fn authority_authenticate(&self, name: &str, password: &str) -> Option<String> {
        self.db.authenticate(name, password).map(str::to_string)
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
                self.handle_account_gone(account, "was dropped");
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
                self.emit_irc(NetAction::Notice { from: ns.clone(), to: uid, text: format!("You have been logged out of \x02{account}\x02.") });
            }
        }
        n
    }

    pub fn authority_group_nick(&mut self, nick: &str, account: &str) -> AuthorityStatus {
        if self.db.account(nick).is_some() {
            return AuthorityStatus::Invalid; // nick is itself a registered account
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
    pub(crate) fn account_request(&mut self, reqid: String, kind: String, account: String, p2: String, p3: String) -> Vec<NetAction> {
        if kind.eq_ignore_ascii_case("REGISTER") {
            let email = if p2.is_empty() || p2 == "*" { None } else { Some(p2) };
            return vec![NetAction::DeferRegister { account, password: p3, email, reply: RegReply::Relay { reqid, kind } }];
        }

        // Relay-only replies, built directly (REGISTER goes through complete_register).
        let resp = |status: &str, code: &str, message: &str| {
            vec![NetAction::AccountResponse {
                reqid: reqid.clone(),
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
                Some((false, Some(addr))) => {
                    let code = self.db.issue_code(&account, db::CodeKind::Confirm);
                    let mail = echo_api::email::confirm(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), &account, &code);
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
        if self.db.registrations_frozen() {
            return Some(reg_reply(reply, RegOutcome::Frozen, account));
        }
        if self.db.exists(account) {
            return Some(reg_reply(reply, RegOutcome::Exists, account));
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
            if let Some(addr) = addr {
                let code = self.db.issue_code(account, db::CodeKind::Confirm);
                let mail = echo_api::email::confirm(self.db.email_brand(), self.db.email_accent(), self.db.email_logo(), account, &code);
                out.push(NetAction::SendEmail { to: addr, subject: mail.subject, text: mail.text, html: Some(mail.html) });
                if let RegReply::NickServ { agent, uid, .. } = &reply {
                    out.push(NetAction::Notice { from: agent.clone(), to: uid.clone(), text: "A confirmation code has been emailed to you. Confirm with \x02CONFIRM <code>\x02.".to_string() });
                }
            }
        }
        out
    }

    // Commit a password change the link layer derived off-thread, then notice the user.
    pub fn complete_password_change(&mut self, account: &str, creds: Option<db::Credentials>, agent: &str, uid: &str) -> Vec<NetAction> {
        let text = match creds.and_then(|c| self.db.set_credentials(account, c).ok()) {
            Some(()) => format!("Your password for \x02{account}\x02 has been changed."),
            None => "Sorry, that didn't work. Please try again in a moment.".to_string(),
        };
        vec![NetAction::Notice { from: agent.to_string(), to: uid.to_string(), text }]
    }
}
