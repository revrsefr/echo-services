use super::*;

impl Engine {
    // SASL agent side of the exchange the ircd relays to us (modes H/S/C/D), per
    // IRCv3 SASL 3.2. On success we set the client's account (drives 900) then
    // report success (drives 903); a bad credential or unknown mechanism reports
    // failure (drives 904). PLAIN and SCRAM-SHA-256/512 are supported.
    pub(crate) fn sasl(&mut self, client: String, mode: String, data: Vec<String>) -> Vec<NetAction> {
        let agent = match self.services.first() {
            Some(s) => s.uid().to_string(),
            None => return Vec::new(),
        };
        let mk = |mode: &str, d: Vec<String>| {
            vec![NetAction::Sasl { agent: agent.clone(), client: client.clone(), mode: mode.to_string(), data: d }]
        };
        match mode.as_str() {
            "H" => {
                // The ircd sends the client's real host + IP before the exchange;
                // keep it for the auth feed (the client isn't connected yet).
                self.remember_sasl_source(&client, &data);
                Vec::new()
            }
            "S" => {
                self.sweep_sasl();
                if self.sasl_sessions.len() >= MAX_SASL_SESSIONS {
                    return mk("D", vec!["F".to_string()]); // too many in flight
                }
                match data.first().map(String::as_str) {
                    Some("PLAIN") => {
                        self.stash_sasl(client.clone(), SaslSession::Plain { response: String::new() });
                        mk("C", vec!["+".to_string()]) // empty challenge -> client sends the payload
                    }
                    Some("EXTERNAL") => {
                        // The ircd appends the client's TLS cert fingerprints after the mechanism.
                        let fingerprints = data.iter().skip(1).map(|f| f.to_ascii_lowercase()).collect();
                        self.stash_sasl(client.clone(), SaslSession::External { fingerprints });
                        mk("C", vec!["+".to_string()]) // client sends its authzid (or "+")
                    }
                    Some(mech) if scram::Hash::from_mech(mech).is_some() => {
                        let hash = scram::Hash::from_mech(mech).unwrap();
                        self.stash_sasl(client.clone(), SaslSession::Scram { hash, step: ScramStep::ClientFirst });
                        mk("C", vec!["+".to_string()]) // client sends client-first next
                    }
                    _ => mk("D", vec!["F".to_string()]), // unsupported mechanism
                }
            }
            "C" => {
                let chunk = data.first().map(String::as_str).unwrap_or("");
                match self.sasl_sessions.remove(&client).map(|t| t.session) {
                    None => mk("D", vec!["F".to_string()]),
                    Some(SaslSession::Plain { mut response }) => {
                        // Reassemble the base64 response: append each chunk until
                        // one is shorter than a full chunk (or a lone "+").
                        if chunk != "+" {
                            response.push_str(chunk);
                        }
                        if response.len() > MAX_SASL_RESPONSE {
                            return mk("D", vec!["F".to_string()]);
                        }
                        if chunk.len() >= MAX_AUTHENTICATE {
                            self.stash_sasl(client.clone(), SaslSession::Plain { response });
                            return Vec::new(); // more chunks still to come
                        }
                        // Decode, then defer the verify off the lock (the login
                        // finish lands in Engine::complete_authenticate).
                        match decode_plain(&response) {
                            // A website login keycard (`kc_…`), not a password: it can't be
                            // SCRAM-verified, so redeem it off-lock (link.rs) against Django.
                            Some((authcid, passwd)) if passwd.starts_with("kc_") => {
                                let account = match self.db.resolve_account(&authcid) {
                                    Some(a) => a.to_string(),
                                    None => authcid,
                                };
                                vec![NetAction::DeferKeycard {
                                    token: passwd,
                                    account: account.clone(),
                                    then: AuthThen::Sasl { agent: agent.clone(), client: client.clone(), account, password: false },
                                }]
                            }
                            Some((authcid, passwd)) => match self.scram_verifier(&authcid) {
                                // Refuse while throttled, so SASL PLAIN can't be used to
                                // brute-force past the IDENTIFY lockout.
                                Some((account, _)) if self.db.auth_lockout(&account).is_some() => {
                                    let mut out = mk("D", vec!["F".to_string()]);
                                    out.extend(self.auth_report(false, Some(&account), "SASL PLAIN", &client, Some("rate limited")));
                                    out
                                }
                                Some((account, verifier)) => vec![NetAction::DeferAuthenticate {
                                    verifier,
                                    password: passwd,
                                    then: AuthThen::Sasl { agent: agent.clone(), client: client.clone(), account, password: true },
                                }],
                                None => {
                                    let mut out = mk("D", vec!["F".to_string()]);
                                    out.extend(self.auth_report(false, Some(&authcid), "SASL PLAIN", &client, Some("no such account")));
                                    out
                                }
                            },
                            None => mk("D", vec!["F".to_string()]),
                        }
                    }
                    Some(SaslSession::Scram { hash, step }) => self.sasl_scram(&agent, &client, hash, step, chunk),
                    Some(SaslSession::External { fingerprints }) => self.sasl_external(&agent, &client, fingerprints, chunk),
                }
            }
            "D" => {
                self.sasl_sessions.remove(&client);
                self.sasl_source.remove(&client);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    // One SCRAM step. The client's messages arrive base64-encoded in the C data
    // (except the final empty "+" acknowledgement).
    fn sasl_scram(&mut self, agent: &str, client: &str, hash: scram::Hash, step: ScramStep, chunk: &str) -> Vec<NetAction> {
        let fail = || vec![NetAction::Sasl {
            agent: agent.to_string(), client: client.to_string(), mode: "D".to_string(), data: vec!["F".to_string()],
        }];
        let challenge = |msg: String| vec![NetAction::Sasl {
            agent: agent.to_string(), client: client.to_string(), mode: "C".to_string(), data: vec![STANDARD.encode(msg)],
        }];
        let decode = |chunk: &str| STANDARD.decode(chunk).ok().and_then(|b| String::from_utf8(b).ok());

        match step {
            ScramStep::ClientFirst => {
                let Some(cf) = decode(chunk).as_deref().and_then(scram::parse_client_first) else {
                    return fail();
                };
                let Some((account, verifier)) = self.db.scram_lookup(&cf.username, hash.mech()) else {
                    return fail();
                };
                let (account, Some(verifier)) = (account.to_string(), scram::parse_verifier(verifier)) else {
                    return fail();
                };
                // Refuse while throttled, so SCRAM (Orbit's default mech) can't be used
                // to brute-force past the IDENTIFY/PLAIN lockout.
                if self.db.auth_lockout(&account).is_some() {
                    return fail();
                }
                let (server_first, nonce) = scram::server_first(&cf.cnonce, &verifier);
                let out = challenge(server_first.clone());
                self.stash_sasl(client.to_string(), SaslSession::Scram {
                    hash,
                    step: ScramStep::ClientFinal {
                        account,
                        verifier,
                        client_first_bare: cf.client_first_bare,
                        server_first,
                        gs2_header: cf.gs2_header,
                        nonce,
                    },
                });
                out
            }
            ScramStep::ClientFinal { account, verifier, client_first_bare, server_first, gs2_header, nonce } => {
                let Some(msg) = decode(chunk) else { return fail() };
                match scram::verify_final(hash, &verifier, &client_first_bare, &server_first, &gs2_header, &nonce, &msg) {
                    Some(server_final) => {
                        // Feed the same brute-force throttle as IDENTIFY/PLAIN: clear it
                        // on success, grow the backoff on a wrong password.
                        self.db.note_auth(&account, true);
                        let out = challenge(server_final);
                        self.stash_sasl(client.to_string(), SaslSession::Scram { hash, step: ScramStep::Ack { account } });
                        out
                    }
                    None => {
                        self.db.note_auth(&account, false);
                        fail()
                    }
                }
            }
            // Client acknowledged our server-final ("+"); apply the login.
            ScramStep::Ack { account } => self.sasl_login(&format!("SASL {}", hash.mech()), agent, client, account),
        }
    }

    // SASL EXTERNAL: the credential is the client's TLS cert fingerprint, which
    // the ircd handed us in the S message (already validated at the handshake).
    // Match it to an account; an authzid, if given, must name that same account.
    fn sasl_external(&self, agent: &str, client: &str, fingerprints: Vec<String>, chunk: &str) -> Vec<NetAction> {
        let authzid = if chunk == "+" || chunk.is_empty() {
            String::new()
        } else {
            match STANDARD.decode(chunk).ok().and_then(|b| String::from_utf8(b).ok()) {
                Some(a) => a,
                None => return self.sasl_deny("SASL EXTERNAL", agent, client, None, "malformed authzid"),
            }
        };
        match fingerprints.iter().find_map(|fp| self.db.certfp_owner(fp)) {
            Some(account) if authzid.is_empty() || authzid.eq_ignore_ascii_case(account) => {
                let account = account.to_string();
                self.sasl_login("SASL EXTERNAL", agent, client, account)
            }
            _ => self.sasl_deny("SASL EXTERNAL", agent, client, None, "unknown certificate"),
        }
    }
}
