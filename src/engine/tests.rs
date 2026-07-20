    use super::*;
    use echo_nickserv::NickServ;

    fn plain(authzid: &[u8], authcid: &[u8], passwd: &[u8]) -> String {
        let mut payload = Vec::new();
        payload.extend_from_slice(authzid);
        payload.push(0);
        payload.extend_from_slice(authcid);
        payload.push(0);
        payload.extend_from_slice(passwd);
        STANDARD.encode(payload)
    }

    fn engine_with(name: &str, account: &str, password: &str) -> Engine {
        // A globally-unique path per call: tests run in parallel and some share a
        // `name` (e.g. every scram_exchange caller), so a fixed path would race.
        let path = {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            std::env::temp_dir().join(format!("echo-sasl-{name}-{}-{n}.jsonl", std::process::id()))
        };
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096; // keep the debug-build verifier cheap in tests
        assert!(db.register(account, password, None).is_ok());
        Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".to_string(), guest_nick: "Guest".to_string(), guest_seq: 12345 })], db)
    }

    fn sasl(engine: &mut Engine, mode: &str, chunk: &str) -> Vec<NetAction> {
        engine.handle(NetEvent::Sasl {
            client: "000AAAAAB".to_string(),
            agent: "*".to_string(),
            mode: mode.to_string(),
            data: vec![chunk.to_string()],
        })
    }

    fn is_success(out: &[NetAction]) -> bool {
        out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "foo"))
            && out.iter().any(|a| matches!(a, NetAction::Sasl { mode, data, .. } if mode == "D" && data.as_slice() == ["S"]))
    }

    // Single-chunk PLAIN (short response) logs in.
    #[test]
    fn plain_single_chunk() {
        let mut e = engine_with("single", "foo", "sesame");
        sasl(&mut e, "S", "PLAIN");
        let out = sasl(&mut e, "C", &plain(b"", b"foo", b"sesame"));
        assert!(is_success(&out), "{out:?}");
    }

    // A routed WHOIS (mIRC double-click) asks the service's server for its idle
    // time; we must answer for our own pseudo-clients, and only them.
    #[test]
    fn idle_request_is_answered_for_our_clients_only() {
        let mut e = engine_with("idle", "foo", "sesame");
        e.set_sid("42S".into());
        let ours = e.handle(NetEvent::Idle { requester: "000AAAAAB".into(), target: "42SAAAAAA".into() });
        assert!(
            ours.iter().any(|a| matches!(a, NetAction::IdleReply { target, requester, idle, .. }
                if target == "42SAAAAAA" && requester == "000AAAAAB" && *idle == 0)),
            "expected an IDLE reply for NickServ, got {ours:?}"
        );
        let foreign = e.handle(NetEvent::Idle { requester: "000AAAAAB".into(), target: "000AAAAAZ".into() });
        assert!(!foreign.iter().any(|a| matches!(a, NetAction::IdleReply { .. })), "{foreign:?}");
    }

    // DebugServ streams auth outcomes into the log channel, and stays silent when
    // it isn't running.
    #[test]
    fn debugserv_feeds_auth_events() {
        let mut e = engine_with("dbgfeed", "foo", "sesame");
        e.set_sid("42S".into());
        e.set_log_channel(Some("#services".into()));
        e.set_debugserv_uid("42SAAAAAO");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into(), ip: "0.0.0.0".into() });

        sasl(&mut e, "S", "PLAIN");
        let ok = sasl(&mut e, "C", &plain(b"", b"foo", b"sesame"));
        assert!(is_success(&ok), "login should still work: {ok:?}");
        assert!(
            ok.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text }
                if from == "42SAAAAAO" && to == "#services" && text.contains("[AUTH]") && text.contains("SASL PLAIN"))),
            "expected an AUTH feed line from DebugServ, got {ok:?}"
        );

        sasl(&mut e, "S", "PLAIN");
        let bad = sasl(&mut e, "C", &plain(b"", b"foo", b"wrongpass"));
        assert!(!is_success(&bad), "wrong password must not log in: {bad:?}");
        assert!(
            bad.iter().any(|a| matches!(a, NetAction::Privmsg { from, text, .. }
                if from == "42SAAAAAO" && text.contains("[AUTH]") && text.contains("bad password"))),
            "expected an AUTH failure line, got {bad:?}"
        );

        // Disabled (no uid) -> the feed is silent.
        e.set_debugserv_uid("");
        sasl(&mut e, "S", "PLAIN");
        let quiet = sasl(&mut e, "C", &plain(b"", b"foo", b"sesame"));
        assert!(
            !quiet.iter().any(|a| matches!(a, NetAction::Privmsg { to, .. } if to == "#services")),
            "no feed line when DebugServ is off: {quiet:?}"
        );
    }

    // A response that is not a multiple of 400 splits into 400 + remainder.
    #[test]
    fn plain_chunked_412() {
        let pw = "bar".repeat(100);
        let mut e = engine_with("c412", "foo", &pw);
        let auth = plain(b"foo", b"foo", pw.as_bytes());
        assert_eq!(auth.len(), 412);
        sasl(&mut e, "S", "PLAIN");
        assert!(sasl(&mut e, "C", &auth[0..400]).is_empty());
        let out = sasl(&mut e, "C", &auth[400..]);
        assert!(is_success(&out), "{out:?}");
    }

    // A response that is an exact multiple of 400 ends with a trailing "+".
    #[test]
    fn plain_chunked_800() {
        let pw = "x".repeat(592);
        let mut e = engine_with("c800", "foo", &pw);
        let auth = plain(b"foo", b"foo", pw.as_bytes());
        assert_eq!(auth.len(), 800);
        sasl(&mut e, "S", "PLAIN");
        assert!(sasl(&mut e, "C", &auth[0..400]).is_empty());
        assert!(sasl(&mut e, "C", &auth[400..800]).is_empty());
        let out = sasl(&mut e, "C", "+");
        assert!(is_success(&out), "{out:?}");
    }

    // Wrong password fails.
    #[test]
    fn plain_bad_password() {
        let mut e = engine_with("bad", "foo", "sesame");
        sasl(&mut e, "S", "PLAIN");
        let out = sasl(&mut e, "C", &plain(b"", b"foo", b"wrong"));
        assert!(out.iter().any(|a| matches!(a, NetAction::Sasl { mode, data, .. } if mode == "D" && data.as_slice() == ["F"])), "{out:?}");
    }

    // SCRAM (Orbit's default mech) must honour the brute-force lockout — else a
    // throttled attacker could switch to SCRAM and keep guessing unthrottled.
    #[test]
    fn sasl_scram_refuses_a_locked_out_account() {
        let mut e = engine_with("scramlock", "foo", "sesame");
        for _ in 0..10 {
            e.db.note_auth("foo", false);
        }
        assert!(e.db.auth_lockout("foo").is_some(), "account is throttled after repeated failures");
        // A SCRAM client-first for the locked account is refused (D/F), never challenged.
        sasl(&mut e, "S", "SCRAM-SHA-256");
        let out = sasl(&mut e, "C", &STANDARD.encode("n,,n=foo,r=cnonce"));
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Sasl { mode, data, .. } if mode == "D" && data.as_slice() == ["F"])),
            "locked-out SCRAM is refused, not challenged: {out:?}"
        );
    }

    // The single reply datum of a C/D action (SCRAM messages are single-chunk).
    fn datum(out: &[NetAction]) -> (&str, &str) {
        match out.first() {
            Some(NetAction::Sasl { mode, data, .. }) => (mode.as_str(), data[0].as_str()),
            other => panic!("expected a SASL action, got {other:?}"),
        }
    }

    // Drive a full SCRAM exchange through the engine, playing the client, and
    // return the final actions. `login_pw` may differ from the registered one.
    fn scram_exchange(mech: &str, login_pw: &str) -> Vec<NetAction> {
        use scram::Hash;
        let hash = Hash::from_mech(mech).unwrap();
        let mut e = engine_with("scram", "foo", "sesame");

        assert_eq!(datum(&sasl(&mut e, "S", mech)), ("C", "+"));

        let client_first_bare = "n=foo,r=cnonce";
        let client_first = format!("n,,{client_first_bare}");
        let first_out = sasl(&mut e, "C", &STANDARD.encode(&client_first));
        let (mode, b64) = datum(&first_out);
        assert_eq!(mode, "C");
        let server_first = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();

        // Reconstruct salt/iterations from server-first and forge the proof.
        let salt = STANDARD.decode(server_first.split(",s=").nth(1).unwrap().split(',').next().unwrap()).unwrap();
        let iters: u32 = server_first.rsplit(",i=").next().unwrap().parse().unwrap();
        let full_nonce = server_first.split("r=").nth(1).unwrap().split(',').next().unwrap();

        let salted = scram::hi(hash, login_pw.as_bytes(), &salt, iters);
        let client_key = scram::hmac(hash, &salted, b"Client Key");
        let stored_key = scram::h(hash, &client_key);
        let without_proof = format!("c=biws,r={full_nonce}");
        let auth = format!("{client_first_bare},{server_first},{without_proof}");
        let proof = scram::xor(&client_key, &scram::hmac(hash, &stored_key, auth.as_bytes()));
        let client_final = format!("{without_proof},p={}", STANDARD.encode(&proof));

        let final_out = sasl(&mut e, "C", &STANDARD.encode(&client_final));
        // On success the engine sends server-final (C v=...); the client then acks.
        match datum(&final_out) {
            ("C", _) => sasl(&mut e, "C", "+"),
            _ => final_out,
        }
    }

    #[test]
    fn scram_sha256_success() {
        assert!(is_success(&scram_exchange("SCRAM-SHA-256", "sesame")));
    }

    #[test]
    fn scram_sha512_success() {
        assert!(is_success(&scram_exchange("SCRAM-SHA-512", "sesame")));
    }

    #[test]
    fn scram_bad_password() {
        let out = scram_exchange("SCRAM-SHA-256", "millet");
        assert!(out.iter().any(|a| matches!(a, NetAction::Sasl { mode, data, .. } if mode == "D" && data.as_slice() == ["F"])), "{out:?}");
    }

    #[test]
    fn scram_unknown_user_fails() {
        let mut e = engine_with("scramnouser", "foo", "sesame");
        sasl(&mut e, "S", "SCRAM-SHA-256");
        let out = sasl(&mut e, "C", &STANDARD.encode("n,,n=ghost,r=cnonce"));
        assert_eq!(datum(&out), ("D", "F"));
    }

    // Start a SASL exchange for an arbitrary client uid.
    fn start(e: &mut Engine, client: &str) -> Vec<NetAction> {
        e.handle(NetEvent::Sasl { client: client.into(), agent: "*".into(), mode: "S".into(), data: vec!["PLAIN".into()] })
    }

    // A client that starts SASL then vanishes must not linger forever.
    #[test]
    fn abandoned_session_swept_after_ttl() {
        let mut e = engine_with("swept", "foo", "sesame");
        start(&mut e, "AAA");
        assert!(e.sasl_sessions.contains_key("AAA"));
        // Backdate it past the TTL; guarded so a just-booted monotonic clock can't panic.
        if let Some(stale) = Instant::now().checked_sub(SASL_SESSION_TTL + Duration::from_secs(1)) {
            e.sasl_sessions.get_mut("AAA").unwrap().touched = stale;
            start(&mut e, "BBB"); // any new start sweeps first
            assert!(!e.sasl_sessions.contains_key("AAA"), "stale exchange should be swept");
            assert!(e.sasl_sessions.contains_key("BBB"));
        }
    }

    // The map is hard-capped so a flood of half-open exchanges can't exhaust memory.
    #[test]
    fn concurrent_sessions_capped() {
        let mut e = engine_with("capped", "foo", "sesame");
        for i in 0..MAX_SASL_SESSIONS {
            assert_eq!(datum(&start(&mut e, &format!("u{i}"))), ("C", "+"));
        }
        assert_eq!(datum(&start(&mut e, "over")), ("D", "F"), "over-cap start must be refused");
    }

    // A QUIT drops any half-finished exchange for that uid.
    #[test]
    fn session_cleared_on_quit() {
        let mut e = engine_with("quit", "foo", "sesame");
        start(&mut e, "ZZZ");
        assert!(e.sasl_sessions.contains_key("ZZZ"));
        e.handle(NetEvent::Quit { uid: "ZZZ".into(), reason: String::new() });
        assert!(!e.sasl_sessions.contains_key("ZZZ"), "quit should drop the exchange");
    }

    // Drive a SASL step with a multi-field data vector (EXTERNAL carries the
    // mechanism plus the ircd-supplied fingerprints in one message).
    fn sasl_multi(e: &mut Engine, mode: &str, data: &[&str]) -> Vec<NetAction> {
        e.handle(NetEvent::Sasl {
            client: "000AAAAAB".into(),
            agent: "*".into(),
            mode: mode.into(),
            data: data.iter().map(|s| s.to_string()).collect(),
        })
    }

    // EXTERNAL with a registered fingerprint logs in; matching is case-insensitive.
    #[test]
    fn external_success_with_registered_cert() {
        let mut e = engine_with("extok", "foo", "sesame");
        e.db.certfp_add("foo", "aabbccddeeff00112233445566778899").unwrap();
        assert_eq!(datum(&sasl_multi(&mut e, "S", &["EXTERNAL", "AABBCCDDEEFF00112233445566778899"])), ("C", "+"));
        assert!(is_success(&sasl(&mut e, "C", "+")), "empty authzid should log in");
    }

    // An authzid, if sent, must name the cert's own account.
    #[test]
    fn external_authzid_must_match() {
        let mut e = engine_with("extaz", "foo", "sesame");
        e.db.certfp_add("foo", "aabbccddeeff00112233445566778899").unwrap();
        sasl_multi(&mut e, "S", &["EXTERNAL", "aabbccddeeff00112233445566778899"]);
        assert!(is_success(&sasl(&mut e, "C", &STANDARD.encode("foo"))), "matching authzid ok");

        let mut e = engine_with("extaz2", "foo", "sesame");
        e.db.certfp_add("foo", "aabbccddeeff00112233445566778899").unwrap();
        sasl_multi(&mut e, "S", &["EXTERNAL", "aabbccddeeff00112233445566778899"]);
        assert_eq!(datum(&sasl(&mut e, "C", &STANDARD.encode("bar"))), ("D", "F"), "foreign authzid rejected");
    }

    // An unknown fingerprint, or no fingerprint at all (plaintext client), fails.
    #[test]
    fn external_without_registered_cert_fails() {
        let mut e = engine_with("extno", "foo", "sesame");
        sasl_multi(&mut e, "S", &["EXTERNAL", "0011223344556677889900aabbccddee"]);
        assert_eq!(datum(&sasl(&mut e, "C", "+")), ("D", "F"), "unknown fp rejected");

        sasl_multi(&mut e, "S", &["EXTERNAL"]); // no fingerprint supplied
        assert_eq!(datum(&sasl(&mut e, "C", "+")), ("D", "F"), "no cert rejected");
    }

    // End to end: enrol a cert with NickServ CERT ADD, then log in with EXTERNAL.
    #[test]
    fn nickserv_cert_add_enables_external() {
        let mut e = engine_with("nscert", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        let fp = "aabbccddeeff00112233445566778899";

        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(),
            to: "42SAAAAAA".into(),
            text: format!("CERT ADD sesame {fp}"),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Added"))), "{out:?}");

        sasl_multi(&mut e, "S", &["EXTERNAL", fp]);
        assert!(is_success(&sasl(&mut e, "C", "+")), "external should work after CERT ADD");
    }

    // A wrong password can't enrol a cert, and a fingerprint is one account only.
    #[test]
    fn cert_add_is_guarded_and_unique() {
        let mut e = engine_with("certguard", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        let fp = "aabbccddeeff00112233445566778899";

        let bad = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(),
            to: "42SAAAAAA".into(),
            text: format!("CERT ADD wrongpw {fp}"),
        });
        assert!(bad.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Invalid password"))), "{bad:?}");
        assert!(e.db.certfp_owner(fp).is_none(), "bad password must not enrol");

        e.db.certfp_add("foo", fp).unwrap();
        e.db.register("bar", "sesame", None).unwrap();
        assert!(matches!(e.db.certfp_add("bar", fp), Err(db::CertError::InUse)), "a fingerprint maps to one account");
    }

    // An identified caller manages certs without re-entering a password.
    #[test]
    fn cert_works_for_identified_user_without_password() {
        let mut e = engine_with("certid", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let fp = "aabbccddeeff00112233445566778899";
        let cert = |e: &mut Engine, t: String| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: t });

        let add = cert(&mut e, format!("CERT ADD {fp}"));
        assert!(add.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Added"))), "add without password: {add:?}");
        let list = cert(&mut e, "CERT LIST".into());
        assert!(list.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(fp))), "list without password: {list:?}");
        let del = cert(&mut e, format!("CERT DEL {fp}"));
        assert!(del.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Removed"))), "del without password: {del:?}");
        assert!(e.db.certfp_owner(fp).is_none(), "fingerprint removed");
    }

    // Standard replies gate: off (default) degrades a service FAIL to a notice so
    // nothing is lost; on, the structured FAIL survives with command + code.
    #[test]
    fn standard_replies_gate_service_failures() {
        let connect = |e: &mut Engine| {
            e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "h".into(), ip: "0.0.0.0".into() });
        };
        let identify_unregistered = |e: &mut Engine| e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY ghost pw".into(),
        });

        // Off: no StandardReply reaches the wire; the user still gets a notice.
        let mut off = engine_with("stdrploff", "foo", "sesame");
        connect(&mut off);
        let a = identify_unregistered(&mut off);
        assert!(a.iter().any(|x| matches!(x, NetAction::Notice { text, .. } if text.contains("isn't registered"))), "{a:?}");
        assert!(!a.iter().any(|x| matches!(x, NetAction::StandardReply { .. })), "off must degrade: {a:?}");

        // On: the FAIL survives, carrying the command and machine code.
        let mut on = engine_with("stdrplon", "foo", "sesame");
        on.set_standard_replies(true);
        connect(&mut on);
        let b = identify_unregistered(&mut on);
        let hit = b.iter().find_map(|x| match x {
            NetAction::StandardReply { kind, command, code, .. } => Some((kind.verb(), command.clone(), code.clone())),
            _ => None,
        });
        assert_eq!(hit, Some(("FAIL", "IDENTIFY".to_string(), "ACCOUNT_NOT_REGISTERED".to_string())), "{b:?}");
    }

    // IDENTIFY logs in, LOGOUT clears the accountname (ircd emits RPL_LOGGEDOUT).
    #[test]
    fn nickserv_logout_clears_account() {
        let mut e = engine_with("nslogout", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() , ip: "0.0.0.0".into() });

        let login = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(),
            to: "42SAAAAAA".into(),
            text: "IDENTIFY sesame".into(),
        });
        assert!(login.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "foo")), "{login:?}");

        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(),
            to: "42SAAAAAA".into(),
            text: "LOGOUT".into(),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value.is_empty())), "logout clears accountname: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAB" && nick == "Guest12345")), "logout renames to guest nick: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("logged out"))), "{out:?}");
    }

    fn logout(e: &mut Engine, uid: &str) -> Vec<NetAction> {
        e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "LOGOUT".into() })
    }

    // SET LANGUAGE stores the preference and switches replies to that language:
    // the confirmation renders in the newly-chosen language, and a later command
    // resolves the language from the account via the dispatch path.
    #[test]
    fn set_language_switches_reply_language() {
        use echo_nickserv::NickServ;
        // Minimal French catalog for this test process. English tests are unaffected:
        // they resolve to "en" and fall back to the English source string.
        let mut fr = std::collections::HashMap::new();
        fr.insert("Your language is now \x02{lang}\x02.".to_string(), "Votre langue est maintenant \x02{lang}\x02.".to_string());
        fr.insert(
            "Your language is \x02{lang}\x02. Available: {list}. Change it with \x02SET LANGUAGE <code>\x02.".to_string(),
            "Votre langue est \x02{lang}\x02. Disponibles : {list}.".to_string(),
        );
        echo_api::load_catalog(std::collections::HashMap::from([("fr".to_string(), fr)]));

        let path = std::env::temp_dir().join("echo-setlang.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.set_available_languages(vec!["fr".to_string()]);
        db.register("bob", "password1", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "bob".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        let ns = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: t.into() });

        let out = ns(&mut e, "SET LANGUAGE fr");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Votre langue est maintenant"))), "confirmation is French: {out:?}");
        assert_eq!(e.db.language_of("bob").as_deref(), Some("fr"), "the preference is stored");

        // A later command now resolves to French via the dispatch path (bob's pref).
        let out2 = ns(&mut e, "SET LANGUAGE");
        assert!(out2.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Disponibles"))), "later reply is French via ctx.lang: {out2:?}");
    }

    // A guest rename must skip a nick that's already online, or it would collide
    // with (and get) an innocent user instead of freeing the name.
    #[test]
    fn logout_skips_an_occupied_guest_nick() {
        let mut e = engine_with("guestskip", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        // Someone already holds Guest12345 (the first nick the counter would pick).
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "Guest12345".into(), host: "h".into() , ip: "0.0.0.0".into() });
        let out = logout(&mut e, "000AAAAAB");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAB" && nick == "Guest12346")),
            "logout skips the taken guest nick: {out:?}"
        );
    }

    // LOGOUT while not identified must not rename you or clear anything.
    #[test]
    fn logout_without_login_is_noop() {
        let mut e = engine_with("nologin", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "someone".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        let out = logout(&mut e, "000AAAAAB");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("not logged in"))), "{out:?}");
        assert!(!out.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "must not rename when not logged in: {out:?}");
    }

    // Regression: a second LOGOUT is a no-op, not another guest rename (the churn
    // where Guest33294 -> LOGOUT -> Guest33295).
    #[test]
    fn logout_twice_renames_only_once() {
        let mut e = engine_with("twice", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let first = logout(&mut e, "000AAAAAB");
        assert!(first.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "first logout renames: {first:?}");

        let second = logout(&mut e, "000AAAAAB");
        assert!(second.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("not logged in"))), "{second:?}");
        assert!(!second.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "second logout must not rename again: {second:?}");
    }

    // A SASL login (before the user is even bursted) is remembered, so a later
    // LOGOUT from that uid is recognised as logged in.
    #[test]
    fn sasl_login_is_tracked_for_logout() {
        let mut e = engine_with("sasllogout", "foo", "sesame");
        sasl(&mut e, "S", "PLAIN");
        let ok = sasl(&mut e, "C", &plain(b"", b"foo", b"sesame"));
        assert!(is_success(&ok), "{ok:?}");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() , ip: "0.0.0.0".into() });

        let out = logout(&mut e, "000AAAAAB");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { .. })), "sasl-authed user can log out: {out:?}");
    }

    // Regression: repeated IDENTIFY while already identified must not re-fire the
    // login (the 900 loop when the command is spammed).
    #[test]
    fn identify_twice_does_not_relogin() {
        let mut e = engine_with("reident", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        let ident = |e: &mut Engine| e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into(),
        });

        let first = ident(&mut e);
        assert!(first.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "foo")), "first identify logs in: {first:?}");

        let second = ident(&mut e);
        assert!(!second.iter().any(|a| matches!(a, NetAction::Metadata { key, .. } if key == "accountname")), "second identify must not re-login: {second:?}");
        assert!(second.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("already identified"))), "{second:?}");
    }

    // The event log is the source of truth: state survives a reopen, rebuilt by
    // folding the log (with its origin/seq metadata) rather than a snapshot.
    #[test]
    fn account_store_survives_reopen() {
        let path = std::env::temp_dir().join("echo-reopen.jsonl");
        let _ = std::fs::remove_file(&path);
        {
            let mut db = Db::open(&path, "n1");
            db.scram_iterations = 4096;
            db.register("foo", "sesame", None).unwrap();
            db.certfp_add("foo", "aabbccddeeff00112233445566778899").unwrap();
        }
        let db = Db::open(&path, "n1");
        assert_eq!(db.certfps("foo").len(), 1, "cert replayed from log");
        assert!(db.authenticate("foo", "sesame").is_some(), "account replayed from log");
    }

    // Regression: after a nick change (e.g. a guest rename, then back to your
    // real nick), IDENTIFY must authenticate the CURRENT nick, not the one held
    // at burst time — otherwise you log into the wrong account.
    #[test]
    fn identify_uses_current_nick_after_rename() {
        let mut e = engine_with("renameident", "realnick", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "Guest99999".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::NickChange { uid: "000AAAAAB".into(), nick: "realnick".into() });
        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into(),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "realnick")), "must log into the current nick's account: {out:?}");
    }

    // Losing a name to a gossiped remote claim releases the local channels that
    // account founded — and a bot assigned to one must part, not linger, even
    // though this cleanup runs outside the dispatch path.
    #[test]
    fn gossip_account_drop_parts_orphaned_channel_bot() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-gossipbot.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("alice".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.db.register_channel("#hers", "alice").unwrap();
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: "BOT ADD Bendy bot serv.host Helper".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: "ASSIGN #hers Bendy".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ServiceJoin { channel, .. } if channel == "#hers")), "bot joins the channel");

        // alice is dropped on another node; the drop arrives by gossip and, being a
        // genuine removal, releases her founderless channel.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        e.gossip_ingest(LogEntry::for_test("peer", 0, 1, db::Event::AccountDropped { account: "alice".into() })).unwrap();

        assert!(e.db.channel("#hers").is_none(), "the dropped account's channel is released");
        let parted = std::iter::from_fn(|| rx.try_recv().ok())
            .any(|a| matches!(a, NetAction::ServicePart { channel, .. } if channel == "#hers"));
        assert!(parted, "the assigned bot parts the released channel");
    }

    // A channel with an assigned bot: the bot (not ChanServ) fronts the in-channel
    // auto-op, so it reads as the bot setting the mode.
    #[test]
    fn assigned_bot_fronts_channel_auto_op() {
        use echo_botserv::BotServ;
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-botfront.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#room", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("alice".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: "BOT ADD Bendy bot serv.host Helper".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: "ASSIGN #room Bendy".into() });
        let botuid = out.iter().find_map(|a| match a {
            NetAction::ServiceJoin { uid, channel, .. } if channel == "#room" => Some(uid.clone()),
            _ => None,
        }).expect("bot joins #room");

        // Founder alice joins: the auto-op is sourced from the bot, not ChanServ.
        let join = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: false });
        let src = join.iter().find_map(|a| match a {
            NetAction::ChannelMode { from, modes, .. } if modes.contains('o') => Some(from.clone()),
            _ => None,
        }).expect("alice auto-opped");
        assert_eq!(src, botuid, "auto-op fronts as the assigned bot");
        assert_ne!(src, "42SAAAAAB", "not sourced from ChanServ");
    }

    // !seen nick in a bot channel: the bot answers in the channel with the nick's
    // last message there (fantasy injects the channel).
    #[test]
    fn fantasy_seen_reports_channel_last_message() {
        use echo_botserv::BotServ;
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-seenchan.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#room", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("alice".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAA".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let assign = e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAD".into(), text: "BOT ADD Bendy bot serv.host Helper".into() });
        let _ = assign;
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAD".into(), text: "ASSIGN #room Bendy".into() });
        let botuid = out.iter().find_map(|a| match a {
            NetAction::ServiceJoin { uid, channel, .. } if channel == "#room" => Some(uid.clone()),
            _ => None,
        }).expect("bot joins #room");

        // bob speaks in the channel but never joins it (online, not a member).
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "#room".into(), text: "bye bye friends".into() });

        // Online elsewhere but not in #room -> report his last message, NOT "here".
        let away = e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "#room".into(), text: "!seen bob".into() });
        assert!(
            away.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text }
                if from == &botuid && to == "#room" && text.contains("bye bye friends") && !text.contains("here right now"))),
            "online-elsewhere bob: last message, not 'here', got {away:?}"
        );

        // Now bob is actually in the channel -> "here right now".
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: false });
        let here = e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "#room".into(), text: "!seen bob".into() });
        assert!(
            here.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text }
                if from == &botuid && to == "#room" && text.contains("here right now"))),
            "bob in channel: 'here right now', got {here:?}"
        );
    }

    // A server split (SQUIT) forgets exactly the users behind it (uids carrying
    // that SID), leaving users on other servers untouched.
    #[test]
    fn squit_forgets_users_behind_the_split() {
        let mut e = engine_with("squit", "alice", "sesame");
        e.db.register("bob", "hunter2", None).unwrap();
        e.handle(NetEvent::UserConnect { uid: "0IRAAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "0XYAAAAAB".into(), nick: "bob".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "0IRAAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "0XYAAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY hunter2".into() });
        assert_eq!(e.network.account_of("0IRAAAAAB"), Some("alice"));
        assert_eq!(e.network.account_of("0XYAAAAAB"), Some("bob"));

        // Server 0IR splits away.
        e.handle(NetEvent::ServerSplit { server: "0IR".into() });
        assert!(e.network.account_of("0IRAAAAAB").is_none(), "users behind the split are forgotten");
        assert_eq!(e.network.account_of("0XYAAAAAB"), Some("bob"), "users on other servers are kept");
    }

    // A hub's SQUIT cascades: users behind the hub AND behind every server in its
    // subtree are forgotten, while unrelated servers' users are kept.
    #[test]
    fn squit_cascades_to_the_whole_subtree() {
        let mut e = engine_with("squitcascade", "alice", "sesame");
        e.db.register("bob", "hunter2", None).unwrap();
        e.db.register("carol", "pw", None).unwrap();
        // 0HB is a hub under our uplink; 0LF is a leaf behind the hub.
        e.handle(NetEvent::ServerLink { sid: "0HB".into(), parent: "42S".into() });
        e.handle(NetEvent::ServerLink { sid: "0LF".into(), parent: "0HB".into() });
        e.handle(NetEvent::UserConnect { uid: "0HBAAAAAA".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "0LFAAAAAA".into(), nick: "bob".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "0OKAAAAAA".into(), nick: "carol".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "0HBAAAAAA".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "0LFAAAAAA".into(), to: "42SAAAAAA".into(), text: "IDENTIFY hunter2".into() });
        e.handle(NetEvent::Privmsg { from: "0OKAAAAAA".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });

        // The hub splits — it and everything behind it are gone.
        e.handle(NetEvent::ServerSplit { server: "0HB".into() });
        assert!(e.network.account_of("0HBAAAAAA").is_none(), "hub user forgotten");
        assert!(e.network.account_of("0LFAAAAAA").is_none(), "user on a leaf behind the hub forgotten");
        assert_eq!(e.network.account_of("0OKAAAAAA"), Some("carol"), "unrelated server's user kept");
    }

    // A netburst that replays a user's accountname restores their services login
    // (so a services restart doesn't silently log everyone out); empty = logout.
    #[test]
    fn account_login_event_restores_session() {
        let mut e = engine_with("acctlogin", "alice", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        assert_eq!(e.network.account_of("000AAAAAB"), None, "not recognised before the metadata");
        e.handle(NetEvent::AccountLogin { uid: "000AAAAAB".into(), account: "alice".into() });
        assert_eq!(e.network.account_of("000AAAAAB"), Some("alice"), "login restored from the ircd");
        e.handle(NetEvent::AccountLogin { uid: "000AAAAAB".into(), account: String::new() });
        assert_eq!(e.network.account_of("000AAAAAB"), None, "empty account is a logout");
    }

    // OperServ REHASH is admin-only and hands the reload to the engine (resolved
    // in the link layer) addressed back to the oper who ran it.
    #[test]
    fn operserv_rehash_is_root_only() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-opsrehash.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "sesame", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("alice".to_string(), Privs::default().with(echo_api::Priv::Root));
        opers.insert("bob".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        // Root: hands off the reload, addressed back to the requesting oper.
        let a = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAH".into(), text: "REHASH".into() });
        assert!(a.iter().any(|x| matches!(x, NetAction::Rehash { requester, agent } if requester == "000AAAAAB" && agent == "42SAAAAAH")), "{a:?}");

        // An administrator (not root): denied, no reload handed off.
        let b = e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAH".into(), text: "REHASH".into() });
        assert!(!b.iter().any(|x| matches!(x, NetAction::Rehash { .. })), "a non-root oper must not rehash: {b:?}");
        assert!(b.iter().any(|x| matches!(x, NetAction::Notice { text, .. } if text.contains("root"))), "{b:?}");
    }

    // REHASH re-reads the file, applies the reloadable settings, and announces the
    // reload in the log channel as a DebugServ feed line.
    #[test]
    fn rehash_applies_config_and_announces_in_log_channel() {
        use echo_operserv::OperServ;
        let cfgpath = std::env::temp_dir().join("echo-rehash-fixture.toml");
        std::fs::write(&cfgpath, concat!(
            "[uplink]\nhost = \"127.0.0.1\"\nport = 7000\npassword = \"x\"\n\n",
            "[server]\nname = \"services.test\"\nsid = \"42S\"\ndescription = \"t\"\n",
            "standard_replies = true\nservices_channel = \"#svc\"\n\n",
            "[log]\nchannel = \"#services\"\n\n",
            "[[oper]]\naccount = \"reverse\"\nprivs = [\"admin\"]\n",
        )).unwrap();
        let path = std::env::temp_dir().join("echo-rehash-eng.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        let mut e = Engine::new(vec![Box::new(OperServ { uid: "42SAAAAAH".into() })], db);
        e.set_sid("42S".into());
        e.set_config_path(cfgpath.to_string_lossy().to_string());
        e.set_debugserv_uid("42SAAAAAO");
        e.set_log_channel(Some("#services".to_string()));

        let (ok, out) = e.rehash("000AAAAAB", "42SAAAAAH");
        assert!(ok, "a valid config reloads successfully");
        let feed = out.iter().find_map(|a| match a {
            NetAction::Privmsg { from, to, text } if from == "42SAAAAAO" && to == "#services" => Some(text.clone()),
            _ => None,
        }).expect("DebugServ announces the reload in the log channel");
        assert!(feed.contains("reloaded the configuration"), "{feed}");
        assert!(feed.contains("#svc"), "the reloaded services channel is applied and shown: {feed}");

        // A parse error must report failure (not a false "reloaded") so the control
        // CLI shows ✗, and must keep the running config.
        std::fs::write(&cfgpath, "this is not = valid toml [[[").unwrap();
        let (ok, out) = e.rehash("000AAAAAB", "42SAAAAAH");
        assert!(!ok, "a broken config reports failure");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("REHASH failed"))), "{out:?}");
        let _ = std::fs::remove_file(&cfgpath);
    }

    // A login that finishes off the handle() path (the link layer's deferred
    // password/keycard verify) must still make echo's OWN account map authoritative.
    // Otherwise re-identifying an already-logged-in user after a services relink —
    // a no-op accountname on the ircd, so nothing is reflected back — leaves them
    // unable to use their access despite a successful login.
    #[test]
    fn deferred_login_makes_account_authoritative() {
        let mut e = engine_with("deferlogin", "foo", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "h".into(), ip: "0.0.0.0".into() });
        assert_eq!(e.network.account_of("000AAAAAB"), None);
        // Exactly what the link layer does after the off-thread verify — not via handle().
        let then = echo_api::AuthThen::Identify { uid: "000AAAAAB".into(), agent: "42SAAAAAA".into(), name: "foo".into(), account: "foo".into() };
        let out = e.complete_authenticate(true, then);
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "foo")), "emits accountname metadata for the ircd");
        assert_eq!(e.network.account_of("000AAAAAB"), Some("foo"), "and is authoritative in echo's own map");
    }

    // NS LOGIN identifies AND reclaims the nick: after the deferred verify succeeds,
    // any ghost on the target nick is renamed off and the caller is moved onto it.
    #[test]
    fn login_recovers_the_nick_after_the_deferred_verify() {
        let mut e = engine_with("login", "alice", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "Guest7".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        let then = echo_api::AuthThen::Login { uid: "000AAAAAB".into(), agent: "42SAAAAAA".into(), name: "alice".into(), account: "alice".into(), nick: "alice".into() };
        let out = e.complete_authenticate(true, then);
        assert_eq!(e.network.account_of("000AAAAAB"), Some("alice"), "caller is identified");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAC" && nick != "alice")), "ghost renamed off the nick: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAB" && nick == "alice")), "caller takes the nick: {out:?}");
    }

    // LOGIN from a session already identified to that account skips the (wasteful)
    // re-verify and just reclaims the nick, like RECOVER.
    #[test]
    fn login_while_identified_reclaims_without_reverify() {
        let mut e = engine_with("loginid", "alice", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "Guest1".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.complete_authenticate(true, echo_api::AuthThen::Identify { uid: "000AAAAAB".into(), agent: "42SAAAAAA".into(), name: "alice".into(), account: "alice".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "LOGIN alice sesame".into() });
        assert!(!out.iter().any(|a| matches!(a, NetAction::DeferAuthenticate { .. })), "no re-verify when already identified: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAC" && nick != "alice")), "ghost freed: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAB" && nick == "alice")), "caller regains the nick: {out:?}");
    }

    // A suspension that arrives by gossip must end local sessions on that account,
    // just as a local SUSPEND does — the account and its channels stay put.
    #[test]
    fn gossiped_suspension_logs_out_local_sessions() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-gossipsusp.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        e.set_sid("42S".into());
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        assert_eq!(e.network.account_of("000AAAAAB"), Some("alice"), "logged in first");

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        // A peer suspends alice; the suspension gossips in.
        let entry = LogEntry::for_test("peer", 0, 1, db::Event::AccountSuspended { account: "alice".into(), by: "peer-oper".into(), reason: "spam".into(), ts: 0, expires: None });
        e.gossip_ingest(entry).unwrap();

        assert!(e.db.is_suspended("alice"), "suspension applied locally");
        assert!(e.network.account_of("000AAAAAB").is_none(), "the live session is logged out");
        assert!(e.db.exists("alice"), "the account itself is kept");
        let (mut cleared, mut told) = (false, false);
        while let Ok(a) = rx.try_recv() {
            match a {
                NetAction::Metadata { target, key, value } if target == "000AAAAAB" && key == "accountname" && value.is_empty() => cleared = true,
                NetAction::Notice { to, text, .. } if to == "000AAAAAB" && text.contains("suspended") => told = true,
                _ => {}
            }
        }
        assert!(cleared, "accountname metadata cleared on the ircd");
        assert!(told, "the user is told they were suspended");
    }

    // A network ban that arrives by gossip is pushed to the local ircd right
    // away, not just held for the next netburst — otherwise a banned user could
    // hop to a peer network until its next relink.
    #[test]
    fn gossiped_network_ban_is_pushed_to_the_ircd() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-gossipban.jsonl");
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path, "test");
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        e.set_sid("42S".into());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);

        // A peer sets a permanent G-line; it must be applied to our ircd now.
        e.gossip_ingest(LogEntry::for_test("peer", 0, 1, db::Event::AkillAdded {
            kind: "G".into(), mask: "*@evil.example".into(), setter: "peer-oper".into(), reason: "spam".into(), ts: 0, expires: None,
        })).unwrap();
        let added = std::iter::from_fn(|| rx.try_recv().ok())
            .any(|a| matches!(a, NetAction::AddLine { kind, mask, duration, .. } if kind == "G" && mask == "*@evil.example" && duration == 0));
        assert!(added, "gossiped ban pushed to the ircd immediately");

        // A peer lifts it; the ircd is told to drop the line.
        e.gossip_ingest(LogEntry::for_test("peer", 1, 2, db::Event::AkillRemoved {
            kind: "G".into(), mask: "*@evil.example".into(),
        })).unwrap();
        let lifted = std::iter::from_fn(|| rx.try_recv().ok())
            .any(|a| matches!(a, NetAction::DelLine { kind, mask } if kind == "G" && mask == "*@evil.example"));
        assert!(lifted, "gossiped ban lift removes the line from the ircd");
    }

    // Losing a registration conflict logs out the local session on that name and
    // notifies them over the services-initiated outbound path.
    #[test]
    fn lost_conflict_logs_out_local_session() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-lostconf.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 12345 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        // A local user logs into alice and registers a channel as founder.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        assert_eq!(e.network.account_of("000AAAAAB"), Some("alice"), "logged in before the conflict");
        e.db.register_channel("#hers", "alice").unwrap();

        // An earlier claim from another node wins and takes the name over.
        let winner = db::Account {
            name: "alice".into(), email: None,
            ts: 0, home: "peer".into(), scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![], suspension: None, memos: vec![], memo_ignore: vec![], memo_notify: true, memo_limit: None, greet: String::new(), no_autoop: false, no_protect: false, hide_status: false, snotice: false, language: None, vhost: None, vhost_request: None, last_seen: 0, noexpire: false, expiry_warned: false, oper_note: None,
        };
        let entry = LogEntry::for_test("peer", 0, 1, db::Event::AccountRegistered(Box::new(winner)));
        e.gossip_ingest(entry).unwrap();

        // The local session is logged out (its credential moved to the winner), but
        // the channel it founded is KEPT — the account still exists, home just moved.
        assert!(e.network.account_of("000AAAAAB").is_none(), "session cleared after losing the name");
        assert!(e.db.channel("#hers").is_some(), "the channel is kept on a takeover (the account still exists)");
        // The outbound path got a logout and a notice, but NO -r and NO release notice.
        let (mut logout, mut notice, mut unreg, mut released) = (false, false, false, false);
        while let Ok(a) = rx.try_recv() {
            match a {
                NetAction::Metadata { target, key, value } if target == "000AAAAAB" && key == "accountname" && value.is_empty() => logout = true,
                NetAction::Notice { to, text, .. } if to == "000AAAAAB" && text.contains("collided") => notice = true,
                NetAction::Notice { to, text, .. } if to == "000AAAAAB" && text.contains("released") => released = true,
                NetAction::ChannelMode { channel, modes, .. } if channel == "#hers" && modes == "-r" => unreg = true,
                _ => {}
            }
        }
        assert!(logout, "a logout must be pushed to the uplink");
        assert!(notice, "the user must be told why");
        assert!(!unreg, "a takeover must NOT de-register the channel");
        assert!(!released, "no channels are released on a takeover");
    }

    // NickServ INFO shows registration details (email only to the owner); ALIST
    // lists the channels the account founds or has access on.
    #[test]
    fn nickserv_info_and_alist() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-nsinfo.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "hunter2", None).unwrap();
        db.register_channel("#a", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_ns = |e: &mut Engine, text: &str| {
            e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() })
        };
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let info = to_ns(&mut e, "INFO");
        assert!(notice(&info, "Information for \x02alice\x02"));
        assert!(notice(&info, "Registered"));
        assert!(notice(&info, "Email"), "owner sees their email line: {info:?}");
        // alice is identified, so her INFO reports her as online.
        assert!(notice(&info, "Last seen"), "INFO has a last-seen line: {info:?}");
        assert!(notice(&info, "online"), "an identified account reads as online: {info:?}");
        // bob is registered but not connected: last-seen shows a time, not online.
        let binfo = to_ns(&mut e, "INFO bob");
        assert!(notice(&binfo, "Last seen"), "offline account still shows last-seen: {binfo:?}");
        assert!(!notice(&binfo, "online"), "an offline account is not reported online: {binfo:?}");
        assert!(notice(&to_ns(&mut e, "INFO ghost"), "isn't registered"));
        assert!(notice(&to_ns(&mut e, "ALIST"), "#a"));
    }

    // A user authenticated via SASL during registration never runs the IDENTIFY
    // path, so the engine applies their auto-join and vhost when they connect.
    #[test]
    fn sasl_login_applies_ajoin_and_vhost_on_connect() {
        let path = std::env::temp_dir().join("echo-saslajoin.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#auto", "alice").unwrap();
        db.ajoin_add("alice", "#auto", "").unwrap();
        db.set_vhost("alice", "cool.example", "boss", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        e.set_sid("42S".into());

        // SASL PLAIN logs uid 000AAAAAB into alice during registration.
        e.handle(NetEvent::Sasl { client: "000AAAAAB".into(), agent: "*".into(), mode: "S".into(), data: vec!["PLAIN".into()] });
        let out = e.handle(NetEvent::Sasl { client: "000AAAAAB".into(), agent: "*".into(), mode: "C".into(), data: vec![plain(b"", b"alice", b"sesame")] });
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "alice")), "sasl login set the account: {out:?}");

        // On connect the SASL user is force-joined and their vhost is applied,
        // exactly as an IDENTIFY would have done.
        let out = e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceJoin { uid, channel, .. } if uid == "000AAAAAB" && channel == "#auto")), "auto-join applied on SASL connect: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::SetHost { uid, host } if uid == "000AAAAAB" && host == "cool.example")), "vhost applied on SASL connect: {out:?}");

        // A plain (unauthenticated) connection gets neither.
        let out = e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        assert!(!out.iter().any(|a| matches!(a, NetAction::ForceJoin { .. } | NetAction::SetHost { .. })), "no effects for an unauthenticated connect: {out:?}");
    }

    // SET HIDE STATUS keeps the last-seen/online line to the owner and opers.
    #[test]
    fn nickserv_set_hide_status() {
        let path = std::env::temp_dir().join("echo-nshide.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "hunter2", None).unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);
        let send = |e: &mut Engine, uid: &str, text: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAA".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        send(&mut e, "000AAAAAA", "IDENTIFY sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        send(&mut e, "000AAAAAB", "IDENTIFY hunter2");

        // Default: a stranger (bob) sees alice's last-seen line.
        assert!(notice(&send(&mut e, "000AAAAAB", "INFO alice"), "Last seen"), "last-seen public by default");

        // alice hides it: strangers lose the line, owner keeps it.
        assert!(notice(&send(&mut e, "000AAAAAA", "SET HIDE STATUS ON"), "hidden"), "hide confirmed");
        let stranger = send(&mut e, "000AAAAAB", "INFO alice");
        assert!(notice(&stranger, "Registered"), "stranger still sees registration: {stranger:?}");
        assert!(!notice(&stranger, "Last seen"), "stranger no longer sees last-seen: {stranger:?}");
        assert!(notice(&send(&mut e, "000AAAAAA", "INFO"), "Last seen"), "owner still sees their own last-seen");

        // Turn it off: public again.
        assert!(notice(&send(&mut e, "000AAAAAA", "SET HIDE STATUS OFF"), "visible"), "unhide confirmed");
        assert!(notice(&send(&mut e, "000AAAAAB", "INFO alice"), "Last seen"), "last-seen public again");
    }

    // SET EMAIL stores an email; SET PASSWORD defers derivation, and once
    // completed the new password authenticates and the old one no longer does.
    #[test]
    fn nickserv_set_password_and_email() {
        let mut e = engine_with("nsset", "alice", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let to_ns = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        assert!(notice(&to_ns(&mut e, "SET EMAIL alice@example.org"), "updated"));
        assert!(notice(&to_ns(&mut e, "INFO"), "alice@example.org"), "owner INFO shows the email");

        let out = to_ns(&mut e, "SET PASSWORD newsecret");
        let deferred = out.iter().find_map(|a| match a {
            NetAction::DeferPassword { account, password, agent, uid } => Some((account.clone(), password.clone(), agent.clone(), uid.clone())),
            _ => None,
        });
        let (account, password, agent, uid) = deferred.expect("SET PASSWORD defers derivation");
        assert_eq!(password, "newsecret");
        let creds = Db::derive_credentials(&password, 4096);
        e.complete_password_change(&account, creds, &agent, &uid);
        assert!(e.db.authenticate("alice", "newsecret").is_some(), "new password works");
        assert!(e.db.authenticate("alice", "sesame").is_none(), "old password rejected");
    }

    // DROP deletes the account, releases and drops the channels it founded, and
    // logs the session out; a wrong password is refused.
    #[test]
    fn nickserv_drop_account() {
        let mut e = engine_with("nsdrop", "alice", "sesame");
        e.db.register_channel("#a", "alice").unwrap();
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let to_ns = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        assert!(notice(&to_ns(&mut e, "DROP wrongpass"), "Invalid password"));
        assert!(e.db.account("alice").is_some(), "wrong password keeps the account");

        let out = to_ns(&mut e, "DROP sesame");
        assert!(notice(&out, "has been dropped"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#a" && modes == "-r")), "channel released: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { target, key, value } if target == "000AAAAAB" && key == "accountname" && value.is_empty())), "session logged out: {out:?}");
        assert!(e.db.account("alice").is_none(), "account gone");
        assert!(e.db.channel("#a").is_none(), "founded channel gone");
    }

    // GROUP links a nick to an account so it identifies there too; GLIST lists the
    // aliases; UNGROUP removes one, after which the nick no longer resolves.
    #[test]
    fn nickserv_grouped_nicks() {
        let mut e = engine_with("nsgroup", "alice", "sesame");
        let to_ns = |e: &mut Engine, uid: &str, text: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));
        // A user on a different nick groups it to alice by password.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "ali".into(), host: "h".into() , ip: "0.0.0.0".into() });
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "GROUP alice sesame"), "grouped to \x02alice\x02"));
        // Identifying as the grouped nick logs into alice.
        let out = to_ns(&mut e, "000AAAAAB", "IDENTIFY sesame");
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "alice")), "grouped nick identifies to alice: {out:?}");
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "GLIST"), "ali"));
        // Ungroup it; a fresh session on that nick no longer resolves.
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "UNGROUP ali"), "no longer grouped"));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "ali".into(), host: "h".into() , ip: "0.0.0.0".into() });
        assert!(notice(&to_ns(&mut e, "000AAAAAC", "IDENTIFY sesame"), "isn't registered"));
    }

    // RESETPASS emails a code, and that code + a new password completes the reset;
    // the new password then authenticates and the old one no longer does.
    #[test]
    fn nickserv_resetpass() {
        let mut e = engine_with("nsreset", "alice", "sesame");
        e.db.set_email_enabled(true);
        e.db.set_email("alice", Some("alice@example.org".into())).unwrap();
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "someone".into(), host: "h".into() , ip: "0.0.0.0".into() });
        let to_ns = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() });

        // Request: a code is emailed to the address on file.
        let out = to_ns(&mut e, "RESETPASS alice");
        let (to, body) = out.iter().find_map(|a| match a {
            NetAction::SendEmail { to, text, .. } => Some((to.clone(), text.clone())),
            _ => None,
        }).expect("a reset code is emailed");
        assert_eq!(to, "alice@example.org");
        let code = body.split("is: ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();

        // Complete: the code + a new password defers the change.
        let out = to_ns(&mut e, &format!("RESETPASS alice {code} brandnew"));
        let (account, password, agent, uid) = out.iter().find_map(|a| match a {
            NetAction::DeferPassword { account, password, agent, uid } => Some((account.clone(), password.clone(), agent.clone(), uid.clone())),
            _ => None,
        }).expect("a valid code defers the new password");
        assert_eq!(password, "brandnew");
        e.complete_password_change(&account, Db::derive_credentials(&password, 4096), &agent, &uid);
        assert!(e.db.authenticate("alice", "brandnew").is_some(), "new password works");
        assert!(e.db.authenticate("alice", "sesame").is_none(), "old password rejected");

        // A used/wrong code is refused.
        assert!(to_ns(&mut e, "RESETPASS alice 000000 x").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Invalid or expired"))));
    }

    // RESETPASS is throttled per account so it can't be used to email-bomb the
    // address on file: a second request inside the cooldown sends no email.
    #[test]
    fn resetpass_is_throttled_against_email_bombing() {
        let mut e = engine_with("nsresetrl", "alice", "sesame");
        e.db.set_email_enabled(true);
        e.db.set_email("alice", Some("alice@example.org".into())).unwrap();
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "someone".into(), host: "h".into() , ip: "0.0.0.0".into() });
        let to_ns = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: text.into() });

        assert!(to_ns(&mut e, "RESETPASS alice").iter().any(|a| matches!(a, NetAction::SendEmail { .. })), "first request emails a code");
        let out = to_ns(&mut e, "RESETPASS alice");
        assert!(!out.iter().any(|a| matches!(a, NetAction::SendEmail { .. })), "second immediate request sends no email: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("wait"))), "and tells the caller to wait: {out:?}");
    }

    // With email configured, registering with an address creates an unverified
    // account and emails a confirmation code; CONFIRM <code> verifies it.
    #[test]
    fn nickserv_confirm() {
        let path = std::env::temp_dir().join("echo-nsconfirm.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.set_email_enabled(true);
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "newbie".into(), host: "h".into() , ip: "0.0.0.0".into() });

        // REGISTER with an email defers; complete it as the link layer would.
        let reg = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "REGISTER correcthorse newbie@example.org".into() });
        let (account, password, email, reply) = reg.iter().find_map(|a| match a {
            NetAction::DeferRegister { account, password, email, reply } => Some((account.clone(), password.clone(), email.clone(), reply.clone())),
            _ => None,
        }).expect("register defers");
        let out = e.complete_register(&account, Db::derive_credentials(&password, 4096), email, reply);
        assert!(!e.db.is_verified("newbie"), "registering with email starts unverified");
        let body = out.iter().find_map(|a| match a {
            NetAction::SendEmail { text, .. } => Some(text.clone()),
            _ => None,
        }).expect("a confirm code is emailed");
        let code = body.split("CONFIRM ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();

        // CONFIRM verifies (the user was auto-logged-in by register).
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: format!("CONFIRM {code}") });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("now confirmed"))), "{out:?}");
        assert!(e.db.is_verified("newbie"), "confirmed after CONFIRM");
    }

    // draft/account-registration over the ircd relay: REGISTER defers, replies
    // verification_required and emails a code; VERIFY confirms; STATUS reports it.
    #[test]
    fn account_registration_relay_verify_flow() {
        let path = std::env::temp_dir().join("echo-acctreg-relay.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "test");
        db.scram_iterations = 4096;
        db.set_email_enabled(true);
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);

        // REGISTER <account> <email> :<password> relayed from the ircd.
        let reg = e.account_request("r1".into(), "leaf".into(), "REGISTER".into(), "neo".into(), "neo@example.org".into(), "trinity".into());
        let (account, password, email, reply) = reg.iter().find_map(|a| match a {
            NetAction::DeferRegister { account, password, email, reply } => Some((account.clone(), password.clone(), email.clone(), reply.clone())),
            _ => None,
        }).expect("relay register defers");
        let out = e.complete_register(&account, Db::derive_credentials(&password, 4096), email, reply);
        assert!(out.iter().any(|a| matches!(a, NetAction::AccountResponse { status, .. } if status == "verification_required")), "{out:?}");
        assert!(!e.db.is_verified("neo"), "unverified until the code is confirmed");
        let body = out.iter().find_map(|a| match a { NetAction::SendEmail { text, .. } => Some(text.clone()), _ => None }).expect("a code is emailed on the relay path too");
        let code = body.split("CONFIRM ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();

        // VERIFY with the code succeeds; a stale/duplicate VERIFY then fails.
        let ok = e.account_request("r2".into(), "leaf".into(), "VERIFY".into(), "neo".into(), code, String::new());
        assert!(ok.iter().any(|a| matches!(a, NetAction::AccountResponse { status, .. } if status == "success")), "{ok:?}");
        assert!(e.db.is_verified("neo"), "verified after VERIFY");
        let again = e.account_request("r3".into(), "leaf".into(), "VERIFY".into(), "neo".into(), "000000".into(), String::new());
        assert!(again.iter().any(|a| matches!(a, NetAction::AccountResponse { code, .. } if code == "INVALID_CODE")), "{again:?}");

        // STATUS reports verified; VERIFY on an unknown account is a clean error.
        let st = e.account_request("r4".into(), "leaf".into(), "STATUS".into(), "neo".into(), String::new(), String::new());
        assert!(st.iter().any(|a| matches!(a, NetAction::AccountResponse { code, .. } if code == "VERIFIED")), "{st:?}");
        let unknown = e.account_request("r5".into(), "leaf".into(), "VERIFY".into(), "ghost".into(), "x".into(), String::new());
        assert!(unknown.iter().any(|a| matches!(a, NetAction::AccountResponse { code, .. } if code == "ACCOUNT_UNKNOWN")), "{unknown:?}");
    }

    // Nick protection: a user on a registered nick is prompted, then renamed to a
    // guest if they don't identify before the grace period; the burst is exempt.
    #[test]
    fn nick_protection_enforces_after_grace() {
        let mut e = engine_with("nickprot", "alice", "sesame");
        e.set_sid("42S".into());
        e.now_override = Some(1000);

        // During the uplink burst (not yet synced) nobody is enforced.
        let out = e.handle(NetEvent::UserConnect { uid: "000AAAAAZ".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        assert!(!out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("registered"))), "no enforcement during burst: {out:?}");
        e.handle(NetEvent::Quit { uid: "000AAAAAZ".into(), reason: String::new() });
        e.handle(NetEvent::EndBurst);

        // Live: an unidentified user lands on the registered nick and is prompted.
        let out = e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "000AAAAAB" && text.contains("registered"))), "prompted to identify: {out:?}");

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        e.now_override = Some(1000 + ENFORCE_GRACE - 1);
        e.enforce_sweep();
        assert!(rx.try_recv().is_err(), "no rename before the grace period");
        e.now_override = Some(1000 + ENFORCE_GRACE + 1);
        e.enforce_sweep();
        let renamed = std::iter::from_fn(|| rx.try_recv().ok())
            .any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAB" && nick.starts_with("Guest")));
        assert!(renamed, "unidentified user on a registered nick is renamed after grace");
    }

    // NickServ SET KILL OFF opts an account out of nick protection: an
    // unidentified user on the nick is neither prompted nor renamed.
    #[test]
    fn nick_protection_disabled_by_set_kill_off() {
        let mut e = engine_with("nickkill", "alice", "sesame");
        e.set_sid("42S".into());
        e.now_override = Some(1000);
        e.handle(NetEvent::EndBurst);

        // Owner identifies (holding the nick) and turns protection off.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAA".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAA".into(), text: "SET KILL OFF".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("off"))), "KILL OFF confirmed: {out:?}");
        assert!(!e.db.account_wants_protect("alice"), "protection preference stored off");
        e.handle(NetEvent::Quit { uid: "000AAAAAA".into(), reason: String::new() });

        // An unidentified intruder takes the nick: no prompt, and no rename at grace.
        let out = e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        assert!(!out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("registered"))), "no prompt when KILL is off: {out:?}");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        e.now_override = Some(1000 + ENFORCE_GRACE + 1);
        e.enforce_sweep();
        assert!(rx.try_recv().is_err(), "no rename when KILL is off");

        // Turning it back on restores enforcement for the next arrival.
        e.handle(NetEvent::Quit { uid: "000AAAAAB".into(), reason: String::new() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAA".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAA".into(), text: "SET KILL ON".into() });
        assert!(e.db.account_wants_protect("alice"), "protection preference stored on");
        e.handle(NetEvent::Quit { uid: "000AAAAAA".into(), reason: String::new() });
        let out = e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("registered"))), "prompt returns when KILL back on: {out:?}");
    }

    // Identifying before the grace period cancels the pending rename.
    #[test]
    fn nick_protection_cancelled_by_identify() {
        let mut e = engine_with("nickprot2", "alice", "sesame");
        e.set_sid("42S".into());
        e.now_override = Some(1000);
        e.handle(NetEvent::EndBurst);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        e.now_override = Some(1000 + ENFORCE_GRACE + 1);
        e.enforce_sweep();
        assert!(rx.try_recv().is_err(), "an identified user is never renamed");
    }

    // GHOST renames off a session using a nick the caller owns.
    #[test]
    fn nickserv_ghost() {
        let mut e = engine_with("nsghost", "alice", "sesame");
        let to_ns = |e: &mut Engine, uid: &str, text: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: text.into() });
        // A ghost sits on nick alice; the owner identifies from another nick.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "owner".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY alice sesame".into() });
        let out = to_ns(&mut e, "000AAAAAC", "GHOST alice");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, .. } if uid == "000AAAAAB")), "ghost renamed off: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("freed"))), "{out:?}");
    }

    // IDENTIFY accepts the two-arg account+password form: log into a named
    // account even when the current nick differs; a wrong password is refused.
    #[test]
    fn identify_two_arg_account_form() {
        let mut e = engine_with("twoarg", "realacct", "sesame");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "someguest".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        let out = e.handle(NetEvent::Privmsg {
            from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY realacct sesame".into(),
        });
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "realacct")), "two-arg identify logs into the named account: {out:?}");

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "other".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        let bad = e.handle(NetEvent::Privmsg {
            from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY realacct wrongpw".into(),
        });
        assert!(bad.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Invalid password"))), "{bad:?}");
        assert!(!bad.iter().any(|a| matches!(a, NetAction::Metadata { .. })), "wrong password must not log in: {bad:?}");

        // An unregistered account says so, rather than "Invalid password".
        let missing = e.handle(NetEvent::Privmsg {
            from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY ghost whatever".into(),
        });
        assert!(missing.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("isn't registered"))), "{missing:?}");
    }

    // SECUREOPS strips channel-operator status from a user without op-level access.
    #[test]
    fn secureops_strips_op_from_a_user_without_access() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-secureops.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register_channel("#c", "boss").unwrap();
        db.set_channel_setting("#c", db::ChanSetting::SecureOps, true).unwrap();
        let mut e = Engine::new(vec![Box::new(ChanServ { uid: "42SAAAAAB".into() })], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "rando".into(), host: "h".into() , ip: "0.0.0.0".into() });
        // rando holds no access; being opped triggers a -o from ChanServ.
        let out = e.handle(NetEvent::ChannelOp { channel: "#c".into(), uid: "000AAAAAB".into(), op: true });
        assert!(
            out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "-o 000AAAAAB")),
            "SECUREOPS strips the op: {out:?}"
        );
        // With SECUREOPS off, the same op is left alone.
        e.db.set_channel_setting("#c", db::ChanSetting::SecureOps, false).unwrap();
        let out = e.handle(NetEvent::ChannelOp { channel: "#c".into(), uid: "000AAAAAB".into(), op: true });
        assert!(out.is_empty(), "no enforcement when SECUREOPS is off: {out:?}");
    }

    // ChanServ UP applies the status your access entitles you to; DOWN strips it.
    #[test]
    fn chanserv_up_down_status() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-csupdown.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false });

        let cs = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: text.into() });
        let out = cs(&mut e, "UP #c");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "+qo 000AAAAAB 000AAAAAB")), "UP applies the founder's +qo: {out:?}");
        let out = cs(&mut e, "DOWN #c");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes.starts_with("-qaohv"))), "DOWN strips status: {out:?}");
        let out = cs(&mut e, "UP #nope");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("isn't registered"))), "unknown channel refused: {out:?}");
    }

    // A SOP auto-gets op + protect (+ao, so it shows @ and outranks AOP) on join,
    // and secureops never strips it — op access is a capability, not literal "+o".
    #[test]
    fn sop_join_gets_protect_and_op_and_survives_secureops() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-sopjoin.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("mik", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        for (uid, nick) in [("000AAAAAA", "alice"), ("000AAAAAB", "mik")] {
            e.handle(NetEvent::UserConnect { uid: uid.into(), nick: nick.into(), host: "h".into(), ip: "0.0.0.0".into() });
            e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        }
        // Founder makes mik a SOP and turns secureops on.
        e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAB".into(), text: "SOP #c ADD mik".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAB".into(), text: "SET #c SECUREOPS ON".into() });

        // On join mik is granted op + protect (+ao, the nick once per mode).
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false });
        assert!(
            out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "+ao 000AAAAAB 000AAAAAB")),
            "SOP auto-gets op + protect: {out:?}"
        );
        // Arriving already opped, secureops must NOT strip a SOP's op.
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: true });
        assert!(
            !out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes.starts_with("-o"))),
            "secureops keeps a SOP opped: {out:?}"
        );
    }

    // DEOP with no target deops yourself; PEACE (no acting against equal-or-higher
    // access) must NOT block that — you can always drop your own status.
    #[test]
    fn chanserv_deop_self_allowed_under_peace() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-csdeopself.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: true });
        let cs = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: text.into() });
        cs(&mut e, "SET #c PEACE ON");
        let out = cs(&mut e, "DEOP #c"); // no target = self
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "-o 000AAAAAB")), "self-deop applies -o: {out:?}");
        assert!(!out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("PEACE"))), "self-deop must not be PEACE-blocked: {out:?}");
    }

    // The ordered rank in action: with PEACE on, an AOP can't kick a SOP, but a
    // SOP (higher tier) can kick an AOP. The old collapsed u8 rank made SOP and
    // AOP equal, so neither could act on the other.
    #[test]
    fn peace_lets_sop_act_on_aop_not_the_reverse() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-peacetiers.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        for a in ["alice", "bob", "carol"] {
            db.register(a, "sesame", None).unwrap();
        }
        db.register_channel("#c", "alice").unwrap();
        db.access_add("#c", "bob", "sop").unwrap();
        db.access_add("#c", "carol", "op").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        for (uid, nick) in [("000AAAAAA", "alice"), ("000AAAAAB", "bob"), ("000AAAAAC", "carol")] {
            e.handle(NetEvent::UserConnect { uid: uid.into(), nick: nick.into(), host: "h".into(), ip: "0.0.0.0".into() });
            e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
            e.handle(NetEvent::Join { uid: uid.into(), channel: "#c".into(), op: true });
        }
        e.handle(NetEvent::Privmsg { from: "000AAAAAA".into(), to: "42SAAAAAB".into(), text: "SET #c PEACE ON".into() });

        let kick = |e: &mut Engine, from: &str, target: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: format!("KICK #c {target}") })
        };
        let blocked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("PEACE")));
        let kicked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Kick { .. }));

        // AOP carol tries to kick SOP bob -> PEACE blocks it.
        let out = kick(&mut e, "000AAAAAC", "bob");
        assert!(blocked(&out) && !kicked(&out), "AOP can't kick a SOP under PEACE: {out:?}");
        // SOP bob kicks AOP carol -> allowed (SOP outranks AOP).
        let out = kick(&mut e, "000AAAAAB", "carol");
        assert!(kicked(&out) && !blocked(&out), "SOP can kick an AOP: {out:?}");
    }

    // Regression: FLAGS-editing a HOP/SOP entry must not corrupt it. Adding +v to a
    // halfop once escalated them to founder — the preset name "halfop" got reparsed
    // as flags (f,o,h,a — 'f' = founder). It must stay in the halfop tier.
    #[test]
    fn flags_edit_of_a_preset_entry_does_not_escalate() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-flagsesc.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        db.access_add("#c", "bob", "halfop").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: "FLAGS #c bob +v".into() });

        let ci = e.db.channel("#c").unwrap();
        assert!(!ci.is_op("bob"), "halfop + voice must not gain op or founder");
        let lvl = ci.access.iter().find(|a| a.account == "bob").unwrap().level.clone();
        assert!(!lvl.contains('f'), "must not acquire the founder flag: got {lvl:?}");
    }

    // NickServ LIST is auspex-gated and glob-matches; UPDATE refreshes a session.
    #[test]
    fn nickserv_list_and_update() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-nslistupd.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("alice", "pw", None).unwrap();
        db.register("albert", "pw", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Auspex));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "rando".into(), host: "h".into(), ip: "0.0.0.0".into() });

        assert!(notice(&ns(&mut e, "000AAAAAB", "LIST *"), "Access denied"), "non-oper LIST refused");
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        let out = ns(&mut e, "000AAAAAC", "LIST al*");
        assert!(notice(&out, "alice") && notice(&out, "albert"), "LIST al* shows the matches: {out:?}");
        assert!(!notice(&out, "\x02staff\x02"), "LIST al* excludes non-matches: {out:?}");

        let out = ns(&mut e, "000AAAAAC", "UPDATE");
        assert!(notice(&out, "refreshed"), "UPDATE confirms: {out:?}");
    }

    // MemoServ SENDALL (admin) drops a memo on every registered account.
    #[test]
    fn memoserv_sendall() {
        use echo_memoserv::MemoServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-mssendall.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "pw", None).unwrap();
        db.register("alice", "pw", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(MemoServ { uid: "42SAAAAAE".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAE".into(), text: "SENDALL hello everyone".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("sent to") && text.contains('3'))), "sent to all 3: {out:?}");
        assert_eq!(e.db.unread_memos("alice"), 1);
        assert_eq!(e.db.unread_memos("bob"), 1);
    }

    // MemoServ STAFF memos every operator (config opers here), and only the
    // operators — a plain account gets nothing.
    #[test]
    fn memoserv_staff_memos_operators() {
        use echo_memoserv::MemoServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-msstaff.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "pw", None).unwrap();
        db.register("mod", "pw", None).unwrap();
        db.register("alice", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(MemoServ { uid: "42SAAAAAE".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        opers.insert("mod".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAE".into(), text: "STAFF heads up team".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("2"))), "memoed 2 opers: {out:?}");
        assert_eq!(e.db.unread_memos("mod"), 1, "the other operator got it");
        assert_eq!(e.db.unread_memos("alice"), 0, "a non-operator did not");
    }

    // NickServ SASET lets an operator edit another account's settings, and is
    // refused to non-operators.
    #[test]
    fn nickserv_saset_greet_by_operator() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-nssaset.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "pw", None).unwrap();
        db.register("alice", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY pw");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAC", "IDENTIFY pw");

        // A non-operator cannot use it.
        assert!(notice(&ns(&mut e, "000AAAAAC", "SASET boss GREET nope"), "Access denied"), "non-oper refused");
        // The operator sets alice's greet.
        assert!(notice(&ns(&mut e, "000AAAAAB", "SASET alice GREET hello there"), "is now"), "oper sets greet");
        assert_eq!(e.db.account("alice").map(|a| a.greet.clone()), Some("hello there".to_string()), "greet stored");
        // And clears it.
        assert!(notice(&ns(&mut e, "000AAAAAB", "SASET alice GREET"), "cleared"), "oper clears greet");
        assert_eq!(e.db.account("alice").map(|a| a.greet.clone()), Some(String::new()), "greet cleared");
    }

    // MemoServ IGNORE: a memo from an ignored sender is silently dropped, and the
    // sender is still told it was sent (so the ignore isn't revealed).
    #[test]
    fn memoserv_ignore_drops_memo() {
        use echo_memoserv::MemoServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-msignore.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(MemoServ { uid: "42SAAAAAE".into() }),
            ],
            db,
        );
        let ms = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAE".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });

        // alice ignores bob.
        assert!(notice(&ms(&mut e, "000AAAAAB", "IGNORE ADD bob"), "ignoring"), "ignore added");
        // bob's memo is accepted-looking but dropped.
        assert!(notice(&ms(&mut e, "000AAAAAC", "SEND alice hey"), "Memo sent"), "sender told it was sent");
        assert_eq!(e.db.unread_memos("alice"), 0, "the memo was dropped");
        // After un-ignoring, delivery resumes.
        ms(&mut e, "000AAAAAB", "IGNORE DEL bob");
        ms(&mut e, "000AAAAAC", "SEND alice hey again");
        assert_eq!(e.db.unread_memos("alice"), 1, "delivered once no longer ignored");
    }

    // MemoServ SET NOTIFY/LIMIT change the account's memo preferences, and LIMIT
    // caps the mailbox on SEND.
    #[test]
    fn memoserv_set_notify_and_limit() {
        use echo_memoserv::MemoServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-msset.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(MemoServ { uid: "42SAAAAAE".into() }),
            ],
            db,
        );
        let ms = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAE".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });

        assert!(notice(&ms(&mut e, "000AAAAAB", "SET NOTIFY OFF"), "off"), "notify off");
        assert!(!e.db.memo_notify_on("alice"), "notify pref stored");
        assert!(notice(&ms(&mut e, "000AAAAAB", "SET LIMIT 2"), "2"), "limit set");
        assert_eq!(e.db.memo_limit_of("alice"), Some(2), "limit stored");

        // bob fills alice's 2-memo mailbox; the third is rejected.
        ms(&mut e, "000AAAAAC", "SEND alice one");
        ms(&mut e, "000AAAAAC", "SEND alice two");
        assert!(notice(&ms(&mut e, "000AAAAAC", "SEND alice three"), "mailbox is full"), "limit enforced on SEND");
        assert_eq!(e.db.unread_memos("alice"), 2, "capped at the limit");
    }

    // MemoServ RSEND: when the recipient reads the memo, the sender is memoed back.
    #[test]
    fn memoserv_rsend_read_receipt() {
        use echo_memoserv::MemoServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-msrsend.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(MemoServ { uid: "42SAAAAAE".into() }),
            ],
            db,
        );
        let ms = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAE".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });

        assert!(notice(&ms(&mut e, "000AAAAAC", "RSEND alice testing"), "Memo sent"), "rsend delivered");
        assert_eq!(e.db.unread_memos("bob"), 0, "bob has no receipt yet");
        // alice reads it; bob gets a receipt memo.
        assert!(notice(&ms(&mut e, "000AAAAAB", "READ 1"), "testing"), "alice reads the memo");
        assert_eq!(e.db.unread_memos("bob"), 1, "bob got a read receipt");
        assert!(notice(&ms(&mut e, "000AAAAAC", "READ 1"), "has read the memo"), "receipt text delivered");
        // Reading again does not fire a second receipt.
        ms(&mut e, "000AAAAAB", "READ 1");
        assert_eq!(e.db.unread_memos("bob"), 0, "no duplicate receipt on re-read");
    }

    // ChanServ AKICK CLEAR empties the auto-kick list.
    #[test]
    fn chanserv_akick_clear() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-csakickclear.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "pw", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        let cs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: t.into() });
        cs(&mut e, "AKICK #c ADD *!*@bad1");
        cs(&mut e, "AKICK #c ADD *!*@bad2");
        let out = cs(&mut e, "AKICK #c CLEAR");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Cleared") && text.contains('2'))), "clears 2: {out:?}");
        let out = cs(&mut e, "AKICK #c LIST");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("empty"))), "now empty: {out:?}");
    }

    // ChanServ OWNER (+q) is founder-only; PROTECT (+a) and HALFOP (+h) need op.
    #[test]
    fn chanserv_owner_protect_halfop() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-csstatus.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });

        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let mode = |out: &[NetAction], m: &str| out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == m));

        assert!(mode(&cs(&mut e, "000AAAAAB", "OWNER #c"), "+q 000AAAAAB"), "founder grants +q to self");
        assert!(mode(&cs(&mut e, "000AAAAAB", "PROTECT #c"), "+a 000AAAAAB"), "founder grants +a");
        assert!(mode(&cs(&mut e, "000AAAAAB", "HALFOP #c"), "+h 000AAAAAB"), "founder grants +h");

        // bob has no access: OWNER is refused (no +q emitted for him).
        let out = cs(&mut e, "000AAAAAC", "OWNER #c");
        assert!(!mode(&out, "+q 000AAAAAC"), "non-founder cannot grant owner: {out:?}");
    }

    // ChanServ SET SUCCESSOR: the successor inherits the channel when the founder
    // account is dropped, instead of the channel being released.
    #[test]
    fn chanserv_successor_inherits_on_drop() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-cssucc.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: "SET #c SUCCESSOR bob".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Successor") && text.contains("bob"))), "successor set: {out:?}");

        // alice drops her account -> #c is inherited by bob, not released.
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "DROP sesame".into() });
        assert_eq!(e.db.channel("#c").map(|c| c.founder.clone()), Some("bob".to_string()), "channel inherited by the successor");
        assert!(e.db.account("alice").is_none(), "the dropped account is gone");
    }

    // OperServ FORBID bans a nick/channel pattern from registration.
    #[test]
    fn operserv_forbid_blocks_registration() {
        use echo_nickserv::NickServ;
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osforbid.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        let os = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAH".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        assert!(notice(&os(&mut e, "FORBID ADD NICK evil* squatting"), "Forbade"), "nick forbid added");
        assert!(notice(&os(&mut e, "FORBID ADD CHAN #warez piracy"), "Forbade"), "chan forbid added");

        let reply = crate::proto::RegReply::NickServ { agent: "42SAAAAAA".into(), uid: "000AAAAAC".into(), nick: "evilbob".into() };
        assert!(e.pre_register_check("evilbob", &reply).is_some(), "forbidden nick refused");
        assert!(e.pre_register_check("cleanname", &reply).is_none(), "clean nick allowed");
        assert!(e.db.is_forbidden(echo_api::ForbidKind::Chan, "#warez").is_some(), "channel is forbidden");

        // EMAIL forbids block registration and SET EMAIL.
        assert!(notice(&os(&mut e, "FORBID ADD EMAIL *@spam.tld disposable"), "Forbade"), "email forbid added");
        let ereply = || crate::proto::RegReply::NickServ { agent: "42SAAAAAA".into(), uid: "000AAAAAE".into(), nick: "newbie".into() };
        let out = e.complete_register("newbie", Db::derive_credentials("pw", 4096), Some("evil@spam.tld".into()), ereply());
        assert!(notice(&out, "email address is forbidden"), "forbidden email blocks registration: {out:?}");
        assert!(!e.db.exists("newbie"), "no account created with a forbidden email");
        e.complete_register("newbie", Db::derive_credentials("pw", 4096), Some("ok@good.tld".into()), ereply());
        assert!(e.db.exists("newbie"), "a clean email registers fine");
        // boss (identified) can't SET EMAIL to a forbidden address either.
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "SET EMAIL nope@spam.tld".into() });
        assert!(notice(&out, "email address is forbidden"), "SET EMAIL rejects a forbidden address: {out:?}");

        assert!(notice(&os(&mut e, "FORBID LIST"), "evil*"), "list shows the nick forbid");
        assert!(notice(&os(&mut e, "FORBID DEL NICK evil*"), "Removed"), "nick forbid removed");
        assert!(e.pre_register_check("evilbob", &reply).is_none(), "no longer forbidden");

        // A non-oper cannot FORBID.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAD".into(), nick: "rando".into(), host: "h".into(), ip: "0.0.0.0".into() });
        assert!(notice(&e.handle(NetEvent::Privmsg { from: "000AAAAAD".into(), to: "42SAAAAAH".into(), text: "FORBID ADD NICK x y".into() }), "Access denied"), "non-oper refused");
    }

    // OperServ SET READONLY locks out writes: while on, a channel can't be
    // registered; turning it off restores normal service.
    #[test]
    fn operserv_set_readonly_blocks_writes() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osreadonly.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Root));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: true });
        let os = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAH".into(), text: t.into() });
        let cs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        assert!(notice(&os(&mut e, "SET READONLY ON"), "read-only"), "readonly enabled");
        assert!(e.db.readonly(), "flag set");
        let out = cs(&mut e, "REGISTER #c");
        assert!(!notice(&out, "now registered"), "register blocked while read-only: {out:?}");
        assert!(e.db.channel("#c").is_none(), "no channel written");

        assert!(notice(&os(&mut e, "SET READONLY OFF"), "no longer"), "readonly cleared");
        assert!(!e.db.readonly(), "flag cleared");
        assert!(notice(&cs(&mut e, "REGISTER #c"), "now registered"), "register works again");
        assert!(e.db.channel("#c").is_some(), "channel written");
    }

    // OperServ SHUTDOWN/RESTART (admin) emit a Shutdown action (which the link
    // layer turns into a process exit) and are refused to non-operators.
    #[test]
    fn operserv_shutdown_and_restart() {
        use echo_nickserv::NickServ;
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osshutdown.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Root));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });

        // A non-oper is refused and no Shutdown action is produced.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAD".into(), nick: "rando".into(), host: "h".into(), ip: "0.0.0.0".into() });
        let out = os(&mut e, "000AAAAAD", "SHUTDOWN now");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "non-oper refused");
        assert!(!out.iter().any(|a| matches!(a, NetAction::Shutdown { .. })), "no shutdown for non-oper");

        // The admin's SHUTDOWN emits a Shutdown (restart=false) with the reason.
        let out = os(&mut e, "000AAAAAB", "SHUTDOWN maintenance");
        assert!(out.iter().any(|a| matches!(a, NetAction::Shutdown { restart, reason } if !*restart && reason.contains("maintenance"))), "shutdown action: {out:?}");
        // RESTART sets restart=true.
        let out = os(&mut e, "000AAAAAB", "RESTART");
        assert!(out.iter().any(|a| matches!(a, NetAction::Shutdown { restart, .. } if *restart)), "restart action: {out:?}");
    }

    // OperServ SVSPART (admin) forces a user out of a channel.
    #[test]
    fn operserv_svspart() {
        use echo_nickserv::NickServ;
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-svspart.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "pw", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY pw".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "victim".into(), host: "h".into(), ip: "0.0.0.0".into() });

        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAH".into(), text: "SVSPART victim #trouble go away".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ForcePart { uid, channel, .. } if uid == "000AAAAAC" && channel == "#trouble")), "victim parted: {out:?}");
        // A non-oper can't.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAD".into(), nick: "rando".into(), host: "h".into(), ip: "0.0.0.0".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAD".into(), to: "42SAAAAAH".into(), text: "SVSPART victim #trouble".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "non-oper refused: {out:?}");
    }

    // NickServ GETEMAIL (oper) finds accounts by their email glob.
    #[test]
    fn nickserv_getemail() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-getemail.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "pw", None).unwrap();
        db.register("alice", "pw", Some("alice@x.com".into())).unwrap();
        db.register("bob", "pw", Some("bob@x.com".into())).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Auspex));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "staff".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "rando".into(), host: "h".into(), ip: "0.0.0.0".into() });

        assert!(notice(&ns(&mut e, "000AAAAAC", "GETEMAIL *@x.com"), "Access denied"), "non-oper refused");
        ns(&mut e, "000AAAAAB", "IDENTIFY pw");
        let out = ns(&mut e, "000AAAAAB", "GETEMAIL *@x.com");
        assert!(notice(&out, "alice") && notice(&out, "bob"), "finds both: {out:?}");
        assert!(notice(&ns(&mut e, "000AAAAAB", "GETEMAIL nobody@z.com"), "No accounts"), "no match reported");
    }

    // NickServ RECOVER frees a ghost off your nick and puts you back onto it.
    #[test]
    fn nickserv_recover_regains_nick() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-recover.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        // A ghost sits on nick "alice"; the owner is on another nick and identifies.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "owner".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY alice sesame".into() });

        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "RECOVER alice".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAB" && nick.starts_with("Guest"))), "ghost freed: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAC" && nick == "alice")), "caller regained the nick: {out:?}");
    }

    // ChanServ SET RESTRICTED kicks joining users who have no channel access.
    #[test]
    fn chanserv_restricted_kicks_users_without_access() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-restricted.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: "SET #c RESTRICTED ON".into() });

        // The founder has access and is not kicked.
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false });
        assert!(!out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAB")), "founder not kicked: {out:?}");
        // A user with no access is kicked.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "rando".into(), host: "h".into(), ip: "0.0.0.0".into() });
        let out = e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#c".into(), op: false });
        let kick = out.iter().find_map(|a| match a {
            NetAction::Kick { uid, channel, reason, .. } if uid == "000AAAAAC" && channel == "#c" => Some(reason.clone()),
            _ => None,
        });
        let reason = kick.expect(&format!("no-access user kicked: {out:?}"));
        // The restricted kick must be incident-stamped like every other removal —
        // it early-returns, so this proves the return routes through finish() and
        // reaches stamp_incidents (which appends the searchable [#id] tag).
        assert!(reason.contains("[#"), "restricted kick is incident-stamped: {reason:?}");
    }

    // ChanServ SET AUTOOP OFF suppresses auto-op on join (on by default).
    #[test]
    fn chanserv_autoop_off_suppresses_status() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-autoop.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let opped = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "+qo 000AAAAAB 000AAAAAB"));

        // Default: the founder is auto-opped on join.
        assert!(opped(&e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false })), "auto-op on by default");
        e.handle(NetEvent::Part { uid: "000AAAAAB".into(), channel: "#c".into(), reason: String::new() });
        // Turn AUTOOP off; now a join is not auto-opped.
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: "SET #c AUTOOP OFF".into() });
        assert!(!opped(&e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false })), "no auto-op when AUTOOP is off");
    }

    // NickServ SET AUTOOP OFF is a per-account opt-out: the user isn't auto-opped
    // anywhere, even where the channel allows it.
    #[test]
    fn nickserv_set_autoop_off_opts_out_of_status() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-nsautoop.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let ns = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: t.into() });
        let opped = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "+qo 000AAAAAB 000AAAAAB"));
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        // Default: founder is auto-opped (channel AUTOOP on, account AUTOOP on).
        assert!(opped(&e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false })), "auto-op on by default");
        e.handle(NetEvent::Part { uid: "000AAAAAB".into(), channel: "#c".into(), reason: String::new() });

        // Account opts out via NickServ; now no auto-op despite channel allowing it.
        assert!(notice(&ns(&mut e, "SET AUTOOP OFF"), "no longer be auto-opped"), "pref set off");
        assert!(!e.db.account_wants_autoop("alice"), "preference stored");
        assert!(!opped(&e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false })), "no auto-op with account AUTOOP off");

        // Turn it back on: auto-op resumes.
        e.handle(NetEvent::Part { uid: "000AAAAAB".into(), channel: "#c".into(), reason: String::new() });
        assert!(notice(&ns(&mut e, "SET AUTOOP ON"), "auto-opped where you have"), "pref set on");
        assert!(opped(&e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false })), "auto-op resumes");
    }

    // BotServ BOT ADD/LIST is oper-gated (Priv::Admin) and the bot is remembered.
    #[test]
    fn botserv_bot_add_list_is_oper_gated() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-botserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "rando".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });

        // A non-oper cannot add a bot.
        assert!(notice(&bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper"), "Access denied"));
        // The admin oper identifies, adds a bot, and sees it listed.
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        assert!(notice(&bs(&mut e, "000AAAAAC", "BOT ADD Bendy bot serv.host A Helper"), "added"));
        assert!(notice(&bs(&mut e, "000AAAAAC", "BOT LIST"), "Bendy"));
    }

    // BotServ AUTOASSIGN sets a default bot that new channels get automatically,
    // and BOTLIST shows assignable bots to anyone.
    #[test]
    fn botserv_autoassign_and_botlist() {
        use echo_botserv::BotServ;
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bsautoassign.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        bs(&mut e, "000AAAAAC", "BOT ADD Bendy bot serv.host A Helper");

        // BOTLIST shows the bot; setting a nonexistent default is rejected.
        assert!(notice(&bs(&mut e, "000AAAAAC", "BOTLIST"), "Bendy"), "botlist shows the bot");
        assert!(notice(&bs(&mut e, "000AAAAAC", "AUTOASSIGN Ghost"), "no bot named"), "unknown default rejected");
        assert!(notice(&bs(&mut e, "000AAAAAC", "AUTOASSIGN Bendy"), "auto-assigned"), "default set");
        assert_eq!(e.db.default_bot(), Some("Bendy"), "default bot stored canonically");

        // Registering a new channel auto-assigns the default bot.
        e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#new".into(), op: true });
        let out = cs(&mut e, "000AAAAAC", "REGISTER #new");
        assert!(notice(&out, "Assigned"), "bot auto-assigned on register: {out:?}");
        assert_eq!(e.db.channel("#new").and_then(|c| c.assigned_bot.clone()), Some("Bendy".to_string()), "assignment recorded");

        // Turning it off stops auto-assignment.
        assert!(notice(&bs(&mut e, "000AAAAAC", "AUTOASSIGN OFF"), "no longer"), "default cleared");
        assert_eq!(e.db.default_bot(), None, "default bot cleared");
    }

    // A bot is introduced on the network when added, and quit when deleted.
    #[test]
    fn botserv_introduces_and_quits_bots() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-botintro.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        // Adding a bot introduces it on the network with a SID-prefixed uid.
        let out = bs(&mut e, "000AAAAAC", "BOT ADD Bendy bot serv.host A Helper");
        assert!(out.iter().any(|a| matches!(a, NetAction::IntroduceUser { nick, uid, .. } if nick == "Bendy" && uid.starts_with("42SB"))), "introduced: {out:?}");
        // A later command doesn't re-introduce an already-live bot.
        assert!(!bs(&mut e, "000AAAAAC", "BOT LIST").iter().any(|a| matches!(a, NetAction::IntroduceUser { .. })), "no duplicate introduce");
        // Deleting it quits the pseudo-client.
        assert!(bs(&mut e, "000AAAAAC", "BOT DEL Bendy").iter().any(|a| matches!(a, NetAction::QuitUser { .. })), "quit on delete");
        // A registered bot is introduced at burst.
        bs(&mut e, "000AAAAAC", "BOT ADD Roger svc host Bot");
        assert!(e.startup_actions().iter().any(|a| matches!(a, NetAction::IntroduceUser { nick, .. } if nick == "Roger")), "introduced at burst");
    }

    // ASSIGN puts the bot in the channel; UNASSIGN takes it out.
    #[test]
    fn botserv_assign_joins_and_unassign_parts() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bsassign.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("staff", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAC", "IDENTIFY password1");
        bs(&mut e, "000AAAAAC", "BOT ADD Bendy bot serv.host Helper"); // goes live

        // The founder assigns the bot: it joins as a protected admin + op (+ao).
        let out = bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");
        assert!(out.iter().any(|a| matches!(a, NetAction::ServiceJoin { channel, modes, .. } if channel == "#c" && modes == "ao")), "joins +ao on assign: {out:?}");
        // Unassigning parts it.
        let out = bs(&mut e, "000AAAAAB", "UNASSIGN #c");
        assert!(out.iter().any(|a| matches!(a, NetAction::ServicePart { channel, .. } if channel == "#c")), "parts on unassign: {out:?}");
    }

    // A services bot kicked from a channel it's assigned to rejoins at once — an
    // op can't evict it.
    #[test]
    fn kicked_bot_rejoins_its_channel() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-kickbot.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "IDENTIFY password1");
        bs(&mut e, "BOT ADD Bendy bot serv.host Helper");
        let bot_uid = bs(&mut e, "ASSIGN #c Bendy").iter().find_map(|a| match a {
            NetAction::ServiceJoin { uid, channel, .. } if channel == "#c" => Some(uid.clone()),
            _ => None,
        }).expect("bot joined on assign");

        // The bot is kicked out (the ircd relays this as a PART for its uid).
        let out = e.handle(NetEvent::Part { uid: bot_uid.clone(), channel: "#c".into(), reason: String::new() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ServiceJoin { uid, channel, .. } if uid == &bot_uid && channel == "#c")), "kicked bot rejoins: {out:?}");
    }

    // A KILL forgets a real user, but a killed services bot is reintroduced and
    // rejoins its channels — an oper can't take a bot down for good.
    #[test]
    fn kill_forgets_a_user_and_reintroduces_a_bot() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-killbot.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "IDENTIFY password1");
        bs(&mut e, "BOT ADD Bendy bot serv.host Helper");
        let bot_uid = bs(&mut e, "ASSIGN #c Bendy").iter().find_map(|a| match a {
            NetAction::ServiceJoin { uid, channel, .. } if channel == "#c" => Some(uid.clone()),
            _ => None,
        }).expect("bot joined on assign");

        // Killing a real user forgets their session.
        assert_eq!(e.network.account_of("000AAAAAB"), Some("boss"), "identified before the kill");
        e.handle(NetEvent::UserKilled { uid: "000AAAAAB".into() });
        assert!(e.network.account_of("000AAAAAB").is_none(), "killed user forgotten");

        // Killing the bot brings it right back and rejoins its channel.
        let out = e.handle(NetEvent::UserKilled { uid: bot_uid });
        assert!(out.iter().any(|a| matches!(a, NetAction::IntroduceUser { nick, .. } if nick == "Bendy")), "killed bot reintroduced: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::ServiceJoin { channel, .. } if channel == "#c")), "reintroduced bot rejoins #c: {out:?}");
    }

    // Killing a service agent (NickServ etc.) reintroduces it — an oper can't
    // take services off the network with a KILL.
    #[test]
    fn killed_service_agent_is_reintroduced() {
        let mut e = engine_with("killagent", "alice", "sesame");
        // engine_with wires NickServ at uid 42SAAAAAA.
        let out = e.handle(NetEvent::UserKilled { uid: "42SAAAAAA".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::IntroduceUser { uid, nick, .. } if uid == "42SAAAAAA" && !nick.is_empty())), "killed agent reintroduced: {out:?}");
    }

    // A channel that expires with an assigned bot parts the bot in the same
    // sweep — it must not linger in a channel it no longer serves.
    #[test]
    fn expired_channel_parts_its_assigned_bot() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-expirebot.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        // boss is an oper so its account is spared — only the channel expires.
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "IDENTIFY password1");
        bs(&mut e, "BOT ADD Bendy bot serv.host Helper");
        assert!(bs(&mut e, "ASSIGN #c Bendy").iter().any(|a| matches!(a, NetAction::ServiceJoin { channel, .. } if channel == "#c")), "bot joins on assign");

        // Expire #c; the sweep drops it and must part the bot.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        e.now_override = Some(10_000_000_000);
        e.set_expiry(Some(100), Some(100), None);
        e.expire_sweep();
        assert!(e.db.channel("#c").is_none(), "channel expired");
        let parted = std::iter::from_fn(|| rx.try_recv().ok())
            .any(|a| matches!(a, NetAction::ServicePart { channel, .. } if channel == "#c"));
        assert!(parted, "the assigned bot parts the expired channel");
    }

    // A truly-empty channel is forgotten (so a stale `+k` key can't leak to a later
    // channel of the same name), but a channel a services bot still sits in is kept
    // alive (bots aren't tracked as members) so its live key/modes survive.
    #[test]
    fn emptied_channel_pruned_but_botted_channel_kept() {
        let path = std::env::temp_dir().join("echo-emptykey.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut e = Engine::new(vec![], Db::open(&path, "42S"));

        // Bot-less channel: once the last member leaves, it's gone (no stale key).
        e.network.channel_join("#x", "000AAAAAB", true);
        e.network.set_channel_key("#x", Some("secret".into()));
        assert_eq!(e.network.channel_key("#x"), Some("secret"));
        e.network.channel_part("#x", "000AAAAAB");
        e.prune_channel_if_gone("#x");
        assert_eq!(e.network.channel_key("#x"), None, "empty bot-less channel is forgotten");
        e.network.channel_join("#x", "000AAAAAD", true); // recreated, fresh
        assert_eq!(e.network.channel_key("#x"), None, "recreated channel starts keyless");

        // Botted channel: emptied of humans, but the bot keeps it alive on the ircd,
        // so echo must NOT drop its live key.
        e.network.channel_join("#y", "000AAAAAC", true);
        e.network.set_channel_key("#y", Some("hunter2".into()));
        e.bot_channels.insert(("bendy".to_string(), "#y".to_string()));
        e.network.channel_part("#y", "000AAAAAC");
        e.prune_channel_if_gone("#y");
        assert_eq!(e.network.channel_key("#y"), Some("hunter2"), "botted channel keeps its key");
    }

    // The gRPC login path applies the same guards as IRC IDENTIFY: a suspended or
    // throttled account is refused before the verify (and the throttle clears on success).
    #[test]
    fn authority_auth_begin_refuses_suspended_or_throttled() {
        let path = std::env::temp_dir().join("echo-authbegin.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("carol", "hunter2", None).unwrap();
        db.register("dave", "hunter2", None).unwrap();
        let mut e = Engine::new(vec![], db);
        assert!(e.authority_auth_begin("carol").is_some(), "a normal account resolves a verifier");

        e.db.suspend_account("carol", "staff", "x", None).unwrap();
        assert!(e.authority_auth_begin("carol").is_none(), "suspended account refused");

        for _ in 0..10 {
            e.db.note_auth("dave", false);
        }
        assert!(e.authority_auth_begin("dave").is_none(), "throttled account refused");
        e.db.note_auth("dave", true);
        assert!(e.authority_auth_begin("dave").is_some(), "cleared after a success");
    }

    // groups_founded bounds group registration: it counts only groups the account founds.
    #[test]
    fn groups_founded_counts_only_a_founders_own_groups() {
        let path = std::env::temp_dir().join("echo-groupcount.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register("boss", "password1", None).unwrap();
        db.register("other", "password1", None).unwrap();
        db.group_register("!a", "boss").unwrap();
        db.group_register("!b", "boss").unwrap();
        db.group_register("!c", "other").unwrap();
        assert_eq!(db.groups_founded("boss"), 2);
        assert_eq!(db.groups_founded("other"), 1);
        assert_eq!(db.groups_founded("nobody"), 0);
    }

    // BOT DEL * removes every bot at once, quitting each.
    #[test]
    fn botserv_mass_bot_removal() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bsmass.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        bs(&mut e, "BOT ADD One a serv.host Bot");
        bs(&mut e, "BOT ADD Two b serv.host Bot");

        let out = bs(&mut e, "BOT DEL *");
        let quits = out.iter().filter(|a| matches!(a, NetAction::QuitUser { .. })).count();
        assert_eq!(quits, 2, "both bots quit: {out:?}");
        // The registry is empty afterwards.
        assert!(!bs(&mut e, "BOT LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("One") || text.contains("Two"))), "registry cleared");
    }

    // BOT CHANGE renames a bot (moving its channel assignments) and reintroduces
    // it when only the identity changes; the network client is refreshed both ways.
    #[test]
    fn botserv_bot_change_renames_and_reidentifies() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bschange.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "IDENTIFY password1");
        bs(&mut e, "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "ASSIGN #c Bendy");

        // Rename: the old client quits, a Roger client is introduced and rejoins #c.
        let out = bs(&mut e, "BOT CHANGE Bendy Roger");
        assert!(out.iter().any(|a| matches!(a, NetAction::QuitUser { .. })), "old client quit: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::IntroduceUser { nick, .. } if nick == "Roger")), "Roger introduced");
        assert!(out.iter().any(|a| matches!(a, NetAction::ServiceJoin { channel, .. } if channel == "#c")), "Roger rejoins #c");

        // Same nick, new identity: the client is refreshed with the new host.
        let out = bs(&mut e, "BOT CHANGE Roger Roger newbot new.host A New Bot");
        assert!(out.iter().any(|a| matches!(a, NetAction::QuitUser { .. })), "stale client quit");
        assert!(out.iter().any(|a| matches!(a, NetAction::IntroduceUser { nick, host, .. } if nick == "Roger" && host == "new.host")), "reintroduced with new host: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::ServiceJoin { channel, .. } if channel == "#c")), "rejoins #c after re-identify");
    }

    // NOBOT (channel) and PRIVATE (bot) both reserve assignment for operators:
    // the founder is refused, a services admin is allowed.
    #[test]
    fn botserv_nobot_and_private_gate_assign() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bsprot.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap(); // admin
        db.register("owner", "password1", None).unwrap(); // plain founder
        db.register_channel("#c", "owner").unwrap();
        db.register_channel("#d", "owner").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let boss = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let owner = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAO".into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAO".into(), nick: "owner".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAO", "IDENTIFY password1");
        boss(&mut e, "BOT ADD Bendy bot serv.host Helper");
        let joined = |out: &[NetAction], ch: &str| out.iter().any(|a| matches!(a, NetAction::ServiceJoin { channel, .. } if channel == ch));
        let denied = |out: &[NetAction], word: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(word)));

        // NOBOT on #c: the founder is refused, the admin isn't.
        boss(&mut e, "SET #c NOBOT ON");
        assert!(denied(&owner(&mut e, "ASSIGN #c Bendy"), "NOBOT"), "founder blocked by NOBOT");
        assert!(joined(&boss(&mut e, "ASSIGN #c Bendy"), "#c"), "admin overrides NOBOT");

        // Private bot on #d: the founder is refused, the admin isn't.
        boss(&mut e, "SET Bendy PRIVATE ON");
        assert!(denied(&owner(&mut e, "ASSIGN #d Bendy"), "private"), "founder blocked from private bot");
        assert!(joined(&boss(&mut e, "ASSIGN #d Bendy"), "#d"), "admin assigns private bot");
    }

    // SAY/ACT speak through the channel's assigned bot, sourced from the bot's uid.
    #[test]
    fn botserv_say_speaks_through_bot() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bssay.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("rando", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAR".into(), nick: "rando".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAR", "IDENTIFY password1");
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");

        // Founder SAY: a PRIVMSG to the channel sourced from the bot's uid.
        let out = bs(&mut e, "000AAAAAB", "SAY #c hello there");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text } if from.starts_with("42SB") && to == "#c" && text == "hello there")),
            "bot says: {out:?}"
        );
        // ACT wraps the text in a CTCP ACTION.
        let out = bs(&mut e, "000AAAAAB", "ACT #c waves");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Privmsg { text, .. } if text == "\x01ACTION waves\x01")),
            "bot acts: {out:?}"
        );
        // A non-op can't drive the bot.
        let out = bs(&mut e, "000AAAAAR", "SAY #c nope");
        assert!(!out.iter().any(|a| matches!(a, NetAction::Privmsg { .. })), "non-op blocked: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "denied notice: {out:?}");
    }

    // The caps kicker makes the assigned bot kick a shouting message, exempts
    // operators when DONTKICKOPS is on, and leaves ordinary lines alone.
    #[test]
    fn botserv_caps_kicker_kicks() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bskick.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "#c".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAR".into(), nick: "rando".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");
        bs(&mut e, "000AAAAAB", "KICK #c CAPS ON");
        e.handle(NetEvent::Join { uid: "000AAAAAR".into(), channel: "#c".into(), op: false });

        // Shouting is kicked, sourced from the bot.
        let out = say(&mut e, "000AAAAAR", "HELLO EVERYONE LISTEN UP");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Kick { from, channel, uid, .. } if from.starts_with("42SB") && channel == "#c" && uid == "000AAAAAR")),
            "caps kicked: {out:?}"
        );
        // A normal line is fine.
        assert!(!say(&mut e, "000AAAAAR", "hello everyone").iter().any(|a| matches!(a, NetAction::Kick { .. })), "quiet line ok");
        // With DONTKICKOPS, an operator can shout.
        bs(&mut e, "000AAAAAB", "KICK #c DONTKICKOPS ON");
        e.network.set_op("#c", "000AAAAAR", true);
        assert!(!say(&mut e, "000AAAAAR", "SHOUTING BUT I AM OP").iter().any(|a| matches!(a, NetAction::Kick { .. })), "op exempt");
    }

    // The repeat kicker counts consecutive identical lines (case-insensitively)
    // and kicks once the threshold is reached; a different line resets it.
    #[test]
    fn botserv_repeat_kicker_kicks() {
        let (mut e, _p) = kicker_fixture("bsrepeat");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        bs(&mut e, "KICK #c REPEAT ON 2"); // kick on the third identical line

        let kicked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Kick { from, uid, .. } if from.starts_with("42SB") && uid == "000AAAAAS"));
        assert!(!kicked(&say(&mut e, "spam")), "1st ok");
        assert!(!kicked(&say(&mut e, "SPAM")), "2nd (case-fold) ok");
        assert!(kicked(&say(&mut e, "Spam")), "3rd identical kicks");
        // A different line clears the streak.
        assert!(!kicked(&say(&mut e, "something else entirely")), "reset on new line");
    }

    // The flood kicker counts lines within a window; the window resets after it
    // elapses. Uses the injectable clock so it is deterministic.
    #[test]
    fn botserv_flood_kicker_kicks() {
        let (mut e, _p) = kicker_fixture("bsflood");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        bs(&mut e, "KICK #c FLOOD ON 3 10"); // 3 lines in 10 seconds
        let kicked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAS"));

        e.now_override = Some(1000);
        assert!(!kicked(&say(&mut e, "a")), "line 1");
        assert!(!kicked(&say(&mut e, "b")), "line 2");
        // The window elapses before the 3rd line, so it resets instead of kicking.
        e.now_override = Some(1011);
        assert!(!kicked(&say(&mut e, "c")), "window reset");
        // Three lines inside the window now trip it.
        assert!(!kicked(&say(&mut e, "d")), "line 2 of new window");
        assert!(kicked(&say(&mut e, "e")), "3rd in-window line kicks");
    }

    // The badwords kicker matches user-supplied regexes (case-insensitively),
    // rebuilds its compiled set when the list changes, and rejects bad patterns.
    #[test]
    fn botserv_badwords_kicker_kicks() {
        let (mut e, _p) = kicker_fixture("bsbadwords");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        let kicked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Kick { from, uid, .. } if from.starts_with("42SB") && uid == "000AAAAAS"));

        bs(&mut e, "BADWORDS #c ADD fr[ao]g");
        bs(&mut e, "KICK #c BADWORDS ON");
        // Matching line (case-insensitive) is kicked; clean line is not.
        assert!(kicked(&say(&mut e, "i love FROGS")), "matched badword kicked");
        assert!(!kicked(&say(&mut e, "hello world")), "clean line ok");

        // Adding a pattern bumps the revision, so the cached set rebuilds.
        bs(&mut e, "BADWORDS #c ADD wibble");
        assert!(kicked(&say(&mut e, "wibble wobble")), "new pattern matches after rebuild");

        // An invalid regex is rejected and not stored.
        let out = bs(&mut e, "BADWORDS #c ADD [unclosed");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("valid regular expression"))), "invalid rejected: {out:?}");
        assert!(!say(&mut e, "[unclosed bracket text").iter().any(|a| matches!(a, NetAction::Kick { .. })), "bad pattern not stored");
    }

    // COPY clones one channel's kicker/badword config onto another.
    #[test]
    fn botserv_copy_bot_config() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bscopy.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        db.register_channel("#d", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        bs(&mut e, "KICK #c CAPS ON");
        bs(&mut e, "BADWORDS #c ADD fr[ao]g");
        bs(&mut e, "KICK #c BADWORDS ON");
        let says = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        // #d starts blank, so nothing trips.
        assert!(says(&bs(&mut e, "KICK #d TEST SHOUTING LOUD ALLCAPS"), "trips no content kicker"), "blank #d");
        bs(&mut e, "COPY #c #d");
        // Now #d has #c's caps and badword config.
        assert!(says(&bs(&mut e, "KICK #d TEST SHOUTING LOUD ALLCAPS"), "would be kicked"), "caps copied");
        assert!(says(&bs(&mut e, "KICK #d TEST i love frogs"), "would be kicked"), "badwords copied");
    }

    // TRIGGER makes the assigned bot auto-respond to a matching line, with $nick
    // substituted for the speaker.
    #[test]
    fn botserv_trigger_auto_responds() {
        let (mut e, _p) = kicker_fixture("bstrigger");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        bs(&mut e, "TRIGGER #c ADD (?i)hello|Hi $nick, welcome!");

        // A matching line gets a bot response addressed with the speaker's nick.
        let out = say(&mut e, "hello everyone");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text } if from.starts_with("42SB") && to == "#c" && text == "Hi spammer, welcome!")),
            "auto-response: {out:?}"
        );
        // A non-matching line is ignored.
        assert!(!say(&mut e, "goodbye all").iter().any(|a| matches!(a, NetAction::Privmsg { .. })), "no response on miss");
    }

    // Community !votekick tallies distinct voters and kicks at the threshold.
    #[test]
    fn botserv_votekick_reaches_threshold() {
        let (mut e, _p) = kicker_fixture("bsvote");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let vote = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "#c".into(), text: t.into() });
        bs(&mut e, "SET #c VOTEKICK 2");
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "victim".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "carol".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAV".into(), channel: "#c".into(), op: false }); // the target must be in the channel
        let kicked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Kick { from, uid, .. } if from.starts_with("42SB") && uid == "000AAAAAV"));

        // First voter, then the same voter again (deduped) — no kick yet.
        assert!(!kicked(&vote(&mut e, "000AAAAAB", "!votekick victim")), "1 vote: no kick");
        assert!(!kicked(&vote(&mut e, "000AAAAAB", "!votekick victim")), "same voter doesn't double-count");
        // A second distinct voter reaches the threshold.
        assert!(kicked(&vote(&mut e, "000AAAAAC", "!votekick victim")), "2 distinct votes: kicked");
    }

    // HostServ: a vhost is applied on identify and by SET, listed and removed by
    // operators, and its administration is oper-gated with host validation.
    #[test]
    fn hostserv_assigns_and_applies_vhosts() {
        use echo_hostserv::HostServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-hostserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        db.set_vhost("alice", "alice.vhost.example", "system", None).unwrap(); // pre-assigned
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(HostServ { uid: "42SAAAAAG".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let hs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAG".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "alice".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        let sethost = |out: &[NetAction], uid: &str, host: &str| out.iter().any(|a| matches!(a, NetAction::SetHost { uid: u, host: h } if u == uid && h == host));

        // Identifying applies the pre-assigned vhost.
        assert!(sethost(&ns(&mut e, "000AAAAAV", "IDENTIFY password1"), "000AAAAAV", "alice.vhost.example"), "vhost applied on identify");
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");

        // An operator SET applies at once to the online session.
        assert!(sethost(&hs(&mut e, "000AAAAAB", "SET alice new.host.example"), "000AAAAAV", "new.host.example"), "SET applies online");
        // ON re-activates the account's vhost.
        assert!(sethost(&hs(&mut e, "000AAAAAV", "ON"), "000AAAAAV", "new.host.example"), "ON re-applies");
        // LIST shows it.
        assert!(hs(&mut e, "000AAAAAB", "LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("alice") && text.contains("new.host.example"))), "listed");
        // DEL restores the real host on the online session.
        assert!(sethost(&hs(&mut e, "000AAAAAB", "DEL alice"), "000AAAAAV", "realhost"), "DEL restores real host");

        // Non-operators can't SET; invalid hosts are rejected.
        assert!(hs(&mut e, "000AAAAAV", "SET boss x.y").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "oper-gated");
        assert!(hs(&mut e, "000AAAAAB", "SET alice not a host").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("isn't a valid host"))), "host validated");
    }

    // A vhost is normalised the way the ircd displays it (_ -> -) and can't be
    // assigned to two accounts (uniqueness on the normalised form).
    #[test]
    fn hostserv_normalises_and_dedupes() {
        use echo_hostserv::HostServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-hsnorm.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        db.register("bob", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(HostServ { uid: "42SAAAAAG".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let hs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAG".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "alice".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAW".into(), nick: "bob".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAV", "IDENTIFY password1");
        ns(&mut e, "000AAAAAW", "IDENTIFY password1");
        let says = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        // The underscore is normalised to a hyphen, so what's applied matches the
        // ircd's display.
        let out = hs(&mut e, "000AAAAAB", "SET alice cool_user.example");
        assert!(out.iter().any(|a| matches!(a, NetAction::SetHost { host, .. } if host == "cool-user.example")), "normalised: {out:?}");
        // bob can't take the same host (even spelled with the underscore).
        assert!(says(&hs(&mut e, "000AAAAAB", "SET bob cool_user.example"), "already in use"), "uniqueness enforced");
        // A distinct host is fine.
        assert!(hs(&mut e, "000AAAAAB", "SET bob other.example").iter().any(|a| matches!(a, NetAction::SetHost { host, .. } if host == "other.example")), "distinct host ok");
    }

    // A temporary vhost applies while valid; an already-expired one is ignored.
    #[test]
    fn hostserv_vhost_expiry() {
        use echo_hostserv::HostServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-hsexpiry.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        db.register("bob", "password1", None).unwrap();
        db.set_vhost("bob", "old.host.example", "system", Some(0)).unwrap(); // already expired
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(HostServ { uid: "42SAAAAAG".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let hs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAG".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "alice".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAW".into(), nick: "bob".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAV", "IDENTIFY password1");

        // bob's expired vhost is not applied on identify.
        assert!(!ns(&mut e, "000AAAAAW", "IDENTIFY password1").iter().any(|a| matches!(a, NetAction::SetHost { .. })), "expired vhost not applied");
        // A temporary vhost with a duration applies now and lists as temporary.
        let out = hs(&mut e, "000AAAAAB", "SET alice temp.host.example 1h");
        assert!(out.iter().any(|a| matches!(a, NetAction::SetHost { uid, host } if uid == "000AAAAAV" && host == "temp.host.example")), "temporary vhost applied: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("expires in 1h"))), "expiry announced");
        assert!(hs(&mut e, "000AAAAAB", "LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("alice") && text.contains("temporary"))), "listed as temporary");
    }

    // Forbidden patterns block impersonating requests; the template + DEFAULT
    // gives a user a $account-based vhost.
    #[test]
    fn hostserv_forbid_and_template() {
        use echo_hostserv::HostServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-hsforbid.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(HostServ { uid: "42SAAAAAG".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let hs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAG".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "alice".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAV", "IDENTIFY password1");
        let says = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        // Forbid impersonating hosts; a matching request is refused, others pass.
        hs(&mut e, "000AAAAAB", "FORBID (?i)(admin|staff)");
        assert!(says(&hs(&mut e, "000AAAAAV", "REQUEST admin.example"), "isn't allowed"), "impersonating request blocked");
        assert!(says(&hs(&mut e, "000AAAAAV", "REQUEST cool.example"), "will review"), "clean request allowed");
        // A second request right away is throttled.
        assert!(says(&hs(&mut e, "000AAAAAV", "REQUEST another.example"), "Please wait"), "request throttled");
        assert!(says(&hs(&mut e, "000AAAAAV", "FORBID x"), "Access denied"), "FORBID oper-gated");

        // A template lets a user self-serve a $account vhost.
        hs(&mut e, "000AAAAAB", "TEMPLATE $account.users.example");
        let out = hs(&mut e, "000AAAAAV", "DEFAULT");
        assert!(out.iter().any(|a| matches!(a, NetAction::SetHost { uid, host } if uid == "000AAAAAV" && host == "alice.users.example")), "template applied: {out:?}");
    }

    // The vhost OFFER menu: operators OFFER specs, users TAKE them self-serve.
    #[test]
    fn hostserv_offer_menu() {
        use echo_hostserv::HostServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-hsoffer.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(HostServ { uid: "42SAAAAAG".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let hs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAG".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "alice".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAV", "IDENTIFY password1");
        let says = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        // An operator offers a vhost; anyone can list it.
        hs(&mut e, "000AAAAAB", "OFFER free.cloak.example");
        assert!(says(&hs(&mut e, "000AAAAAV", "OFFERLIST"), "free.cloak.example"), "listed");
        // A user takes it and it applies to them.
        let out = hs(&mut e, "000AAAAAV", "TAKE 1");
        assert!(out.iter().any(|a| matches!(a, NetAction::SetHost { uid, host } if uid == "000AAAAAV" && host == "free.cloak.example")), "TAKE applies: {out:?}");
        // The operator removes it; a non-operator can't offer.
        assert!(says(&hs(&mut e, "000AAAAAB", "OFFERDEL 1"), "Removed"), "removed");
        assert!(says(&hs(&mut e, "000AAAAAV", "OFFER x.example"), "Access denied"), "oper-gated");
    }

    // An ident@host vhost applies both the ident (CHGIDENT) and the host.
    #[test]
    fn hostserv_ident_at_host() {
        use echo_hostserv::HostServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-hsident.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        db.set_vhost("alice", "web@cloak.example", "system", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(HostServ { uid: "42SAAAAAG".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "alice".into(), host: "realhost".into() , ip: "0.0.0.0".into() });

        let out = ns(&mut e, "000AAAAAV", "IDENTIFY password1");
        assert!(out.iter().any(|a| matches!(a, NetAction::SetIdent { uid, ident } if uid == "000AAAAAV" && ident == "web")), "ident set: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::SetHost { uid, host } if uid == "000AAAAAV" && host == "cloak.example")), "host set");
    }

    // HostServ REQUEST -> WAITING -> ACTIVATE assigns and applies the vhost; a
    // REJECT clears the request without assigning anything.
    #[test]
    fn hostserv_request_workflow() {
        use echo_hostserv::HostServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-hsreq.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        db.register("bob", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(HostServ { uid: "42SAAAAAG".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let hs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAG".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "alice".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAW".into(), nick: "bob".into(), host: "realhost".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAV", "IDENTIFY password1");
        ns(&mut e, "000AAAAAW", "IDENTIFY password1");
        let says = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        // alice requests; the request shows up in WAITING.
        hs(&mut e, "000AAAAAV", "REQUEST alice.cool.example");
        assert!(says(&hs(&mut e, "000AAAAAB", "WAITING"), "alice.cool.example"), "request waiting");
        // ACTIVATE assigns + applies it to alice's online session.
        let out = hs(&mut e, "000AAAAAB", "ACTIVATE alice");
        assert!(out.iter().any(|a| matches!(a, NetAction::SetHost { uid, host } if uid == "000AAAAAV" && host == "alice.cool.example")), "activated + applied: {out:?}");
        // The request is consumed; WAITING is empty again.
        assert!(says(&hs(&mut e, "000AAAAAB", "WAITING"), "No vhost requests"), "request consumed");

        // A different user's request, rejected, assigns nothing.
        hs(&mut e, "000AAAAAW", "REQUEST other.example");
        assert!(says(&hs(&mut e, "000AAAAAB", "REJECT bob"), "Rejected"), "rejected");
        assert!(says(&hs(&mut e, "000AAAAAB", "WAITING"), "No vhost requests"), "no request left after reject");
        // A non-operator can't approve.
        assert!(says(&hs(&mut e, "000AAAAAV", "WAITING"), "Access denied"), "oper-gated");

        // A host forbidden AFTER its request is filed must not slip through ACTIVATE.
        hs(&mut e, "000AAAAAB", "REQUEST evilcorp.example");
        hs(&mut e, "000AAAAAB", "FORBID (?i)evilcorp");
        let out = hs(&mut e, "000AAAAAB", "ACTIVATE boss");
        assert!(says(&out, "forbidden list"), "activate refused for a now-forbidden host: {out:?}");
        assert!(!out.iter().any(|a| matches!(a, NetAction::SetHost { .. })), "no vhost applied when forbidden: {out:?}");
    }

    // StatServ reports per-channel activity (#channel) and the global registry
    // (SERVER, operators only).
    #[test]
    fn statserv_reports_channel_and_global() {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        use echo_statserv::StatServ;
        let path = std::env::temp_dir().join("echo-statserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
                Box::new(StatServ { uid: "42SAAAAAF".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin).with(echo_api::Priv::Auspex));
        e.set_opers(opers);
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let ss = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAF".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "spammer".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        bs(&mut e, "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "ASSIGN #c Bendy");
        say(&mut e, "one");
        say(&mut e, "two");
        say(&mut e, "three");

        // Per-channel view.
        let out = ss(&mut e, "#c");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("lines seen"))), "channel lines: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("spammer") && text.contains("3"))), "top talker: {out:?}");
        // Global view (oper) shows the shared counters.
        let out = ss(&mut e, "SERVER");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("botserv.messages"))), "global counters: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("channels.total"))), "gauge shown");
    }

    // The shared stats registry gathers per-service command counts, BotServ
    // events, and live gauges — the same pipe every module reports through.
    #[test]
    fn stats_registry_collects_across_services() {
        let (mut e, _p) = kicker_fixture("bsstats");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        // The fixture already ran a NickServ IDENTIFY and BotServ BOT ADD/ASSIGN.
        bs(&mut e, "KICK #c CAPS ON");
        say(&mut e, "SHOUTING LOUDLY NOW"); // one kick

        let s = e.stats_snapshot();
        assert!(s.get("nickserv.command").copied().unwrap_or(0) >= 1, "nickserv counted: {s:?}");
        assert!(s.get("botserv.command").copied().unwrap_or(0) >= 2, "botserv commands counted");
        assert_eq!(s.get("botserv.kick").copied(), Some(1), "one kick counted");
        // Live gauges derived from the store.
        assert_eq!(s.get("channels.total").copied(), Some(1));
        assert_eq!(s.get("bots.total").copied(), Some(1));
        assert!(s.contains_key("accounts.total"));
    }

    // DONTKICKVOICES exempts voiced users; removing the voice makes them kickable.
    #[test]
    fn botserv_dontkickvoices_exempts() {
        let (mut e, _p) = kicker_fixture("bsdkv");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        let kicked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAS"));
        bs(&mut e, "KICK #c CAPS ON");
        bs(&mut e, "KICK #c DONTKICKVOICES ON");

        // Voiced: exempt.
        e.handle(NetEvent::ChannelVoice { channel: "#c".into(), uid: "000AAAAAS".into(), voice: true });
        assert!(!kicked(&say(&mut e, "SHOUTING WHILE VOICED")), "voiced user exempt");
        // Devoiced: kickable again.
        e.handle(NetEvent::ChannelVoice { channel: "#c".into(), uid: "000AAAAAS".into(), voice: false });
        assert!(kicked(&say(&mut e, "SHOUTING WITHOUT VOICE")), "devoiced user kicked");
    }

    // Triggers substitute regex capture groups ($1) and honour a cooldown.
    #[test]
    fn botserv_trigger_captures_and_cooldown() {
        let (mut e, _p) = kicker_fixture("bstrigcap");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        bs(&mut e, "TRIGGER #c ADD (?i)hi (\\w+)|Hi $1!|30"); // capture group + 30s cooldown
        let response = |out: &[NetAction]| out.iter().find_map(|a| match a {
            NetAction::Privmsg { text, .. } => Some(text.clone()),
            _ => None,
        });

        e.now_override = Some(1000);
        assert_eq!(response(&say(&mut e, "hi alice")).as_deref(), Some("Hi alice!"), "capture substituted");
        // Within the cooldown window: suppressed.
        e.now_override = Some(1010);
        assert_eq!(response(&say(&mut e, "hi bob")), None, "suppressed by cooldown");
        // After the cooldown: fires again.
        e.now_override = Some(1031);
        assert_eq!(response(&say(&mut e, "hi carol")).as_deref(), Some("Hi carol!"), "fires after cooldown");
    }

    // WARN gives a one-time warning before the first real kick.
    #[test]
    fn botserv_warn_before_kick() {
        let (mut e, _p) = kicker_fixture("bswarn");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        bs(&mut e, "KICK #c CAPS ON");
        bs(&mut e, "KICK #c WARN ON");
        let kicked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAS"));

        // First offence: a warning notice from the bot, no kick.
        let out = say(&mut e, "SHOUTING THE FIRST TIME");
        assert!(!kicked(&out), "no kick on first offence");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { from, to, text } if from.starts_with("42SB") && to == "000AAAAAS" && text.contains("Next time"))), "warned: {out:?}");
        // Second offence: kicked for real.
        assert!(kicked(&say(&mut e, "SHOUTING THE SECOND TIME")), "kicked on second offence");
    }

    // KICK TEST dry-runs the content kickers against a line without kicking.
    #[test]
    fn botserv_kick_test_dry_run() {
        let (mut e, _p) = kicker_fixture("bskicktest");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        bs(&mut e, "KICK #c CAPS ON");
        bs(&mut e, "BADWORDS #c ADD fr[ao]g");
        bs(&mut e, "KICK #c BADWORDS ON");
        let says = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        assert!(says(&bs(&mut e, "KICK #c TEST HELLO EVERYONE LOUD"), "would be kicked"), "caps flagged");
        assert!(says(&bs(&mut e, "KICK #c TEST i love frogs"), "would be kicked"), "badword flagged");
        assert!(says(&bs(&mut e, "KICK #c TEST hello there"), "trips no content kicker"), "clean line ok");
    }

    // Times-to-ban: after TTB kicks the bot bans the user, and BANEXPIRE lifts
    // the ban once it elapses (swept on the next event).
    #[test]
    fn botserv_ttb_bans_and_expires() {
        let (mut e, _p) = kicker_fixture("bsttb");
        let bs = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
        let say = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "#c".into(), text: t.into() });
        bs(&mut e, "KICK #c CAPS ON");
        bs(&mut e, "KICK #c TTB 2");
        bs(&mut e, "SET #c BANEXPIRE 1m");
        let banned = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::ChannelMode { from, channel, modes } if from.starts_with("42SB") && channel == "#c" && modes == "+b *!*@h"));
        let kicked = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAS"));

        e.now_override = Some(1000);
        // First offence: kick only.
        let out = say(&mut e, "SHOUTING LOUDLY ONE");
        assert!(kicked(&out) && !banned(&out), "1st: kick only: {out:?}");
        // Second offence reaches TTB: ban then kick.
        let out = say(&mut e, "SHOUTING LOUDLY TWO");
        assert!(banned(&out) && kicked(&out), "2nd: ban + kick: {out:?}");

        // Before the ban expires, an event lifts nothing.
        e.now_override = Some(1059);
        let out = e.handle(NetEvent::Ping { token: "t".into(), from: None });
        assert!(!out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes.starts_with("-b"))), "not yet expired: {out:?}");
        // After it expires, the next event lifts it.
        e.now_override = Some(1061);
        let out = e.handle(NetEvent::Ping { token: "t".into(), from: None });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#c" && modes == "-b *!*@h")), "ban lifted: {out:?}");
    }

    // Registers #c with founder boss (admin), a live assigned bot Bendy, and
    // returns the engine ready for KICK configuration + a spammer uid 000AAAAAS.
    fn kicker_fixture(tag: &str) -> (Engine, std::path::PathBuf) {
        use echo_botserv::BotServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join(format!("echo-{tag}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "spammer".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: "BOT ADD Bendy bot serv.host Helper".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: "ASSIGN #c Bendy".into() });
        (e, path)
    }

    // A member's personal greet is shown by the assigned bot on join, once the
    // channel enables greets and the member has access.
    #[test]
    fn botserv_greet_shown_on_join() {
        use echo_botserv::BotServ;
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bsgreet.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.chan_service = Some("42SAAAAAB".into());
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAB", "SET GREET hello all");
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");

        // Greets off by default: joining is silent.
        assert!(
            !e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: true }).iter().any(|a| matches!(a, NetAction::Privmsg { .. })),
            "no greet before it is enabled"
        );
        e.handle(NetEvent::Part { uid: "000AAAAAB".into(), channel: "#c".into(), reason: String::new() });
        bs(&mut e, "000AAAAAB", "SET #c GREET ON");
        // Now the founder's greet is shown by the bot.
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: true });
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text } if from.starts_with("42SB") && to == "#c" && text == "[boss] hello all")),
            "greet shown: {out:?}"
        );
    }

    // Fantasy commands typed in-channel route through ChanServ and are sourced
    // from the assigned bot.
    #[test]
    fn fantasy_roll_speaks_dice_through_the_bot() {
        use echo_botserv::BotServ;
        use echo_chanserv::ChanServ;
        use echo_diceserv::DiceServ;
        let path = std::env::temp_dir().join("echo-fantasyroll.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        db.register_channel("#d", "boss").unwrap(); // no bot
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
                Box::new(DiceServ { uid: "42SAAAAAI".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        let chan = |e: &mut Engine, uid: &str, c: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: c.into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");

        // `!roll` is answered by DiceServ but spoken into the channel by the bot.
        let out = chan(&mut e, "000AAAAAB", "#c", "!roll 2d6+1");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text } if from.starts_with("42SB") && to == "#c" && text.contains("2d6+1") && text.contains('='))),
            "fantasy roll spoken by the bot: {out:?}"
        );
        // No DiceServ (or no bot) → no dice fantasy.
        assert!(chan(&mut e, "000AAAAAB", "#d", "!roll 2d6").is_empty(), "no bot, no roll");
    }

    #[test]
    fn botserv_fantasy_routes_through_bot() {
        use echo_botserv::BotServ;
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-bsfantasy.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        db.register_channel("#d", "boss").unwrap(); // registered, no bot
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(BotServ { uid: "42SAAAAAD".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let bs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAD".into(), text: t.into() });
        let chan = |e: &mut Engine, uid: &str, c: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: c.into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        bs(&mut e, "000AAAAAB", "BOT ADD Bendy bot serv.host Helper");
        bs(&mut e, "000AAAAAB", "ASSIGN #c Bendy");

        // `!op` (founder, no target) ops the invoker, sourced from the bot uid.
        let out = chan(&mut e, "000AAAAAB", "#c", "!op");
        assert!(
            out.iter().any(|a| matches!(a, NetAction::ChannelMode { from, channel, modes } if from.starts_with("42SB") && channel == "#c" && modes.contains("+o") && modes.contains("000AAAAAB"))),
            "fantasy op via bot: {out:?}"
        );
        // Ordinary chatter is ignored.
        assert!(chan(&mut e, "000AAAAAB", "#c", "hello everyone").is_empty(), "chatter ignored");
        // Fantasy in a channel with no bot does nothing.
        assert!(chan(&mut e, "000AAAAAB", "#d", "!op").is_empty(), "no bot, no fantasy");

        // An unknown `!word` (another bot's command sharing the `!` prefix) draws
        // no reply from the assigned bot — not even "I don't know that command".
        let out = chan(&mut e, "000AAAAAB", "#c", "!cissue \"CERT LIST\" fix it");
        assert!(out.is_empty(), "unknown fantasy command stays silent: {out:?}");
    }

    // MemoServ delivers a memo to an offline account and notifies them on login.
    #[test]
    fn memoserv_delivers_and_notifies_on_login() {
        use echo_memoserv::MemoServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-memoserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "password1", None).unwrap();
        db.register("bob", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(MemoServ { uid: "42SAAAAAE".into() }),
            ],
            db,
        );
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let ms = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAE".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        // alice identifies and sends bob (offline) a memo.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        assert!(notice(&ms(&mut e, "000AAAAAB", "SEND bob Hello from alice"), "Memo sent"));

        // bob logs in later and is told he has a new memo, then reads it.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into() , ip: "0.0.0.0".into() });
        assert!(notice(&ns(&mut e, "000AAAAAC", "IDENTIFY password1"), "new memo"));
        assert!(notice(&ms(&mut e, "000AAAAAC", "READ NEW"), "Hello from alice"));
    }

    // Channel SUSPEND is oper-gated and freezes founder management until lifted.
    #[test]
    fn channel_suspend_is_oper_gated_and_freezes_management() {
        use echo_chanserv::ChanServ;
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-chansuspendcmd.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("boss", "password1", None).unwrap();
        db.register("staff", "password1", None).unwrap();
        db.register_channel("#c", "boss").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Suspend));
        e.set_opers(opers);
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let notice = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        ns(&mut e, "000AAAAAC", "IDENTIFY password1");

        // A non-oper cannot suspend a channel.
        assert!(notice(&cs(&mut e, "000AAAAAB", "SUSPEND #c"), "Access denied"));
        // The oper suspends it.
        assert!(notice(&cs(&mut e, "000AAAAAC", "SUSPEND #c raided"), "now suspended"));
        // The founder can no longer manage it — including MODE/ACCESS/FLAGS, which
        // used to bypass the suspension freeze.
        assert!(notice(&cs(&mut e, "000AAAAAB", "SET #c SIGNKICK ON"), "suspended"));
        assert!(notice(&cs(&mut e, "000AAAAAB", "MODE #c +m"), "suspended"), "MODE frozen while suspended");
        assert!(notice(&cs(&mut e, "000AAAAAB", "ACCESS #c ADD someone sop"), "suspended"), "ACCESS frozen while suspended");
        assert!(notice(&cs(&mut e, "000AAAAAB", "FLAGS #c someone +o"), "suspended"), "FLAGS frozen while suspended");
        // UNSUSPEND restores management.
        assert!(notice(&cs(&mut e, "000AAAAAC", "UNSUSPEND #c"), "no longer suspended"));
        assert!(notice(&cs(&mut e, "000AAAAAB", "SET #c SIGNKICK ON"), "is now"));
    }

    // SUSPEND is oper-gated, blocks the victim's login, and UNSUSPEND restores it.
    #[test]
    fn suspend_blocks_login_and_needs_oper() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-suspendcmd.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("victim", "password1", None).unwrap();
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Suspend));
        e.set_opers(opers);
        let to_ns = |e: &mut Engine, uid: &str, text: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: text.into() });
        let notice = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "victim".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });

        // A non-oper cannot suspend.
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "SUSPEND victim"), "Access denied"));
        // The oper identifies and suspends the victim.
        to_ns(&mut e, "000AAAAAC", "IDENTIFY password1");
        assert!(notice(&to_ns(&mut e, "000AAAAAC", "SUSPEND victim being a nuisance"), "now suspended"));
        // The victim can no longer identify.
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "IDENTIFY password1"), "suspended"));
        // UNSUSPEND lets them back in.
        assert!(notice(&to_ns(&mut e, "000AAAAAC", "UNSUSPEND victim"), "no longer suspended"));
        assert!(notice(&to_ns(&mut e, "000AAAAAB", "IDENTIFY password1"), "now identified"));
    }

    // An auspex oper sees another account's hidden INFO (email); a non-oper does not.
    #[test]
    fn auspex_oper_sees_hidden_info() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-auspex.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "password1", Some("alice@example.org".into())).unwrap();
        db.register("operator", "password1", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        let mut opers = std::collections::HashMap::new();
        opers.insert("operator".to_string(), Privs::default().with(echo_api::Priv::Auspex));
        e.set_opers(opers);
        let info_alice = |e: &mut Engine, uid: &str| {
            e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "INFO alice".into() })
        };
        let shows_email = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("alice@example.org")));

        // The auspex oper identifies and sees alice's email.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "operator".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        assert!(shows_email(&info_alice(&mut e, "000AAAAAB")), "auspex oper sees the email");

        // An unidentified (non-oper) viewer does not.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "guest".into(), host: "h".into() , ip: "0.0.0.0".into() });
        assert!(!shows_email(&info_alice(&mut e, "000AAAAAC")), "non-oper sees no email");
    }

    // TOPICLOCK reverts an unauthorised topic change; KEEPTOPIC restores the
    // remembered topic when the channel is recreated.
    #[test]
    fn topiclock_reverts_and_keeptopic_restores() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-topic.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register_channel("#c", "boss").unwrap();
        db.set_channel_setting("#c", db::ChanSetting::KeepTopic, true).unwrap();
        db.set_channel_setting("#c", db::ChanSetting::TopicLock, true).unwrap();
        db.set_channel_topic("#c", "Official topic").unwrap();
        let mut e = Engine::new(vec![Box::new(ChanServ { uid: "42SAAAAAB".into() })], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "rando".into(), host: "h".into() , ip: "0.0.0.0".into() });
        // A user without access changes the topic -> reverted to the stored one.
        let out = e.handle(NetEvent::TopicChange { channel: "#c".into(), setter: "000AAAAAB".into(), topic: "hacked".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Topic { topic, .. } if topic == "Official topic")), "topiclock reverts: {out:?}");
        // KEEPTOPIC restores the remembered topic on channel (re)creation.
        let out = e.handle(NetEvent::ChannelCreate { channel: "#c".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Topic { topic, .. } if topic == "Official topic")), "keeptopic restores: {out:?}");
    }

    // ChanServ: registration needs identification, INFO shows the founder, and
    // only the founder can drop.
    #[test]
    fn chanserv_register_info_drop() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-chanserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);

        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        let notice = |out: &[NetAction], needle: &str| {
            out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)))
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "host.example".into() , ip: "0.0.0.0".into() });

        // Not identified yet: refused.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "REGISTER #room"), "logged in"));

        // Identify, then register. Registration needs operator status in the channel.
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "REGISTER #room"), "channel operator"), "op required to register");
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: true });
        let out = to_cs(&mut e, "000AAAAAB", "REGISTER #room");
        assert!(notice(&out, "now registered"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "+r")), "register sets +r: {out:?}");
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "INFO #room"), "alice"));

        // Founder sets a mode lock: it applies immediately and shows on view.
        let out = to_cs(&mut e, "000AAAAAB", "MLOCK #room +nt-s");
        assert!(notice(&out, "updated"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "+rnt-s")), "mlock applied: {out:?}");
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "MLOCK #room"), "+nt-s"));

        // Founder sets modes directly via ChanServ MODE.
        let out = to_cs(&mut e, "000AAAAAB", "MODE #room +S");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "+S")), "MODE applies: {out:?}");

        // Founder manages the access list.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "ACCESS #room ADD helper op"), "Added"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "ACCESS #room"), "helper"));

        // A different, unidentified user cannot change modes, access, the lock, or drop it.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "MODE #room +i"), "founder"));
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "ACCESS #room ADD x op"), "founder"));
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "MLOCK #room +i"), "founder"));
        assert!(notice(&to_cs(&mut e, "000AAAAAC", "DROP #room"), "founder"));

        // The founder can, which also clears +r.
        let out = to_cs(&mut e, "000AAAAAB", "DROP #room");
        assert!(notice(&out, "dropped"));
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes == "-r")), "drop clears +r: {out:?}");
    }

    // Notable service actions are announced to the staff audit channel, sourced
    // from the services server; private/cosmetic events are not, and no channel
    // means no feed.
    #[test]
    fn audit_feed_announces_notable_actions() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        e.set_log_channel(Some("#services".into()));
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        // The audit line is a Notice to the log channel, from the services SID.
        let audit = |out: &[NetAction], needle: &str| {
            out.iter().any(|a| matches!(a, NetAction::Notice { from, to, text }
                if from == "42S" && to == "#services" && text.contains(needle)))
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: true });

        // Registering a channel is announced with the actor and the founder.
        let out = to_cs(&mut e, "000AAAAAB", "REGISTER #room");
        assert!(audit(&out, "registered channel \x02#room\x02"), "reg announced: {out:?}");
        assert!(audit(&out, "alice"), "names the actor");

        // A cosmetic mode lock is not surfaced (only its user-facing reply is).
        let out = to_cs(&mut e, "000AAAAAB", "MLOCK #room +nt");
        assert!(!out.iter().any(|a| matches!(a, NetAction::Notice { to, .. } if to == "#services")), "mlock not audited: {out:?}");

        // Dropping the channel is announced.
        assert!(audit(&to_cs(&mut e, "000AAAAAB", "DROP #room"), "dropped channel \x02#room\x02"), "drop announced");

        // With no log channel configured, nothing is emitted to it.
        e.set_log_channel(None);
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#other".into(), op: true });
        let out = to_cs(&mut e, "000AAAAAB", "REGISTER #other");
        assert!(!out.iter().any(|a| matches!(a, NetAction::Notice { to, .. } if to == "#services")), "no feed when unset: {out:?}");
    }

    // Inactivity-expiry drops stale accounts and channels, but spares opers, live
    // sessions, occupied channels, and anything pinned with NOEXPIRE. Each expiry
    // is announced to the audit channel.
    #[test]
    fn expiry_sweep_respects_pins_sessions_and_opers() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-expiry.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        for a in ["victim", "staff", "active", "pinned"] {
            db.register(a, "password1", None).unwrap();
        }
        db.register_channel("#dead", "staff").unwrap(); // founder is an oper, so only the channel expires
        db.register_channel("#pinned", "staff").unwrap();
        db.register_channel("#live", "staff").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        e.set_log_channel(Some("#services".into()));
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);

        // staff (an oper) pins one account and one channel against expiry.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "NOEXPIRE pinned ON".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAB".into(), text: "NOEXPIRE #pinned ON".into() });
        // active keeps a live session; #live keeps a member sitting in it.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "active".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#live".into(), op: false });

        // Jump far past the threshold and sweep.
        e.now_override = Some(10_000_000_000);
        e.set_expiry(Some(100), Some(100), None);
        e.expire_sweep();

        // Only the plain, unused, unpinned, session-less records are gone.
        assert!(!e.db.exists("victim"), "inactive account expired");
        assert!(e.db.channel("#dead").is_none(), "unused channel expired");
        assert!(e.db.exists("staff"), "oper account spared");
        assert!(e.db.exists("active"), "logged-in account spared");
        assert!(e.db.exists("pinned"), "NOEXPIRE account spared");
        assert!(e.db.channel("#pinned").is_some(), "NOEXPIRE channel spared");
        assert!(e.db.channel("#live").is_some(), "occupied channel spared");

        // The expiries were announced and the dropped channel had +r cleared.
        let (mut acct_note, mut chan_note, mut unreg) = (false, false, false);
        while let Ok(a) = rx.try_recv() {
            match a {
                NetAction::Notice { to, text, .. } if to == "#services" && text.contains("victim") && text.contains("expired") => acct_note = true,
                NetAction::Notice { to, text, .. } if to == "#services" && text.contains("#dead") && text.contains("expired") => chan_note = true,
                NetAction::ChannelMode { channel, modes, .. } if channel == "#dead" && modes == "-r" => unreg = true,
                _ => {}
            }
        }
        assert!(acct_note, "account expiry announced to audit channel");
        assert!(chan_note, "channel expiry announced to audit channel");
        assert!(unreg, "expired channel had +r cleared");
    }

    // OperServ AKILL: an admin adds/lists/removes network bans, they drive the
    // ircd's G-lines, persist for re-assertion at burst, and non-admins are shut
    // out entirely.
    #[test]
    fn operserv_akill_add_list_del_and_burst() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-akill.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("nobody", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        e.set_log_channel(Some("#services".into()));
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAN".into(), nick: "nobody".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAN".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        // A non-admin can't even see OperServ exists beyond the refusal.
        let denied = os(&mut e, "000AAAAAN", "AKILL ADD *@evil.host being evil");
        assert!(denied.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "non-admin refused: {denied:?}");
        assert!(!denied.iter().any(|a| matches!(a, NetAction::AddLine { .. })), "no ban from a non-admin");

        // Admin adds a temporary ban: it drives a G-line and is audited.
        let out = os(&mut e, "000AAAAAS", "AKILL ADD +1h *@evil.host spamming");
        assert!(out.iter().any(|a| matches!(a, NetAction::AddLine { kind, mask, duration, .. } if kind == "G" && mask == "*@evil.host" && *duration == 3600)), "G-line added: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "#services" && text.contains("*@evil.host"))), "ban audited: {out:?}");

        // A too-wide mask is refused outright.
        assert!(os(&mut e, "000AAAAAS", "AKILL ADD *@* everything").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("too wide"))), "wildcard mask refused");

        // LIST shows it, numbered.
        assert!(os(&mut e, "000AAAAAS", "AKILL LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("1.") && text.contains("*@evil.host"))), "listed");

        // It survives to burst: startup re-asserts the G-line with a remaining
        // duration, not the original 3600.
        assert!(e.startup_actions().iter().any(|a| matches!(a, NetAction::AddLine { mask, duration, .. } if mask == "*@evil.host" && *duration > 0 && *duration <= 3600)), "re-asserted at burst");

        // DEL by number removes it and lifts the G-line.
        let out = os(&mut e, "000AAAAAS", "AKILL DEL 1");
        assert!(out.iter().any(|a| matches!(a, NetAction::DelLine { kind, mask } if kind == "G" && mask == "*@evil.host")), "G-line lifted: {out:?}");
        assert!(os(&mut e, "000AAAAAS", "AKILL LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("No matching"))), "list now empty");
    }

    #[test]
    fn ctcp_query_to_a_service_replies_or_stays_silent() {
        use echo_nickserv::NickServ;
        let path = std::env::temp_dir().join("echo-ctcp.jsonl");
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path, "42S");
        let mut e = Engine::new(
            vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })],
            db,
        );
        e.set_sid("42S".into());
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        let ns = |e: &mut Engine, t: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: t.into() });

        // VERSION → a CTCP NOTICE from the service, never an "unknown command".
        let ver = ns(&mut e, "\x01VERSION\x01");
        assert!(ver.iter().any(|a| matches!(a, NetAction::Notice { from, text, .. } if from == "42SAAAAAA" && text.starts_with("\x01VERSION echo") && text.ends_with('\x01'))), "VERSION reply: {ver:?}");
        assert!(!ver.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("don't know"))), "no unknown-command bounce");
        // PING echoes the token back verbatim.
        assert!(ns(&mut e, "\x01PING tok123\x01").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text == "\x01PING tok123\x01")), "PING echo");
        // ACTION and unrecognised CTCPs get no reply at all.
        assert!(ns(&mut e, "\x01ACTION waves\x01").iter().all(|a| !matches!(a, NetAction::Notice { .. })), "ACTION silent");
        assert!(ns(&mut e, "\x01FLOOBLE\x01").iter().all(|a| !matches!(a, NetAction::Notice { .. })), "unknown CTCP silent");
        // A normal (non-CTCP) unknown command is still answered — the intercept
        // didn't swallow ordinary routing.
        assert!(ns(&mut e, "FLOOBLE").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("don't know"))), "normal unknown command still answered");
    }

    // An account approaching expiry with an email on file is warned once by
    // email, isn't dropped while still in the window, and isn't warned twice.
    #[test]
    fn expiry_warns_by_email_before_dropping() {
        let path = std::env::temp_dir().join("echo-expwarn.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.set_email_enabled(true);
        db.register("dozer", "password1", Some("dozer@example.test".to_string())).unwrap();
        db.register("nomail", "password1", None).unwrap();
        let mut e = Engine::new(vec![Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })], db);
        e.set_sid("42S".into());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);

        // A very wide warning window that brackets any freshly-registered account.
        e.now_override = Some(10_000_000_000);
        e.set_expiry(Some(9_900_000_000), None, Some(9_000_000_000));
        e.expire_sweep();

        // The account with an email got exactly one warning; neither was dropped.
        let mut warns = 0;
        while let Ok(a) = rx.try_recv() {
            if let NetAction::SendEmail { to, subject, .. } = a {
                assert_eq!(to, "dozer@example.test");
                assert!(subject.contains("dozer") && subject.contains("expire"), "subject: {subject}");
                warns += 1;
            }
        }
        assert_eq!(warns, 1, "one warning email for the account with an address");
        assert!(e.db.exists("dozer"), "still in the window, not dropped");
        assert!(e.db.exists("nomail"), "no email, no warning, not dropped");

        // A second sweep in the same window doesn't re-warn.
        e.expire_sweep();
        let mut again = 0;
        while let Ok(a) = rx.try_recv() {
            if matches!(a, NetAction::SendEmail { .. }) {
                again += 1;
            }
        }
        assert_eq!(again, 0, "warning isn't repeated while still idle");
    }

    // OperServ SQLINE (nick bans), GLOBAL (announce to all), and KILL (disconnect
    // a user): the Q-line, the $* broadcast, and the KILL all reach the ircd, and
    // each is admin-gated.
    #[test]
    fn operserv_sqline_global_and_kill() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osmore.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("plain", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAP".into(), nick: "plain".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAP".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAV".into(), nick: "spammer".into(), host: "h".into() , ip: "0.0.0.0".into() });

        // SQLINE drives a Q-line on the nick mask, tracked separately from AKILLs.
        let out = os(&mut e, "000AAAAAS", "SQLINE ADD *bot* botnet");
        assert!(out.iter().any(|a| matches!(a, NetAction::AddLine { kind, mask, .. } if kind == "Q" && mask == "*bot*")), "Q-line added: {out:?}");
        // A rejected @-shaped mask (that belongs to AKILL, not SQLINE).
        assert!(os(&mut e, "000AAAAAS", "SQLINE ADD a@b spam").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("valid"))), "nick mask rejects user@host");
        // STATS reflects the live ban counts.
        assert!(os(&mut e, "000AAAAAS", "STATS").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("1") && text.contains("SQLINE"))), "stats shows the sqline count");
        // SNLINE drives a realname R-line.
        assert!(os(&mut e, "000AAAAAS", "SNLINE ADD .*free.money.* spambot").iter().any(|a| matches!(a, NetAction::AddLine { kind, mask, .. } if kind == "R" && mask == ".*free.money.*")), "R-line added");
        // SHUN drives a SHUN X-line on a user@host mask.
        assert!(os(&mut e, "000AAAAAS", "SHUN ADD *@noisy.host quiet down").iter().any(|a| matches!(a, NetAction::AddLine { kind, mask, .. } if kind == "SHUN" && mask == "*@noisy.host")), "shun added");
        // CBAN drives a channel-name ban; an all-wildcard channel mask is refused.
        assert!(os(&mut e, "000AAAAAS", "CBAN ADD #warez* piracy").iter().any(|a| matches!(a, NetAction::AddLine { kind, mask, .. } if kind == "CBAN" && mask == "#warez*")), "cban added");
        assert!(os(&mut e, "000AAAAAS", "CBAN ADD #* everything").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("too wide"))), "wildcard channel refused");

        // GLOBAL fans out to every user via the $* server glob.
        let out = os(&mut e, "000AAAAAS", "GLOBAL rebooting in 5");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "$*" && text.contains("rebooting in 5"))), "global broadcast: {out:?}");

        // KILL disconnects the named user, attributed to the oper.
        let out = os(&mut e, "000AAAAAS", "KILL spammer flooding");
        assert!(out.iter().any(|a| matches!(a, NetAction::KillUser { uid, reason, .. } if uid == "000AAAAAV" && reason.contains("flooding") && reason.contains("staff"))), "kill issued: {out:?}");

        // None of it works for a non-admin: refused, and no network action leaks.
        for cmd in ["SQLINE ADD *x* y", "GLOBAL hi", "KILL staff go"] {
            let out = os(&mut e, "000AAAAAP", cmd);
            assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "non-admin refused {cmd}");
            assert!(!out.iter().any(|a| matches!(a, NetAction::AddLine { .. } | NetAction::KillUser { .. })), "no ban/kill from non-admin {cmd}");
            assert!(!out.iter().any(|a| matches!(a, NetAction::Notice { to, .. } if to == "$*")), "no broadcast from non-admin {cmd}");
        }
    }

    // OperServ MODE (forced channel mode override, resolving a status-mode nick
    // to its uid) and KICK (remove a user from a channel), both admin-gated.
    #[test]
    fn operserv_mode_and_kick() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osmodekick.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("plain", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAP".into(), nick: "plain".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAP".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAT".into(), nick: "target".into(), host: "h".into() , ip: "0.0.0.0".into() });

        // A status mode's nick target is resolved to its uid in the FMODE.
        let out = os(&mut e, "000AAAAAS", "MODE #room +o target");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { from, channel, modes } if from == "42SAAAAAH" && channel == "#room" && modes == "+o 000AAAAAT")), "status mode resolved: {out:?}");
        // A paramless mode passes straight through.
        let out = os(&mut e, "000AAAAAS", "MODE #room +mn");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "+mn")), "paramless mode: {out:?}");

        // KICK removes the user, attributed to the operator.
        let out = os(&mut e, "000AAAAAS", "KICK #room target trolling");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { from, channel, uid, reason } if from == "42SAAAAAH" && channel == "#room" && uid == "000AAAAAT" && reason.contains("trolling") && reason.contains("staff"))), "kick issued: {out:?}");

        // A non-admin gets nothing but a refusal.
        for cmd in ["MODE #room +o target", "KICK #room target go"] {
            let out = os(&mut e, "000AAAAAP", cmd);
            assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "non-admin refused {cmd}");
            assert!(!out.iter().any(|a| matches!(a, NetAction::ChannelMode { .. } | NetAction::Kick { .. })), "no action from non-admin {cmd}");
        }
    }

    // LOGSEARCH finds recorded actions — both a kick (stamped) and an akill (from
    // the command audit trail); gated on auspex.
    #[test]
    fn operserv_logsearch_finds_actions() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-logsearch.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("mod", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Root));
        opers.insert("mod".to_string(), Privs::default().with(echo_api::Priv::Suspend));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let has = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAM".into(), nick: "mod".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAM".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAT".into(), nick: "troll".into(), host: "h".into(), ip: "0.0.0.0".into() });

        os(&mut e, "000AAAAAS", "AKILL ADD *@evil.host spamming");
        os(&mut e, "000AAAAAS", "KICK #room troll flooding");

        // The akill (from the command audit trail) is searchable.
        assert!(has(&os(&mut e, "000AAAAAS", "LOGSEARCH evil.host"), "evil.host"), "akill searchable");
        // The kick (stamped at the choke-point) is searchable.
        assert!(has(&os(&mut e, "000AAAAAS", "LOGSEARCH troll"), "troll"), "kick searchable");
        // A bare LOGSEARCH lists recent entries.
        assert!(has(&os(&mut e, "000AAAAAS", "LOGSEARCH"), "End of results"), "lists recent");
        // A nonsense pattern finds nothing.
        assert!(has(&os(&mut e, "000AAAAAS", "LOGSEARCH zzzznope"), "No matching"), "empty result");
        // An oper without auspex is refused.
        assert!(has(&os(&mut e, "000AAAAAM", "LOGSEARCH troll"), "auspex"), "auspex-gated");
    }

    // Every user-removal gets a traceable incident id stamped into its reason and
    // recorded in the searchable log.
    #[test]
    fn removals_get_incident_ids() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-incident.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAT".into(), nick: "troll".into(), host: "h".into(), ip: "0.0.0.0".into() });

        // The kick reason carries a bracketed id, and the incident is searchable.
        let out = os(&mut e, "000AAAAAS", "KICK #room troll flooding");
        let reason = out.iter().find_map(|a| match a {
            NetAction::Kick { reason, .. } => Some(reason.clone()),
            _ => None,
        }).expect("a kick was issued");
        assert!(reason.contains("flooding") && reason.contains("[#"), "id stamped into reason: {reason}");
        // The id in the reason and the incident log agree, and search finds it.
        let id = reason.split("[#").nth(1).and_then(|s| s.split(']').next()).unwrap().to_string();
        let hits = e.network.search_incidents(&id, 10);
        assert_eq!(hits.len(), 1, "searchable by id");
        assert!(hits[0].summary.contains("troll"), "summary names the target: {}", hits[0].summary);
        assert!(e.network.search_incidents("kicked", 10).iter().any(|i| i.summary.contains("troll")), "searchable by keyword");
    }

    // OperServ CHANKILL: AKILL every host in a channel at once, deduped, never
    // banning the operator who ran it.
    #[test]
    fn operserv_chankill_clears_a_channel() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-oschankill.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let conn = |e: &mut Engine, uid: &str, host: &str| e.handle(NetEvent::UserConnect { uid: uid.into(), nick: uid.into(), host: host.into(), ip: "0.0.0.0".into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "staffhost".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        conn(&mut e, "000AAAAA1", "bad1");
        conn(&mut e, "000AAAAA2", "bad2");
        conn(&mut e, "000AAAAA3", "bad1"); // same host as A1 → deduped
        for u in ["000AAAAAS", "000AAAAA1", "000AAAAA2", "000AAAAA3"] {
            e.handle(NetEvent::Join { uid: u.into(), channel: "#spam".into(), op: false });
        }

        let out = os(&mut e, "000AAAAAS", "CHANKILL #spam flooding");
        // Both distinct spammer hosts are G-lined, once each.
        assert!(out.iter().any(|a| matches!(a, NetAction::AddLine { mask, .. } if mask == "*@bad1")), "bad1 banned: {out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::AddLine { mask, .. } if mask == "*@bad2")), "bad2 banned");
        assert_eq!(out.iter().filter(|a| matches!(a, NetAction::AddLine { mask, .. } if mask == "*@bad1")).count(), 1, "deduped");
        // The operator's own host is spared.
        assert!(!out.iter().any(|a| matches!(a, NetAction::AddLine { mask, .. } if mask == "*@staffhost")), "operator not self-banned");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("2") && text.contains("AKILL"))), "reports 2 hosts");
    }

    // OperServ JUPE: hold a server name with a fake server, re-assert it at burst,
    // and lift it with a squit. Admin-only.
    #[test]
    fn operserv_jupe_holds_and_lifts() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osjupe.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into(), ip: "9.9.9.9".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        // Juping introduces a fake server holding the name.
        let out = os(&mut e, "000AAAAAS", "JUPE rogue.example evil twin");
        assert!(out.iter().any(|a| matches!(a, NetAction::JupeServer { name, .. } if name == "rogue.example")), "jupe introduced: {out:?}");
        // A bare name (no dot) isn't a server — syntax refused.
        assert!(os(&mut e, "000AAAAAS", "JUPE notaserver").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Syntax"))), "needs a server name");

        // It's re-introduced at burst.
        assert!(e.startup_actions().iter().any(|a| matches!(a, NetAction::JupeServer { name, .. } if name == "rogue.example")), "re-asserted at burst");
        // LIST shows it.
        assert!(os(&mut e, "000AAAAAS", "JUPE LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("rogue.example"))), "listed");

        // DEL squits the fake server.
        assert!(os(&mut e, "000AAAAAS", "JUPE DEL rogue.example").iter().any(|a| matches!(a, NetAction::Squit { .. })), "squit on lift");
        assert!(!e.startup_actions().iter().any(|a| matches!(a, NetAction::JupeServer { .. })), "gone after DEL");
    }

    // External-account mode: IRC can log in against pushed-in accounts but can't
    // register or change identity; channels (echo's own domain) still work.
    #[test]
    fn external_accounts_delegate_identity() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-external.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        // Simulates an account pushed in by the external authority (the website).
        db.register("alice", "password1", None).unwrap();
        db.set_external_accounts(true);
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let has = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });

        // Login against the pushed-in account still works.
        let out = ns(&mut e, "000AAAAAB", "IDENTIFY password1");
        assert!(out.iter().any(|a| matches!(a, NetAction::Metadata { key, value, .. } if key == "accountname" && value == "alice")), "identify works: {out:?}");

        // But creating or changing identity from IRC is refused.
        assert!(has(&ns(&mut e, "000AAAAAB", "REGISTER newpass a@b.c"), "website"), "register refused");
        assert!(has(&ns(&mut e, "000AAAAAB", "SET PASSWORD hunter2"), "website"), "set password refused");
        assert!(has(&ns(&mut e, "000AAAAAB", "DROP password1"), "website"), "drop refused");
        // The IRCv3 registration relay is refused too.
        let reply = crate::proto::RegReply::NickServ { agent: "42SAAAAAA".into(), uid: "000AAAAAB".into(), nick: "bob".into() };
        assert!(e.pre_register_check("bob", &reply).is_some_and(|r| r.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("website")))), "relay refused");

        // Channels are echo's own domain — still registerable.
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: true });
        assert!(has(&cs(&mut e, "000AAAAAB", "REGISTER #room"), "now registered"), "channels still work");
    }

    // OperServ DEFCON: each level tightens the network — announce on change, freeze
    // channel then all registrations, cap sessions, and lock out new connections.
    #[test]
    fn operserv_defcon_levels() {
        use echo_chanserv::ChanServ;
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-defcon.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let has = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));
        let killed = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::KillUser { .. }));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into(), ip: "1.1.1.1".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAS".into(), channel: "#room".into(), op: true });

        // Setting a level announces it network-wide.
        let out = os(&mut e, "000AAAAAS", "DEFCON 4");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "$*" && text.contains("DEFCON 4"))), "announced: {out:?}");
        // DEFCON 4 freezes channel registrations but not account ones.
        assert!(has(&cs(&mut e, "000AAAAAS", "REGISTER #room"), "frozen"), "chan reg frozen at 4");
        let reply = crate::proto::RegReply::NickServ { agent: "42SAAAAAA".into(), uid: "000AAAAAX".into(), nick: "newbie".into() };
        assert!(e.pre_register_check("newbie", &reply).is_none(), "account reg still ok at 4");

        // DEFCON 3 freezes account registrations too.
        os(&mut e, "000AAAAAS", "DEFCON 3");
        assert!(e.pre_register_check("newbie", &reply).is_some_and(|r| r.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("frozen")))), "account reg frozen at 3");

        // DEFCON 2 caps everyone to one session per host.
        os(&mut e, "000AAAAAS", "DEFCON 2");
        assert!(!killed(&e.handle(NetEvent::UserConnect { uid: "000AAAAA1".into(), nick: "a".into(), host: "h".into(), ip: "2.2.2.2".into() })), "first from an IP ok");
        assert!(killed(&e.handle(NetEvent::UserConnect { uid: "000AAAAA2".into(), nick: "b".into(), host: "h".into(), ip: "2.2.2.2".into() })), "second from the same IP capped");

        // DEFCON 1 turns away every new connection.
        os(&mut e, "000AAAAAS", "DEFCON 1");
        assert!(killed(&e.handle(NetEvent::UserConnect { uid: "000AAAAA3".into(), nick: "c".into(), host: "h".into(), ip: "3.3.3.3".into() })), "lockdown rejects new connections");

        // Back to 5: normal again.
        os(&mut e, "000AAAAAS", "DEFCON 5");
        assert!(!killed(&e.handle(NetEvent::UserConnect { uid: "000AAAAA4".into(), nick: "d".into(), host: "h".into(), ip: "4.4.4.4".into() })), "connections fine at 5");
        assert!(has(&cs(&mut e, "000AAAAAS", "REGISTER #room"), "now registered"), "chan reg works at 5");
    }

    // OperServ session limiting: the connection that puts an IP over its limit is
    // killed; SESSION inspects counts; EXCEPTION raises the allowance per IP-mask.
    #[test]
    fn operserv_session_limit_and_exceptions() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-ossession.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        e.set_session_limit(Some(2));
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let conn = |e: &mut Engine, uid: &str, ip: &str| e.handle(NetEvent::UserConnect { uid: uid.into(), nick: uid.into(), host: "h".into(), ip: ip.into() });
        let killed = |out: &[NetAction], who: &str| out.iter().any(|a| matches!(a, NetAction::KillUser { uid, .. } if uid == who));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into(), ip: "9.9.9.9".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        // Two sessions from one IP are fine; the third is killed.
        assert!(!killed(&conn(&mut e, "000AAAAA1", "5.5.5.5"), "000AAAAA1"), "1st ok");
        assert!(!killed(&conn(&mut e, "000AAAAA2", "5.5.5.5"), "000AAAAA2"), "2nd ok");
        assert!(killed(&conn(&mut e, "000AAAAA3", "5.5.5.5"), "000AAAAA3"), "3rd over the limit is killed");
        // A different IP is unaffected.
        assert!(!killed(&conn(&mut e, "000AAAAA4", "6.6.6.6"), "000AAAAA4"), "other IP fine");

        // SESSION VIEW reports the live count.
        assert!(os(&mut e, "000AAAAAS", "SESSION VIEW 5.5.5.5").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("3"))), "view count");

        // An unlimited exception lets more sessions through from that IP.
        os(&mut e, "000AAAAAS", "EXCEPTION ADD 5.5.5.5 0 nat gateway");
        assert!(!killed(&conn(&mut e, "000AAAAA5", "5.5.5.5"), "000AAAAA5"), "exception lifts the limit");
        assert!(os(&mut e, "000AAAAAS", "EXCEPTION LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("5.5.5.5") && text.contains("unlimited"))), "listed");

        // A quit frees a slot.
        e.handle(NetEvent::Quit { uid: "000AAAAA4".into(), reason: String::new() });
        assert!(os(&mut e, "000AAAAAS", "SESSION VIEW 6.6.6.6").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("0"))), "slot freed on quit");
    }

    // OperServ OPER: a runtime grant actually confers privileges (merged with the
    // config opers), and revoking removes them. Admin-only.
    #[test]
    fn operserv_oper_grants_runtime_privileges() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osoper.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Root));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let denied = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied")));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAL".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAL".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        // Before the grant, alice is a plain user — OperServ shuts her out.
        assert!(denied(&os(&mut e, "000AAAAAL", "STATS")), "alice not an oper yet");

        // Grant alice admin at runtime; now the same command works.
        os(&mut e, "000AAAAAS", "OPER ADD alice admin");
        assert!(!denied(&os(&mut e, "000AAAAAL", "STATS")), "alice is an oper after the grant");
        assert!(os(&mut e, "000AAAAAS", "OPER LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("alice"))), "listed");

        // Revoke; alice loses access again.
        os(&mut e, "000AAAAAS", "OPER DEL alice");
        assert!(denied(&os(&mut e, "000AAAAAL", "STATS")), "alice lost access after revoke");

        // A config oper is not a runtime oper, so it can't be DEL'd here.
        assert!(os(&mut e, "000AAAAAS", "OPER DEL staff").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("isn't a runtime operator"))), "config oper untouched");
    }

    // A temporary OPER grant confers privileges until it lazily expires.
    #[test]
    fn operserv_oper_grant_can_expire() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-opertmp.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("temp", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Root));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let denied = |out: &[NetAction]| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied")));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAP".into(), nick: "temp".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAP".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        // A one-hour admin grant is active now...
        os(&mut e, "000AAAAAS", "OPER ADD temp admin +1h");
        assert!(!denied(&os(&mut e, "000AAAAAP", "STATS")), "active while granted");
        assert!(os(&mut e, "000AAAAAS", "OPER LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("temp") && text.contains("temporary"))), "listed as temporary");

        // ...but not after its window passes.
        e.now_override = Some(10_000_000_000);
        assert!(denied(&os(&mut e, "000AAAAAP", "STATS")), "expired grant confers nothing");
    }

    // HelpServ: a user opens a ticket; it queues, flows into the audit trail
    // (LOGSEARCH), and operators TAKE / CLOSE it. Reviewing is oper-only.
    #[test]
    fn helpserv_ticket_flow() {
        use echo_helpserv::HelpServ;
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-helpserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
                Box::new(HelpServ { uid: "42SAAAAAN".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin).with(echo_api::Priv::Auspex));
        e.set_opers(opers);
        let hs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAN".into(), text: t.into() });
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let has = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAU".into(), nick: "newbie".into(), host: "h".into(), ip: "0.0.0.0".into() });

        // A user asks for help; it queues and is searchable via the audit trail.
        assert!(has(&hs(&mut e, "000AAAAAU", "REQUEST how do I register a channel"), "in the queue"), "request accepted");
        assert!(has(&os(&mut e, "000AAAAAS", "LOGSEARCH register a channel"), "register a channel"), "searchable via LOGSEARCH");

        // Operator works the queue: NEXT claims the oldest, then CLOSE.
        assert!(has(&hs(&mut e, "000AAAAAS", "LIST"), "newbie"), "oper sees the queue");
        assert!(has(&hs(&mut e, "000AAAAAS", "NEXT"), "You took ticket \x02#0\x02"), "next claims oldest");
        assert!(has(&hs(&mut e, "000AAAAAS", "VIEW 0"), "register a channel"), "view detail");
        assert!(has(&hs(&mut e, "000AAAAAS", "CLOSE 0"), "closed"), "close");
        assert!(!has(&hs(&mut e, "000AAAAAS", "LIST"), "newbie"), "closed drops off the open list");

        // Non-opers can't work the queue; and filing is rate-limited.
        assert!(has(&hs(&mut e, "000AAAAAU", "LIST"), "Access denied"), "queue is oper-only");
        assert!(has(&hs(&mut e, "000AAAAAU", "REQUEST again please"), "wait a moment"), "rate-limited");
    }

    // ReportServ: any user files an abuse report; it lands in the queue AND flows
    // through the audit trail so OperServ LOGSEARCH finds it. Reviewing is oper-only.
    #[test]
    fn reportserv_files_and_is_searchable() {
        use echo_operserv::OperServ;
        use echo_reportserv::ReportServ;
        let path = std::env::temp_dir().join("echo-reportserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
                Box::new(ReportServ { uid: "42SAAAAAK".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin).with(echo_api::Priv::Auspex));
        e.set_opers(opers);
        let rs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAK".into(), text: t.into() });
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let has = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAU".into(), nick: "victim".into(), host: "h".into(), ip: "0.0.0.0".into() });

        // An ordinary (unidentified) user files a report.
        assert!(has(&rs(&mut e, "000AAAAAU", "REPORT spammer flooding the lobby"), "has been sent"), "report accepted");
        // The report is in the queue and — via the audit trail — searchable.
        assert!(has(&rs(&mut e, "000AAAAAS", "LIST"), "spammer"), "oper sees the queue");
        assert!(has(&os(&mut e, "000AAAAAS", "LOGSEARCH flooding"), "flooding"), "report searchable via LOGSEARCH");

        // Detail, then close.
        assert!(has(&rs(&mut e, "000AAAAAS", "VIEW 0"), "flooding the lobby"), "view detail");
        assert!(has(&rs(&mut e, "000AAAAAS", "CLOSE 0"), "closed"), "close");
        assert!(!has(&rs(&mut e, "000AAAAAS", "LIST"), "spammer"), "closed reports drop off the open list");

        // Non-opers can't review; and filing is rate-limited.
        assert!(has(&rs(&mut e, "000AAAAAU", "LIST"), "Access denied"), "review is oper-only");
        assert!(has(&rs(&mut e, "000AAAAAU", "REPORT someone again"), "wait a moment"), "rate-limited");
    }

    // InfoServ bulletins over the shared news store: public bulletins greet
    // everyone on connect, oper bulletins greet an operator on login.
    #[test]
    fn infoserv_bulletins_public_and_oper() {
        use echo_infoserv::InfoServ;
        let path = std::env::temp_dir().join("echo-infoserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("boss", "password1", None).unwrap();
        db.register("plain", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(InfoServ { uid: "42SAAAAAJ".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        e.set_irc_out(tx);
        let is = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAJ".into(), text: t.into() });
        let has = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        is(&mut e, "000AAAAAS", "POST Welcome to the network");
        is(&mut e, "000AAAAAS", "OPOST Staff meeting at 5");

        // A new user is greeted with the public bulletin on connect, not the oper one.
        let out = e.handle(NetEvent::UserConnect { uid: "000AAAAAP".into(), nick: "plain".into(), host: "h".into() , ip: "0.0.0.0".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "000AAAAAP" && text.contains("Welcome to the network"))), "public bulletin on connect: {out:?}");
        assert!(!has(&out, "Staff meeting"), "a plain user doesn't get oper bulletins");

        // An operator logging in is shown the oper bulletin (over the outbound path).
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into() , ip: "0.0.0.0".into() });
        while rx.try_recv().is_ok() {} // drain the connect's public bulletin
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        let mut oper_bulletin = false;
        while let Ok(a) = rx.try_recv() {
            if let NetAction::Notice { to, text, .. } = a {
                if to == "000AAAAAB" && text.contains("Staff meeting at 5") {
                    oper_bulletin = true;
                }
            }
        }
        assert!(oper_bulletin, "oper bulletin shown to an operator on login");

        // LIST shows the public one (to anyone); DEL removes it so a later connect is quiet.
        assert!(has(&is(&mut e, "000AAAAAP", "LIST"), "Welcome to the network"), "anyone can list public bulletins");
        is(&mut e, "000AAAAAS", "DEL 1");
        let out = e.handle(NetEvent::UserConnect { uid: "000AAAAAQ".into(), nick: "late".into(), host: "h".into() , ip: "0.0.0.0".into() });
        assert!(!has(&out, "Welcome to the network"), "bulletin gone after DEL");

        // A non-admin can't post.
        assert!(has(&is(&mut e, "000AAAAAP", "POST sneaky"), "Access denied"), "non-admin refused");
    }

    // OperServ INFO staff notes: an admin annotates an account/channel; the note
    // shows in that service's INFO to opers only, never to the account owner.
    #[test]
    fn operserv_info_staff_notes() {
        use echo_chanserv::ChanServ;
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osinfo.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        db.register("alice", "password1", None).unwrap();
        db.register_channel("#room", "staff").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin).with(echo_api::Priv::Auspex));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });
        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let has = |out: &[NetAction], needle: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)));

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAL".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAL".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });

        // Admin attaches a note; it shows in NickServ INFO to the oper.
        os(&mut e, "000AAAAAS", "INFO ADD alice known troublemaker");
        assert!(has(&ns(&mut e, "000AAAAAS", "INFO alice"), "known troublemaker"), "note shown to oper in NS INFO");
        assert!(has(&os(&mut e, "000AAAAAS", "INFO alice"), "known troublemaker"), "note shown via OperServ INFO");
        // The account's own owner never sees the staff note.
        assert!(!has(&ns(&mut e, "000AAAAAL", "INFO alice"), "Staff note"), "owner doesn't see the note");

        // Channel notes show in ChanServ INFO to the oper.
        os(&mut e, "000AAAAAS", "INFO ADD #room watch for drama");
        assert!(has(&cs(&mut e, "000AAAAAS", "INFO #room"), "watch for drama"), "channel note in CS INFO");

        // DEL clears it.
        os(&mut e, "000AAAAAS", "INFO DEL alice");
        assert!(!has(&ns(&mut e, "000AAAAAS", "INFO alice"), "Staff note"), "note cleared");

        // A non-admin can't set notes.
        assert!(has(&os(&mut e, "000AAAAAL", "INFO ADD staff x"), "Access denied"), "non-admin refused");
    }

    // OperServ SVSNICK / SVSJOIN: force a user's nick or channel join, admin-gated.
    #[test]
    fn operserv_svs_forces_nick_and_join() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-ossvs.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAT".into(), nick: "target".into(), host: "h".into() , ip: "0.0.0.0".into() });

        // SVSNICK forces the rename.
        let out = os(&mut e, "000AAAAAS", "SVSNICK target Renamed");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceNick { uid, nick } if uid == "000AAAAAT" && nick == "Renamed")), "svsnick issued: {out:?}");
        // The ircd echoes the rename; once tracked, SVSJOIN resolves the new nick.
        e.handle(NetEvent::NickChange { uid: "000AAAAAT".into(), nick: "Renamed".into() });
        let out = os(&mut e, "000AAAAAS", "SVSJOIN Renamed #room");
        assert!(out.iter().any(|a| matches!(a, NetAction::ForceJoin { uid, channel, .. } if uid == "000AAAAAT" && channel == "#room")), "svsjoin issued: {out:?}");

        // An unknown target is reported, not forced.
        assert!(os(&mut e, "000AAAAAS", "SVSNICK ghost x").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("no \x02ghost\x02"))), "unknown target");
    }

    // OperServ IGNORE: an admin silences a user, whose service commands are then
    // dropped; DEL restores them; opers are never silenced.
    #[test]
    fn operserv_ignore_silences_and_restores() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-osignore.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("staff", "password1", None).unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(OperServ { uid: "42SAAAAAH".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        let os = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAH".into(), text: t.into() });
        let ns = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: t.into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAS".into(), nick: "staff".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAS".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAM".into(), nick: "menace".into(), host: "bad.host".into() , ip: "0.0.0.0".into() });

        // Before the ignore, a NickServ command gets a reply.
        assert!(!ns(&mut e, "000AAAAAM", "INFO").is_empty(), "responds before ignore");

        // Ignore by host mask, then the same command yields nothing at all.
        os(&mut e, "000AAAAAS", "IGNORE ADD *!*@bad.host flooding");
        assert!(ns(&mut e, "000AAAAAM", "INFO").is_empty(), "ignored user's command is dropped");
        assert!(os(&mut e, "000AAAAAM", "HELP").is_empty(), "ignored across every service");

        // The operator is never silenced by an ignore against them.
        os(&mut e, "000AAAAAS", "IGNORE ADD *!*@h staffignore");
        assert!(!ns(&mut e, "000AAAAAS", "INFO").is_empty(), "an oper can't be ignored");

        // DEL restores the menace.
        os(&mut e, "000AAAAAS", "IGNORE DEL *!*@bad.host");
        assert!(!ns(&mut e, "000AAAAAM", "INFO").is_empty(), "responds again after DEL");

        // A non-admin (no longer ignored) can't manage the list — it's refused.
        assert!(os(&mut e, "000AAAAAM", "IGNORE LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "non-admin refused");
    }

    // NOEXPIRE is oper-only.
    #[test]
    fn noexpire_command_is_oper_gated() {
        let mut e = engine_with("noexp", "alice", "sesame");
        e.db.register("mallory", "password1", None).unwrap();
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        // alice is not an oper: refused, and the flag is untouched.
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "NOEXPIRE mallory ON".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Access denied"))), "non-oper refused: {out:?}");
    }

    // ChanFix: op-time is scored from live state, and CHANFIX reops the trusted
    // regulars of an opless, unregistered channel; it defers to ChanServ.
    #[test]
    fn chanfix_scores_and_fixes_opless_channels() {
        use echo_chanfix::ChanFix;
        let path = std::env::temp_dir().join("echo-chanfix.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        for a in ["alice", "bob", "staff"] {
            db.register(a, "password1", None).unwrap();
        }
        db.register_channel("#owned", "staff").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanFix { uid: "42SAAAAAM".into() }),
            ],
            db,
        );
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("staff".to_string(), Privs::default().with(echo_api::Priv::Auspex));
        e.set_opers(opers);
        let cf = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAM".into(), text: t.into() });
        let has = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));
        let opped = |out: &[NetAction], who: &str| out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == &format!("+o {who}")));

        for (uid, nick) in [("000AAAAAA", "alice"), ("000AAAAAB", "bob"), ("000AAAAAS", "staff")] {
            e.handle(NetEvent::UserConnect { uid: uid.into(), nick: nick.into(), host: "h".into(), ip: "0.0.0.0".into() });
            e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        }
        // alice and bob hold ops in an unregistered #lobby; score their op-time.
        e.handle(NetEvent::Join { uid: "000AAAAAA".into(), channel: "#lobby".into(), op: true });
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#lobby".into(), op: true });
        for _ in 0..15 {
            e.chanfix_tick();
        }

        // SCORES shows the accumulated standings.
        assert!(has(&cf(&mut e, "000AAAAAS", "SCORES #lobby"), "alice"), "scores recorded");
        // A non-oper can't use ChanFix at all.
        assert!(has(&cf(&mut e, "000AAAAAA", "SCORES #lobby"), "Access denied"), "oper-only");

        // The channel goes opless; CHANFIX reops the trusted regulars still present.
        e.handle(NetEvent::ChannelOp { channel: "#lobby".into(), uid: "000AAAAAA".into(), op: false });
        e.handle(NetEvent::ChannelOp { channel: "#lobby".into(), uid: "000AAAAAB".into(), op: false });
        let out = cf(&mut e, "000AAAAAS", "CHANFIX #lobby");
        assert!(opped(&out, "000AAAAAA") && opped(&out, "000AAAAAB"), "reopped the regulars: {out:?}");

        // It won't touch a ChanServ-registered channel.
        assert!(has(&cf(&mut e, "000AAAAAS", "CHANFIX #owned"), "registered"), "defers to ChanServ");
    }

    // GroupServ interconnection: a channel grants access to a !group, and every
    // group member holding the c (channel-access) flag inherits it (auto-op on join).
    #[test]
    fn groupserv_grants_channel_access() {
        use echo_chanserv::ChanServ;
        use echo_groupserv::GroupServ;
        let path = std::env::temp_dir().join("echo-groupserv.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        for a in ["alice", "bob", "carol"] {
            db.register(a, "password1", None).unwrap();
        }
        db.register_channel("#room", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
                Box::new(GroupServ { uid: "42SAAAAAL".into() }),
            ],
            db,
        );
        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let gs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAL".into(), text: t.into() });
        let has = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));
        let opped = |out: &[NetAction], who: &str| out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == &format!("+o {who}")));

        for (uid, nick) in [("000AAAAAA", "alice"), ("000AAAAAB", "bob"), ("000AAAAAC", "carol")] {
            e.handle(NetEvent::UserConnect { uid: uid.into(), nick: nick.into(), host: "h".into(), ip: "0.0.0.0".into() });
            e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        }

        // alice makes a group, adds bob, and grants the group op access on #room.
        assert!(has(&gs(&mut e, "000AAAAAA", "REGISTER !team"), "registered"), "group registered");
        assert!(has(&gs(&mut e, "000AAAAAA", "ADD !team bob"), "Added"), "bob added");
        assert!(has(&cs(&mut e, "000AAAAAA", "FLAGS #room !team +o"), "now holds"), "group granted channel op");

        // A member without the c (channel-access) flag does NOT inherit; +c makes
        // bob auto-opped on join. carol (not in the group) never is.
        assert!(!opped(&e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: false }), "000AAAAAB"), "no c flag, no access");
        gs(&mut e, "000AAAAAA", "FLAGS !team bob +c");
        assert!(opped(&e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: false }), "000AAAAAB"), "c flag -> auto-opped");
        assert!(!opped(&e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#room".into(), op: false }), "000AAAAAC"), "non-member not opped");

        // Removing bob from the group revokes his inherited channel access.
        gs(&mut e, "000AAAAAA", "DEL !team bob");
        assert_eq!(e.db.channel_join_mode("#room", "bob"), None, "access gone once out of the group");

        // Managing the group needs the founder or the f flag.
        assert!(has(&gs(&mut e, "000AAAAAC", "ADD !team carol"), "founder or the \x02f\x02 flag"), "outsider can't manage");
        gs(&mut e, "000AAAAAA", "FLAGS !team carol +f");
        assert!(has(&gs(&mut e, "000AAAAAC", "ADD !team bob"), "Added"), "carol with f can now manage");
    }

    // ChanServ FLAGS: granular access grants flow through the shared resolver, so
    // a flag-granted +o gets auto-op like a legacy op entry; changing needs the
    // founder or the 'a' flag.
    #[test]
    fn chanserv_flags_grant_access() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-csflags.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        for a in ["alice", "bob", "carol"] {
            db.register(a, "password1", None).unwrap();
        }
        db.register_channel("#room", "alice").unwrap();
        let mut e = Engine::new(
            vec![
                Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
                Box::new(ChanServ { uid: "42SAAAAAB".into() }),
            ],
            db,
        );
        let cs = |e: &mut Engine, uid: &str, t: &str| e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAB".into(), text: t.into() });
        let has = |out: &[NetAction], n: &str| out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(n)));

        for (uid, nick) in [("000AAAAAA", "alice"), ("000AAAAAB", "bob"), ("000AAAAAC", "carol")] {
            e.handle(NetEvent::UserConnect { uid: uid.into(), nick: nick.into(), host: "h".into(), ip: "0.0.0.0".into() });
            e.handle(NetEvent::Privmsg { from: uid.into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
        }

        // Founder grants bob auto-op + topic via flags.
        assert!(has(&cs(&mut e, "000AAAAAA", "FLAGS #room bob +ot"), "now holds"), "flags set");
        // The grant confers real access: bob is auto-opped on join.
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#room" && modes.starts_with("+o"))), "flag-op is auto-opped: {out:?}");

        // Change to voice-only; now the join mode is +v.
        cs(&mut e, "000AAAAAA", "FLAGS #room bob -ot+v");
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#room2".into(), op: false });
        assert!(!out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes.starts_with("+o"))), "no longer auto-opped elsewhere");
        assert_eq!(e.db.channel("#room").unwrap().join_mode("bob"), Some("+v"), "bob resolves to +v");

        // A non-founder without the 'a' flag can't change access.
        assert!(has(&cs(&mut e, "000AAAAAC", "FLAGS #room bob +o"), "founder or the \x02a\x02 flag"), "carol refused");
        // Grant carol the 'a' flag; now she can.
        cs(&mut e, "000AAAAAA", "FLAGS #room carol +a");
        assert!(has(&cs(&mut e, "000AAAAAC", "FLAGS #room bob +i"), "now holds"), "carol with 'a' can change flags");
        // ...but a non-founder delegate may NOT grant the founder flag (escalation).
        assert!(has(&cs(&mut e, "000AAAAAC", "FLAGS #room bob +f"), "Only the founder"), "carol can't grant +f");
        assert!(!e.db.channel("#room").unwrap().access.iter().any(|a| a.account.eq_ignore_ascii_case("bob") && a.level.contains('f')), "bob did not get founder");
        // The founder still can.
        assert!(has(&cs(&mut e, "000AAAAAA", "FLAGS #room bob +f"), "now holds"), "founder can grant +f");

        // An invalid flag letter is rejected.
        assert!(has(&cs(&mut e, "000AAAAAA", "FLAGS #room bob +z"), "isn't a valid flag"), "bad flag rejected");
    }

    // ChanServ moderation: an op can op/kick/ban users; a non-op is refused.
    #[test]
    fn chanserv_moderation() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-cs-mod.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#m", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);

        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        // Founder alice identifies; target bob connects with a known host.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "1.2.3.4".into() , ip: "0.0.0.0".into() });

        // OP a user by nick.
        let out = to_cs(&mut e, "000AAAAAB", "OP #m bob");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#m" && modes == "+o 000AAAAAC")), "{out:?}");

        // KICK a user by nick, with a reason.
        let out = to_cs(&mut e, "000AAAAAB", "KICK #m bob rude");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { channel, uid, reason, .. } if channel == "#m" && uid == "000AAAAAC" && reason.starts_with("rude"))), "{out:?}");

        // BAN sets +b *!*@host and kicks.
        let out = to_cs(&mut e, "000AAAAAB", "BAN #m bob spam");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#m" && modes == "+b *!*@1.2.3.4")), "{out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAC")), "{out:?}");

        // UNBAN clears it.
        let out = to_cs(&mut e, "000AAAAAB", "UNBAN #m bob");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#m" && modes == "-b *!*@1.2.3.4")), "{out:?}");

        // A user with no access is refused.
        e.handle(NetEvent::UserConnect { uid: "000AAAAAD".into(), nick: "carol".into(), host: "h2".into() , ip: "0.0.0.0".into() });
        assert!(to_cs(&mut e, "000AAAAAD", "KICK #m alice").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("operator access"))));
    }

    // ChanServ topic, invite, auto-kick (with enforcement on join), list and status.
    #[test]
    fn chanserv_topic_invite_akick() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-cs-tia.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "bad.host".into() , ip: "0.0.0.0".into() });

        // TOPIC and INVITE are sourced from ChanServ.
        let out = to_cs(&mut e, "000AAAAAB", "TOPIC #c hello there");
        assert!(out.iter().any(|a| matches!(a, NetAction::Topic { channel, topic, .. } if channel == "#c" && topic == "hello there")), "{out:?}");
        let out = to_cs(&mut e, "000AAAAAB", "INVITE #c bob");
        assert!(out.iter().any(|a| matches!(a, NetAction::Invite { uid, channel, .. } if uid == "000AAAAAC" && channel == "#c")), "{out:?}");

        // LIST and STATUS.
        assert!(to_cs(&mut e, "000AAAAAB", "LIST").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("#c"))));
        assert!(to_cs(&mut e, "000AAAAAB", "STATUS #c").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("founder"))));

        // AKICK a mask, then a matching join is banned and kicked.
        assert!(to_cs(&mut e, "000AAAAAB", "AKICK #c ADD *!*@bad.host begone").iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("Added"))));
        let out = e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#c".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#c" && modes == "+b *!*@bad.host")), "{out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { channel, uid, reason, .. } if channel == "#c" && uid == "000AAAAAC" && reason.starts_with("begone"))), "{out:?}");

        // The founder joining is never auto-kicked (they get +qo instead).
        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes.contains('o'))), "{out:?}");
    }

    // A user who joins clean then switches to a nick matching the akick list is
    // banned and kicked, just as if they'd joined under that nick.
    #[test]
    fn akick_enforced_on_nick_change() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-cs-akick-nick.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        to_cs(&mut e, "000AAAAAB", "AKICK #c ADD evil!*@* begone");

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "clean.host".into(), ip: "0.0.0.0".into() });
        let out = e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#c".into(), op: false });
        assert!(!out.iter().any(|a| matches!(a, NetAction::Kick { .. })), "clean nick not kicked: {out:?}");

        let out = e.handle(NetEvent::NickChange { uid: "000AAAAAC".into(), nick: "evil".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#c" && modes == "+b evil!*@*")), "{out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { channel, uid, reason, .. } if channel == "#c" && uid == "000AAAAAC" && reason.starts_with("begone"))), "{out:?}");
    }

    // Being added to / removed from a channel's access list notifies the affected
    // user: a memo while they're offline, a direct notice while they're online.
    #[test]
    fn access_change_notifies_the_affected_user() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-cs-access-notify.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "hunter2", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        to_cs(&mut e, "000AAAAAB", "ACCESS #c ADD bob op");
        assert_eq!(e.db.unread_memos("bob"), 1, "offline user gets a memo");

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h2".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAC".into(), to: "42SAAAAAA".into(), text: "IDENTIFY hunter2".into() });
        let out = to_cs(&mut e, "000AAAAAB", "ACCESS #c DEL bob");
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "000AAAAAC" && text.contains("removed your access"))), "online user noticed: {out:?}");
        assert_eq!(e.db.unread_memos("bob"), 1, "no extra memo when online");
    }

    // Logging out reverses a services vhost, restoring the connect-time host (the
    // cloak we were given at UserConnect), not the real host.
    #[test]
    fn logout_restores_the_connect_host_over_a_vhost() {
        let path = std::env::temp_dir().join("echo-logout-vhost.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.set_vhost("alice", "cool.vhost", "admin", None).unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "cloak.host".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "LOGOUT".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::SetHost { uid, host } if uid == "000AAAAAB" && host == "cloak.host")), "logout restores the cloak: {out:?}");
    }

    // SECUREVOICES strips voice from a user with no channel access, but leaves an
    // access holder's voice alone.
    #[test]
    fn securevoices_strips_voice_from_non_access_users() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-securevoices.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: "SET #c SECUREVOICES ON".into() });

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "h".into(), ip: "0.0.0.0".into() });
        let out = e.handle(NetEvent::ChannelVoice { channel: "#c".into(), uid: "000AAAAAC".into(), voice: true });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#c" && modes == "-v 000AAAAAC")), "non-access voice stripped: {out:?}");

        let out = e.handle(NetEvent::ChannelVoice { channel: "#c".into(), uid: "000AAAAAB".into(), voice: true });
        assert!(!out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes.starts_with("-v"))), "founder keeps voice: {out:?}");
    }

    // SIGNKICK ON signs every CS KICK; LEVEL exempts kickers with op access.
    #[test]
    fn signkick_level_exempts_ops() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-signkick-level.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::UserConnect { uid: "000AAAAAE".into(), nick: "eve".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Join { uid: "000AAAAAE".into(), channel: "#c".into(), op: false });

        to_cs(&mut e, "000AAAAAB", "SET #c SIGNKICK ON");
        let out = to_cs(&mut e, "000AAAAAB", "KICK #c eve");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { reason, .. } if reason.contains("requested by alice"))), "signed on ON: {out:?}");

        e.handle(NetEvent::Join { uid: "000AAAAAE".into(), channel: "#c".into(), op: false });
        to_cs(&mut e, "000AAAAAB", "SET #c SIGNKICK LEVEL");
        let out = to_cs(&mut e, "000AAAAAB", "KICK #c eve");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { .. })), "kick still happens: {out:?}");
        assert!(!out.iter().any(|a| matches!(a, NetAction::Kick { reason, .. } if reason.contains("requested by"))), "op founder exempt on LEVEL: {out:?}");
    }

    // Invite-only registration: a new account starts pending, and a confirmed
    // member's VOUCH activates it.
    #[test]
    fn vouch_confirms_a_pending_account() {
        let path = std::env::temp_dir().join("echo-vouch.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap(); // verified (vouch off)
        db.set_registration_vouch(true);
        db.register("bob", "pw", None).unwrap(); // invite-only -> pending
        assert!(!db.is_verified("bob"), "bob starts pending under vouch mode");
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "VOUCH bob".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains("vouched"))), "vouch confirmation: {out:?}");
        assert!(e.db.is_verified("bob"), "bob is now active after the vouch");
    }

    // FORBID NICK also Q-lines the nick so it can't be used, and the Q-line is
    // removed on unforbid and re-asserted on a relink.
    #[test]
    fn forbid_nick_qlines_it() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-forbid-qline.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let os = OperServ { uid: "42SAAAAAH".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(os)], db);
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("alice".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        let to_os = |e: &mut Engine, text: &str| e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAH".into(), text: text.into() });

        let out = to_os(&mut e, "FORBID ADD NICK badname reserved");
        assert!(out.iter().any(|a| matches!(a, NetAction::AddLine { kind, mask, .. } if kind == "Q" && mask == "badname")), "qline set: {out:?}");

        let burst = e.startup_actions();
        assert!(burst.iter().any(|a| matches!(a, NetAction::AddLine { kind, mask, .. } if kind == "Q" && mask == "badname")), "qline re-asserted on relink: {burst:?}");

        let out = to_os(&mut e, "FORBID DEL NICK badname");
        assert!(out.iter().any(|a| matches!(a, NetAction::DelLine { kind, mask } if kind == "Q" && mask == "badname")), "qline removed: {out:?}");
    }

    // OperServ PROTECT ALL enables nick protection on accounts that had it off
    // (e.g. carried over from a migration).
    #[test]
    fn operserv_protect_all_enables_protection() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-protectall.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        db.set_account_kill("bob", false).unwrap(); // bob has protection OFF
        assert!(!db.account_wants_protect("bob"));
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let os = OperServ { uid: "42SAAAAAH".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(os)], db);
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("alice".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAH".into(), text: "PROTECT ALL".into() });
        assert!(e.db.account_wants_protect("bob"), "bob is now protected after PROTECT ALL");
    }

    // OperServ SETALL applies a channel setting to every registered channel.
    #[test]
    fn operserv_setall_applies_to_every_channel() {
        use echo_operserv::OperServ;
        let path = std::env::temp_dir().join("echo-setall.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#one", "alice").unwrap();
        db.register_channel("#two", "alice").unwrap();
        assert!(!db.channel("#one").unwrap().settings.secureops);
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let os = OperServ { uid: "42SAAAAAH".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(os)], db);
        e.set_sid("42S".into());
        let mut opers = std::collections::HashMap::new();
        opers.insert("alice".to_string(), Privs::default().with(echo_api::Priv::Admin));
        e.set_opers(opers);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAH".into(), text: "SETALL SECUREOPS ON".into() });
        assert!(e.db.channel("#one").unwrap().settings.secureops, "#one now has secureops");
        assert!(e.db.channel("#two").unwrap().settings.secureops, "#two now has secureops");
    }

    // ChanServ SET: description and founder transfer, founder-gated.
    #[test]
    fn chanserv_set() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-cs-set.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("bob", "hunter2", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        let notice = |out: &[NetAction], needle: &str| {
            out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)))
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        // Description is stored and shows in INFO.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c DESC a friendly place"), "updated"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "INFO #c"), "a friendly place"));

        // URL is stored, shows in INFO, and clears when set empty.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c URL https://example.org/rules"), "updated"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "INFO #c"), "https://example.org/rules"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c URL"), "cleared"));
        assert!(!notice(&to_cs(&mut e, "000AAAAAB", "INFO #c"), "example.org"), "cleared URL no longer shows");

        // Contact email is stored, shows in INFO, and clears when set empty.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c EMAIL staff@example.org"), "updated"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "INFO #c"), "staff@example.org"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c EMAIL"), "cleared"));
        assert!(!notice(&to_cs(&mut e, "000AAAAAB", "INFO #c"), "staff@example.org"), "cleared email no longer shows");

        // Transfer to a non-account is refused.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c FOUNDER nobody"), "isn't a registered account"));

        // Transfer to bob works; alice is then no longer the founder.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c FOUNDER bob"), "transferred"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SET #c DESC nope"), "founder can change"));
    }

    // ChanServ entrymsg, enforce, getkey, seen, clone and the xop lists.
    #[test]
    fn chanserv_extended() {
        use echo_chanserv::ChanServ;
        let path = std::env::temp_dir().join("echo-cs-ext.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register("carol", "pw", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let cs = ChanServ { uid: "42SAAAAAB".into() };
        let mut e = Engine::new(vec![Box::new(ns), Box::new(cs)], db);
        let to_cs = |e: &mut Engine, from: &str, text: &str| {
            e.handle(NetEvent::Privmsg { from: from.into(), to: "42SAAAAAB".into(), text: text.into() })
        };
        let notice = |out: &[NetAction], needle: &str| {
            out.iter().any(|a| matches!(a, NetAction::Notice { text, .. } if text.contains(needle)))
        };
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "h1".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        // ENTRYMSG: set it, then a joining user is noticed it.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "ENTRYMSG #c welcome aboard"), "updated"));
        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "guest".into(), host: "h2".into() , ip: "0.0.0.0".into() });
        let out = e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#c".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "000AAAAAC" && text == "welcome aboard")), "{out:?}");

        // XOP: AOP add shows in the AOP list and grants op access.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "AOP #c ADD carol"), "Added"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "AOP #c LIST"), "carol"));

        // ENFORCE: alice (founder) present gets +qo, the akick-matching guest is kicked.
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#c".into(), op: false });
        to_cs(&mut e, "000AAAAAB", "AKICK #c ADD *!*@h2 out");
        let out = to_cs(&mut e, "000AAAAAB", "ENFORCE #c");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "+qo 000AAAAAB 000AAAAAB")), "{out:?}");
        assert!(out.iter().any(|a| matches!(a, NetAction::Kick { uid, .. } if uid == "000AAAAAC")), "{out:?}");
        // SYNC is an alias for ENFORCE — same re-apply of access modes.
        let out = to_cs(&mut e, "000AAAAAB", "SYNC #c");
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { modes, .. } if modes == "+qo 000AAAAAB 000AAAAAB")), "sync alias: {out:?}");

        // GETKEY: reflects a tracked key change.
        e.handle(NetEvent::ChannelKey { channel: "#c".into(), key: Some("s3cret".into()) });
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "GETKEY #c"), "s3cret"));

        // SEEN: an online user vs one who quit.
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SEEN alice"), "currently online"));
        e.handle(NetEvent::Quit { uid: "000AAAAAC".into(), reason: String::new() });
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "SEEN guest"), "last seen"));

        // CLONE: copy #c's settings (incl. the AOP) into a second owned channel.
        e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#d".into(), op: true });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: "REGISTER #d".into() });
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "CLONE #c #d"), "Copied"));
        assert!(notice(&to_cs(&mut e, "000AAAAAB", "AOP #d LIST"), "carol"));
    }

    // A registered channel (re)appearing re-asserts +r; an unregistered one does not.
    #[test]
    fn channel_create_reasserts_registered_mode() {
        let path = std::env::temp_dir().join("echo-chancreate.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register_channel("#reg", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);

        let out = e.handle(NetEvent::ChannelCreate { channel: "#reg".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#reg" && modes == "+r")), "registered channel regains +r: {out:?}");

        let out = e.handle(NetEvent::ChannelCreate { channel: "#other".into() });
        assert!(out.is_empty(), "unregistered channel is left alone: {out:?}");
    }

    // A channel's mode lock is applied on creation and enforced on violation.
    #[test]
    fn mode_lock_is_applied_and_enforced() {
        let path = std::env::temp_dir().join("echo-mlock-engine.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.register_channel("#lk", "alice").unwrap();
        db.set_mlock("#lk", "nt", "s").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);

        // Creation applies the full lock.
        let out = e.handle(NetEvent::ChannelCreate { channel: "#lk".into() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#lk" && modes == "+rnt-s")), "{out:?}");

        // Setting a locked-off mode is reverted.
        let out = e.handle(NetEvent::ChannelModeChange { channel: "#lk".into(), modes: "+s".into(), setter: String::new() });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#lk" && modes == "-s")), "{out:?}");

        // An unrelated mode change is left alone.
        assert!(e.handle(NetEvent::ChannelModeChange { channel: "#lk".into(), modes: "+m".into(), setter: String::new() }).is_empty());
    }

    // The founder is opped when they join their channel; others are not.
    #[test]
    fn founder_is_opped_on_join() {
        let path = std::env::temp_dir().join("echo-autoop.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("alice", "sesame", None).unwrap();
        db.register_channel("#x", "alice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "alice".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#x".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#x" && modes == "+qo 000AAAAAB 000AAAAAB")), "founder opped: {out:?}");

        e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "bob".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        assert!(e.handle(NetEvent::Join { uid: "000AAAAAC".into(), channel: "#x".into(), op: false }).is_empty(), "non-founder not opped");
    }

    // An access-list voice gets +v on join.
    #[test]
    fn access_voice_on_join() {
        let path = std::env::temp_dir().join("echo-access-join.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut db = Db::open(&path, "42S");
        db.scram_iterations = 4096;
        db.register("carol", "sesame", None).unwrap();
        db.register_channel("#y", "boss").unwrap();
        db.access_add("#y", "carol", "voice").unwrap();
        let ns = NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 };
        let mut e = Engine::new(vec![Box::new(ns)], db);
        e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "carol".into(), host: "host.example".into() , ip: "0.0.0.0".into() });
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });

        let out = e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: "#y".into(), op: false });
        assert!(out.iter().any(|a| matches!(a, NetAction::ChannelMode { channel, modes, .. } if channel == "#y" && modes == "+v 000AAAAAB")), "{out:?}");
    }

// HelpServ fronts the whole network's help: it serves any service's per-command
// help, lists the services, and still answers for its own commands.
#[test]
fn helpserv_fronts_the_network_help_index() {
    let path = std::env::temp_dir().join("echo-helpserv-index.jsonl");
    let _ = std::fs::remove_file(&path);
    let db = Db::open(&path, "test");
    let mut e = Engine::new(
        vec![
            Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
            Box::new(echo_helpserv::HelpServ { uid: "42SAAAAAN".into() }),
        ],
        db,
    );
    e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "foo".into(), host: "h".into(), ip: "0.0.0.0".into() });

    let ask = |e: &mut Engine, text: &str| {
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAN".into(), text: text.into() })
            .into_iter()
            .filter_map(|a| match a {
                NetAction::Notice { text, .. } => Some(text),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    // HELP <service> <command> fronts that service's per-command help.
    let reg = ask(&mut e, "HELP NickServ REGISTER");
    assert!(reg.iter().any(|l| l.contains("Syntax:") && l.contains("REGISTER")), "{reg:?}");

    // Bare HELP lists the services on the network.
    let idx = ask(&mut e, "HELP");
    assert!(idx.iter().any(|l| l.contains("Services:") && l.contains("NickServ")), "{idx:?}");

    // A bare service name works too.
    let ns = ask(&mut e, "NickServ");
    assert!(ns.iter().any(|l| l.contains("IDENTIFY")), "{ns:?}");

    // HelpServ's own commands still resolve.
    let own = ask(&mut e, "HELP REQUEST");
    assert!(own.iter().any(|l| l.contains("Syntax:") && l.contains("REQUEST")), "{own:?}");
}

// ---- Per-service integration coverage --------------------------------------
// The service crates carry almost no unit tests; exercise each one's core path
// through a real Engine so a regression in a command handler is caught.

// Connect uid 000AAAAAB as `acct` and identify (password "sesame"). The account
// must already be registered in the engine's db.
fn svc_login(e: &mut Engine, acct: &str) {
    e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: acct.into(), host: "h".into(), ip: "0.0.0.0".into() });
    e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
}

// Grant the account full operator privileges.
fn svc_oper(e: &mut Engine, acct: &str) {
    // A full (root-tier) operator: `root` implies every lower privilege.
    let mut opers = std::collections::HashMap::new();
    opers.insert(acct.to_string(), echo_api::Privs::from_names(&["root"]));
    e.set_opers(opers);
}

// Send a command to a service uid; return the NOTICE texts it produced.
fn svc_ask(e: &mut Engine, uid: &str, text: &str) -> Vec<String> {
    e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: uid.into(), text: text.into() })
        .into_iter()
        .filter_map(|a| match a { NetAction::Notice { text, .. } => Some(text), _ => None })
        .collect()
}

fn svc_db(tag: &str) -> Db {
    let path = std::env::temp_dir().join(format!("echo-svc-{tag}.jsonl"));
    let _ = std::fs::remove_file(&path);
    let mut db = Db::open(&path, "test");
    db.scram_iterations = 4096;
    db
}

fn ns() -> Box<NickServ> {
    Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 })
}

#[test]
fn memoserv_delivers_a_memo_to_an_offline_account() {
    let mut db = svc_db("memo");
    db.register("alice", "sesame", None).unwrap();
    db.register("bob", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(echo_memoserv::MemoServ { uid: "42SAAAAAE".into() })], db);
    svc_login(&mut e, "alice");
    let out = svc_ask(&mut e, "42SAAAAAE", "SEND bob hi there");
    assert!(out.iter().any(|l| l.contains("Memo sent")), "{out:?}");
    assert_eq!(e.db.unread_memos("bob"), 1);
}

#[test]
fn groupserv_registers_a_group_and_adds_a_member() {
    let mut db = svc_db("group");
    db.register("alice", "sesame", None).unwrap();
    db.register("bob", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(echo_groupserv::GroupServ { uid: "42SAAAAAL".into() })], db);
    svc_login(&mut e, "alice");
    assert!(svc_ask(&mut e, "42SAAAAAL", "REGISTER !team").iter().any(|l| l.contains("registered")));
    svc_ask(&mut e, "42SAAAAAL", "ADD !team bob");
    let g = e.db.group("!team").expect("group exists");
    assert!(g.founder.eq_ignore_ascii_case("alice"));
    assert_eq!(g.members.len(), 1, "bob is a member");
}

#[test]
fn reportserv_files_then_an_oper_closes() {
    let mut db = svc_db("report");
    db.register("alice", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(echo_reportserv::ReportServ { uid: "42SAAAAAK".into() })], db);
    svc_login(&mut e, "alice");
    svc_ask(&mut e, "42SAAAAAK", "REPORT bob being a nuisance");
    assert_eq!(e.db.reports(true).len(), 1, "one open report");
    svc_oper(&mut e, "alice");
    svc_ask(&mut e, "42SAAAAAK", "CLOSE 0"); // report ids start at 0
    assert_eq!(e.db.reports(true).len(), 0, "closed");
}

#[test]
fn infoserv_posts_a_bulletin_admin_only() {
    let mut db = svc_db("info");
    db.register("alice", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(echo_infoserv::InfoServ { uid: "42SAAAAAJ".into() })], db);
    svc_login(&mut e, "alice");
    // Not an oper yet: refused.
    assert!(svc_ask(&mut e, "42SAAAAAJ", "POST scheduled maintenance tonight").iter().any(|l| l.contains("Access denied")));
    assert_eq!(e.db.news(NewsKind::Logon).len(), 0);
    svc_oper(&mut e, "alice");
    svc_ask(&mut e, "42SAAAAAJ", "POST scheduled maintenance tonight");
    assert_eq!(e.db.news(NewsKind::Logon).len(), 1, "bulletin posted");
}

#[test]
fn hostserv_request_then_operator_activate() {
    let mut db = svc_db("host");
    db.register("alice", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(echo_hostserv::HostServ { uid: "42SAAAAAG".into() })], db);
    svc_login(&mut e, "alice");
    svc_ask(&mut e, "42SAAAAAG", "REQUEST cool.vhost");
    assert_eq!(e.db.vhost_requests().len(), 1, "request pending");
    svc_oper(&mut e, "alice");
    svc_ask(&mut e, "42SAAAAAG", "ACTIVATE alice");
    assert!(e.db.vhosts().iter().any(|(acct, host, _, _)| acct.eq_ignore_ascii_case("alice") && host == "cool.vhost"), "vhost assigned: {:?}", e.db.vhosts());
}

#[test]
fn operserv_akill_add_and_remove() {
    let mut db = svc_db("oper");
    db.register("alice", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(echo_operserv::OperServ { uid: "42SAAAAAH".into() })], db);
    svc_login(&mut e, "alice");
    // Not an oper: refused.
    svc_ask(&mut e, "42SAAAAAH", "AKILL ADD *@bad.host spamming");
    assert_eq!(e.db.akills().len(), 0);
    svc_oper(&mut e, "alice");
    svc_ask(&mut e, "42SAAAAAH", "AKILL ADD *@bad.host spamming");
    assert_eq!(e.db.akills().len(), 1, "akill added");
    svc_ask(&mut e, "42SAAAAAH", "AKILL DEL *@bad.host");
    assert_eq!(e.db.akills().len(), 0, "akill removed");
}

#[test]
fn botserv_bot_add_is_operator_gated() {
    let mut db = svc_db("bot");
    db.register("alice", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(echo_botserv::BotServ { uid: "42SAAAAAD".into() })], db);
    svc_login(&mut e, "alice");
    svc_ask(&mut e, "42SAAAAAD", "BOT ADD Helper helper services.local A bot");
    assert_eq!(e.db.bots().count(), 0, "not an oper");
    svc_oper(&mut e, "alice");
    svc_ask(&mut e, "42SAAAAAD", "BOT ADD Helper helper services.local A bot");
    assert_eq!(e.db.bots().count(), 1, "bot created by oper");
}

#[test]
fn statserv_server_needs_an_operator() {
    let mut db = svc_db("stat");
    db.register("alice", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(echo_statserv::StatServ { uid: "42SAAAAAF".into() })], db);
    svc_login(&mut e, "alice");
    assert!(svc_ask(&mut e, "42SAAAAAF", "SERVER").iter().any(|l| l.to_lowercase().contains("denied") || l.contains("operator")), "non-oper refused");
    svc_oper(&mut e, "alice");
    assert!(!svc_ask(&mut e, "42SAAAAAF", "SERVER").is_empty(), "oper gets stats");
}

#[test]
fn chanfix_and_diceserv_basic_paths() {
    let mut db = svc_db("misc");
    db.register("alice", "sesame", None).unwrap();
    let mut e = Engine::new(
        vec![
            ns(),
            Box::new(echo_chanfix::ChanFix { uid: "42SAAAAAM".into() }),
            Box::new(echo_diceserv::DiceServ { uid: "42SAAAAAI".into() }),
        ],
        db,
    );
    svc_login(&mut e, "alice");
    // ChanFix is oper-only; SCORES on an unknown channel reports no history.
    svc_oper(&mut e, "alice");
    assert!(svc_ask(&mut e, "42SAAAAAM", "SCORES #ghost").iter().any(|l| l.contains("No op-time")), "chanfix empty case");
    // DiceServ evaluates an expression.
    assert!(svc_ask(&mut e, "42SAAAAAI", "ROLL 2d6").iter().any(|l| l.contains('=')), "dice result");
}

#[test]
fn notify_flags_match_user_nick_channel_and_expiry() {
    fn bt(nick: &'static str, host: &'static str) -> echo_api::BanTarget<'static> {
        echo_api::BanTarget { nick, ident: "u", host, realhost: host, ip: "1.2.3.4", gecos: "g", account: None, server: "s.net", fingerprint: None, channels: vec![] }
    }
    let mut db = svc_db("notifymatch");
    db.notify_add("baddie*!*@*", "cdn", "nick watch", "admin", None).unwrap();
    db.notify_add("#warez*", "j", "chan watch", "admin", None).unwrap();
    db.notify_add("*@spam.net", "c", "host watch", "admin", Some(1)).unwrap(); // expires at epoch 1 = long gone

    // A user mask hits exactly its own flags, not another entry's.
    let baddie = bt("baddie99", "h.example");
    assert!(db.notify_flags(Some(&baddie), None).contains('c'), "connect flag");
    assert!(db.notify_flags(Some(&baddie), None).contains('n'), "nick flag");
    assert!(!db.notify_flags(Some(&baddie), None).contains('j'), "j belongs to the channel mask only");
    // An unrelated user matches nothing.
    assert!(db.notify_flags(Some(&bt("nice", "h.example")), None).is_empty(), "no match for a clean user");
    // A channel mask matches on the joined channel, not on a different one.
    assert!(db.notify_flags(Some(&bt("nice", "h.example")), Some("#warez7")).contains('j'), "channel watch hit");
    assert!(!db.notify_flags(Some(&bt("nice", "h.example")), Some("#chat")).contains('j'), "channel watch miss");
    // The expired host watch never matches and is hidden from the list.
    assert!(db.notify_flags(Some(&bt("x", "spam.net")), None).is_empty(), "expired entry never matches");
    assert_eq!(db.notifies().len(), 2, "expired entry hidden from the list");
    // A PyLink relay client (nick carries a /network suffix) is excluded wholesale,
    // even against a watch it would otherwise match — and a normal nick still hits.
    db.set_notify_exclude(vec!["*/*".to_string()]);
    assert!(db.notify_flags(Some(&bt("baddie7/fun", "h.example")), None).is_empty(), "relay client excluded from every watch");
    assert!(db.notify_flags(Some(&bt("baddie7", "h.example")), None).contains('c'), "a normal nick still matches after exclude is set");
    // A #channel in the exclude list mutes that channel while others still fire —
    // e.g. watch every channel's joins but skip #staff.
    db.set_notify_exclude(vec!["#staff".to_string()]);
    assert!(db.notify_flags(Some(&bt("nice", "h.example")), Some("#staff")).is_empty(), "excluded channel is muted");
    assert!(db.notify_flags(Some(&bt("nice", "h.example")), Some("#warez7")).contains('j'), "other channels still watched");
    // `server:<glob>` mutes everyone on a matching server — a relay whose users have
    // clean nicks. bt() puts users on server "s.net".
    db.set_notify_exclude(vec!["server:s.net".to_string()]);
    assert!(db.notify_flags(Some(&bt("relayed", "h.example")), Some("#warez7")).is_empty(), "user on the excluded server is muted");
    db.set_notify_exclude(vec!["via:other.net".to_string()]);
    assert!(db.notify_flags(Some(&bt("relayed", "h.example")), Some("#warez7")).contains('j'), "user on a different server still watched");
    db.set_notify_exclude(vec![]);
    // DEL by mask removes just that one.
    assert!(db.notify_del("baddie*!*@*").unwrap());
    assert_eq!(db.notifies().len(), 1);
}

#[test]
fn notify_hook_emits_feed_for_watched_user() {
    let mut e = engine_with("nfyhook", "foo", "sesame");
    e.set_sid("42S".into());
    e.set_log_channel(Some("#services".into()));
    e.set_debugserv_uid("42SAAAAAO");
    e.db.notify_add("baddie*!*@*", "cd", "watch", "admin", None).unwrap();

    // A matching user's connect (identity complete at UserAttrs) feeds a line.
    e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "baddie1".into(), host: "h".into(), ip: "1.2.3.4".into() });
    let out = e.handle(NetEvent::UserAttrs { uid: "000AAAAAC".into(), ident: "x".into(), realhost: "h".into(), gecos: "g".into() });
    assert!(
        out.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text }
            if from == "42SAAAAAO" && to == "#services" && text.contains("[NOTIFY]") && text.contains("connected")
                && text.contains("IP: ") && text.contains("1.2.3.4"))), // real IP carried under a label, not just the cloak
        "expected a NOTIFY connect line with a labelled real IP, got {out:?}"
    );
    // A clean user draws nothing.
    e.handle(NetEvent::UserConnect { uid: "000AAAAAD".into(), nick: "nice".into(), host: "h".into(), ip: "9.9.9.9".into() });
    let quiet = e.handle(NetEvent::UserAttrs { uid: "000AAAAAD".into(), ident: "y".into(), realhost: "h".into(), gecos: "g".into() });
    assert!(!quiet.iter().any(|a| matches!(a, NetAction::Privmsg { to, .. } if to == "#services")), "no line for a clean user: {quiet:?}");
    // Their disconnect is matched before we forget them.
    let dc = e.handle(NetEvent::Quit { uid: "000AAAAAC".into(), reason: String::new() });
    assert!(
        dc.iter().any(|a| matches!(a, NetAction::Privmsg { text, .. } if text.contains("[NOTIFY]") && text.contains("disconnected"))),
        "expected a NOTIFY disconnect line, got {dc:?}"
    );
}

#[test]
fn notify_hook_covers_kick_reason_oper_and_usermode() {
    let mut e = engine_with("nfyext", "foo", "sesame");
    e.set_sid("42S".into());
    e.set_log_channel(Some("#services".into()));
    e.set_debugserv_uid("42SAAAAAO");
    e.db.notify_add("baddie*!*@*", "kdou", "watch", "admin", None).unwrap();
    // The watched victim and a (non-watched) kicker.
    e.handle(NetEvent::UserConnect { uid: "000AAAAAC".into(), nick: "baddie1".into(), host: "h".into(), ip: "1.2.3.4".into() });
    e.handle(NetEvent::UserAttrs { uid: "000AAAAAC".into(), ident: "x".into(), realhost: "h".into(), gecos: "g".into() });
    e.handle(NetEvent::UserConnect { uid: "000AAAAAD".into(), nick: "moddy".into(), host: "h".into(), ip: "9.9.9.9".into() });

    let feed = |acts: &[NetAction], needle: &str| acts.iter().any(|a| matches!(a, NetAction::Privmsg { to, text, .. } if to == "#services" && text.contains("[NOTIFY]") && text.contains(needle)));

    // Kick: the victim's line names the kicker and carries the reason.
    let k = e.handle(NetEvent::Kicked { channel: "#devs".into(), uid: "000AAAAAC".into(), by: "000AAAAAD".into(), reason: "spam".into() });
    assert!(feed(&k, "was kicked from #devs by moddy") && feed(&k, "(spam)"), "kick line: {k:?}");
    // User mode change.
    let u = e.handle(NetEvent::UserMode { uid: "000AAAAAC".into(), modes: "+i".into() });
    assert!(feed(&u, "set user mode +i"), "usermode line: {u:?}");
    // Oper-up carries the oper class.
    let o = e.handle(NetEvent::OperUp { uid: "000AAAAAC".into(), oper_type: "NetAdmin".into() });
    assert!(feed(&o, "opered up") && feed(&o, "NetAdmin"), "operup line: {o:?}");
    // Disconnect now carries the quit reason.
    let d = e.handle(NetEvent::Quit { uid: "000AAAAAC".into(), reason: "Ping timeout: 240 seconds".into() });
    assert!(feed(&d, "disconnected (Ping timeout: 240 seconds)"), "quit reason line: {d:?}");
}

#[test]
fn cmd_limiter_bursts_then_throttles_per_host() {
    let mut lim = CmdLimiter::default();
    let t0 = Instant::now();
    // A full bucket lets a whole burst through back-to-back.
    for _ in 0..CMD_BURST as usize {
        assert!(matches!(lim.check_at("1.2.3.4", t0), CmdVerdict::Allow), "burst within budget");
    }
    // Going over budget warns once, then drops silently — never a fresh warning per
    // line, which would just backscatter the flood.
    assert!(matches!(lim.check_at("1.2.3.4", t0), CmdVerdict::Warn), "first over-budget warns");
    assert!(matches!(lim.check_at("1.2.3.4", t0), CmdVerdict::Drop), "no repeat warning");
    assert!(matches!(lim.check_at("1.2.3.4", t0), CmdVerdict::Drop), "stays dropped");
    // A different host keeps its own independent budget.
    assert!(matches!(lim.check_at("9.9.9.9", t0), CmdVerdict::Allow), "other host independent");
    // A trickle refill lets a couple through, but an abuser the ircd is already
    // pacing must not be re-warned each time the bucket briefly recovers.
    let paced = t0 + Duration::from_secs(4); // +2 tokens
    assert!(matches!(lim.check_at("1.2.3.4", paced), CmdVerdict::Allow), "refilled token 1");
    assert!(matches!(lim.check_at("1.2.3.4", paced), CmdVerdict::Allow), "refilled token 2");
    assert!(matches!(lim.check_at("1.2.3.4", paced), CmdVerdict::Drop), "dropped, not re-warned mid-window");
    // Only once the warn window has elapsed does one fresh warning surface again.
    let next_window = t0 + Duration::from_secs(CMD_WARN_EVERY.as_secs() + 5);
    for _ in 0..CMD_BURST as usize {
        assert!(matches!(lim.check_at("1.2.3.4", next_window), CmdVerdict::Allow), "bucket refilled after idle");
    }
    assert!(matches!(lim.check_at("1.2.3.4", next_window), CmdVerdict::Warn), "one fresh warning in a new window");
}

// A dict fantasy (!dict) in a bot channel emits a DictLookup carried by the
// assigned bot — the actual dict.org round trip happens off-reactor in the link
// layer, so this just checks the routing.
#[test]
fn fantasy_dict_emits_a_lookup_via_the_bot() {
    use echo_botserv::BotServ;
    use echo_dictserv::DictServ;
    use echo_nickserv::NickServ;
    let path = std::env::temp_dir().join("echo-fdict.jsonl");
    let _ = std::fs::remove_file(&path);
    let mut db = Db::open(&path, "42S");
    db.scram_iterations = 4096;
    db.register("boss", "password1", None).unwrap();
    db.register_channel("#c", "boss").unwrap();
    let mut e = Engine::new(
        vec![
            Box::new(NickServ { uid: "42SAAAAAA".into(), guest_nick: "Guest".into(), guest_seq: 0 }),
            Box::new(BotServ { uid: "42SAAAAAD".into() }),
            Box::new(DictServ { uid: "42SAAAAAQ".into() }),
        ],
        db,
    );
    e.set_sid("42S".into());
    let mut opers = std::collections::HashMap::new();
    opers.insert("boss".to_string(), Privs::default().with(echo_api::Priv::Admin));
    e.set_opers(opers);
    e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "h".into(), ip: "0.0.0.0".into() });
    e.handle(NetEvent::UserConnect { uid: "000AAAAAR".into(), nick: "rando".into(), host: "h".into(), ip: "0.0.0.0".into() });
    e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY password1".into() });
    e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: "BOT ADD Bendy bot serv.host Helper".into() });
    e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: "ASSIGN #c Bendy".into() });
    e.handle(NetEvent::Join { uid: "000AAAAAR".into(), channel: "#c".into(), op: false });

    let out = e.handle(NetEvent::Privmsg { from: "000AAAAAR".into(), to: "#c".into(), text: "!dict cat".into() });
    assert!(
        out.iter().any(|a| matches!(a, NetAction::DictLookup { target, database, query, speak_as, .. }
            if target == "#c" && database == "wn" && query == "cat" && speak_as.starts_with("42SB"))),
        "expected a bot-carried DictLookup, got {out:?}"
    );
}

// A blocked look-alike channel registration refuses the user AND tells the staff
// feed who tried it.
#[test]
fn confusable_register_alerts_the_staff_feed() {
    use echo_chanserv::ChanServ;
    let mut db = svc_db("confalert");
    db.register("boss", "sesame", None).unwrap();
    let mut e = Engine::new(vec![ns(), Box::new(ChanServ { uid: "42SAAAAAB".into() })], db);
    e.set_sid("42S".into());
    e.set_log_channel(Some("#services".into()));
    e.set_debugserv_uid("42SAAAAAO");
    e.handle(NetEvent::UserConnect { uid: "000AAAAAB".into(), nick: "boss".into(), host: "host.fr".into(), ip: "1.2.3.4".into() });
    e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAA".into(), text: "IDENTIFY sesame".into() });
    let chan = "#teѕt"; // Latin te + Cyrillic ѕ + Latin t — a look-alike
    e.handle(NetEvent::Join { uid: "000AAAAAB".into(), channel: chan.into(), op: true });
    let out = e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAB".into(), text: format!("REGISTER {chan}") });
    // The user is refused,
    assert!(out.iter().any(|a| matches!(a, NetAction::Notice { to, text, .. } if to == "000AAAAAB" && text.contains("alphabets"))), "user refused: {out:?}");
    // and #services is told who tried it.
    assert!(
        out.iter().any(|a| matches!(a, NetAction::Privmsg { from, to, text }
            if from == "42SAAAAAO" && to == "#services" && text.contains("[REGISTER]") && text.contains("boss") && text.contains("look-alike"))),
        "staff feed alert: {out:?}"
    );
    // ...and it's recorded to the searchable incident log (OperServ LOGSEARCH).
    assert!(!e.network.search_incidents("look-alike", 10).is_empty(), "recorded for LOGSEARCH");
}

// Perf harness — not part of the normal suite. Run:
//   cargo test --release -p echo -- --ignored --nocapture bench_engine
// Measures the two costs that actually bound the single-threaded engine: the
// BotServ per-message hot path (kicker scans + record_line + fantasy), and the
// log append+fsync write path.
#[test]
#[ignore]
fn bench_engine_throughput() {
    use std::time::Instant;

    // Write path: one serialize + append + fsync per state-mutating event.
    {
        let mut db = svc_db("bench_write");
        let n = 3000usize;
        let t = Instant::now();
        for i in 0..n {
            db.notify_add(&format!("m{i}!*@*"), "c", "bench", "admin", None).unwrap();
        }
        let el = t.elapsed();
        println!(
            "\n[write] append+fsync: {n} events in {:.3}s = {:.0} events/s, {:.3} ms/event\n        (temp-dir fs; a real data disk may fsync slower)",
            el.as_secs_f64(),
            n as f64 / el.as_secs_f64(),
            el.as_secs_f64() * 1000.0 / n as f64,
        );
    }

    // Hot path: BotServ chatter in a busy channel. Every kicker is on but set high
    // enough that ordinary lines never trip it, so we time the per-message CHECK
    // cost (the realistic case), not the kick path.
    let (mut e, _p) = kicker_fixture("bench_hot");
    let bs = |e: &mut Engine, t: &str| {
        e.handle(NetEvent::Privmsg { from: "000AAAAAB".into(), to: "42SAAAAAD".into(), text: t.into() });
    };
    bs(&mut e, "KICK #c CAPS ON");
    bs(&mut e, "KICK #c REPEAT ON 100000");
    bs(&mut e, "KICK #c FLOOD ON 100000 60");

    let members = 1000usize;
    let muid = |i: usize| format!("00M{i:06}");
    for i in 0..members {
        e.handle(NetEvent::UserConnect { uid: muid(i), nick: format!("user{i}"), host: "h".into(), ip: "0.0.0.0".into() });
        e.handle(NetEvent::Join { uid: muid(i), channel: "#c".into(), op: false });
    }

    let msgs = 200_000usize;
    let t = Instant::now();
    for i in 0..msgs {
        e.handle(NetEvent::Privmsg { from: muid(i % members), to: "#c".into(), text: format!("just chatting line {i} nothing special here") });
    }
    let el = t.elapsed();
    println!(
        "[hot]   botserv chatter: {msgs} msgs in a {members}-user channel in {:.3}s = {:.0} msgs/s, {:.3} us/msg\n",
        el.as_secs_f64(),
        msgs as f64 / el.as_secs_f64(),
        el.as_micros() as f64 / msgs as f64,
    );
}
