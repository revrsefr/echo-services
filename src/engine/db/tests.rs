    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("echo-log-{name}.jsonl"));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn cert(account: &str, fp: &str) -> Event {
        Event::CertAdded { account: account.into(), fp: fp.into() }
    }

    #[test]
    fn formats_unix_time_as_utc() {
        assert_eq!(echo_api::human_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(echo_api::human_time(1783844590), "2026-07-12 08:23:10 UTC");
    }

    #[test]
    fn glob_matches_hostmasks() {
        assert!(glob_match("*!*@host.example", "bob!~b@host.example"));
        assert!(glob_match("bob!*@*", "BOB!~b@1.2.3.4"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("nick?!*@*", "nickX!~x@h"));
        assert!(!glob_match("*!*@host.example", "bob!~b@other"));
        assert!(!glob_match("alice!*@*", "bob!~b@h"));
    }

    #[test]
    fn account_conflict_resolves_deterministically() {
        // `tag` (carried in the email field, a free identity slot here) labels
        // which of the two competing registrations we're looking at.
        let alice = |tag: &str, ts: u64, home: &str| Account {
            name: "alice".into(), email: Some(tag.into()),
            ts, home: home.into(), scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![], suspension: None, memos: vec![], memo_ignore: vec![], memo_notify: true, memo_limit: None, greet: String::new(), no_autoop: false, no_protect: false, hide_status: false, snotice: false, language: None, vhost: None, vhost_request: None, last_seen: ts, noexpire: false, expiry_warned: false, oper_note: None,
        };
        let converge = |first: &Account, second: &Account| {
            let (mut acc, mut ch, mut gr, mut bo, mut hc, mut nd) = (HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new(), HostConfig::default(), NetData::default());
            apply(&mut acc, &mut ch, &mut gr, &mut bo, &mut hc, &mut nd, Event::AccountRegistered(Box::new(first.clone())));
            apply(&mut acc, &mut ch, &mut gr, &mut bo, &mut hc, &mut nd, Event::AccountRegistered(Box::new(second.clone())));
            acc["alice"].email.clone().unwrap()
        };
        // Earlier registration wins, regardless of which claim applies first.
        let early = alice("EARLY", 100, "nodeB");
        let late = alice("LATE", 200, "nodeA");
        assert_eq!(converge(&early, &late), "EARLY");
        assert_eq!(converge(&late, &early), "EARLY", "commutative: same winner in either order");
        // Same ts: the lower origin wins, in either order.
        let a = alice("A", 100, "nodeA");
        let b = alice("B", 100, "nodeB");
        assert_eq!(converge(&a, &b), "A");
        assert_eq!(converge(&b, &a), "A", "ts tie broken by lower origin, either order");
        // Idempotent: re-delivering the winner keeps it.
        assert_eq!(converge(&a, &a), "A");
    }

    #[test]
    fn group_registration_conflict_converges_deterministically() {
        let reg = |founder: &str, ts: u64, home: &str| Event::GroupRegistered { name: "!g".into(), founder: founder.into(), ts, home: home.into() };
        let converge = |first: Event, second: Event| {
            let (mut acc, mut ch, mut gr, mut bo, mut hc, mut nd) = (HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new(), HostConfig::default(), NetData::default());
            apply(&mut acc, &mut ch, &mut gr, &mut bo, &mut hc, &mut nd, first);
            apply(&mut acc, &mut ch, &mut gr, &mut bo, &mut hc, &mut nd, second);
            nd.groups[0].founder.clone()
        };
        let a = reg("alice", 100, "nodeA");
        let b = reg("bob", 100, "nodeB");
        // Two nodes claim "!g": the earlier (ts, then origin) wins, same result in
        // either apply order — so gossip peers converge instead of diverging.
        assert_eq!(converge(a.clone(), b.clone()), "alice", "(100,nodeA) beats (100,nodeB)");
        assert_eq!(converge(b, a), "alice", "commutative: converges to the same founder");
    }

    // A gossiped registration that wins the name (earlier ts) moves an account's
    // home. That is a hostile takeover — logging the local user out — ONLY if the
    // credential differs; re-asserting the SAME account (same verifier) must not.
    #[test]
    fn rehome_keeping_the_verifier_is_not_a_takeover() {
        let acct = |home: &str, ts: u64, verifier: &str| Account {
            name: "reverse".into(), email: None, ts, home: home.into(),
            scram256: Some(verifier.into()), scram512: None, certfps: vec![], verified: true,
            ajoin: vec![], suspension: None, memos: vec![], memo_ignore: vec![], memo_notify: true,
            memo_limit: None, greet: String::new(), no_autoop: false, no_protect: false,
            hide_status: false, snotice: false, language: None, vhost: None, vhost_request: None, last_seen: ts, noexpire: false,
            expiry_warned: false, oper_note: None,
        };
        let reg = |origin: &str, a: Account| LogEntry::for_test(origin, 0, 1, Event::AccountRegistered(Box::new(a)));

        // Same account, re-homed to B with the SAME verifier — not a takeover.
        let mut db = Db::open(tmp("rehome-same"), "A");
        db.ingest(reg("A", acct("A", 100, "V"))).unwrap();
        assert!(db.ingest(reg("B", acct("B", 1, "V"))).unwrap().is_none(), "same-verifier re-home is not a takeover");
        assert_eq!(db.account("reverse").unwrap().home, "B", "the home still moved (conflict resolved)");

        // A genuinely different account (different verifier) winning the name is one.
        let mut db2 = Db::open(tmp("rehome-diff"), "A");
        db2.ingest(reg("A", acct("A", 100, "V"))).unwrap();
        assert!(matches!(db2.ingest(reg("B", acct("B", 1, "OTHER"))).unwrap(), Some(IngestEffect::TakenOver(n)) if n == "reverse"),
            "a different credential winning the name is a real takeover");
    }

    #[test]
    fn channel_state_is_node_local_but_persists() {
        let path = tmp("scope");
        {
            let mut db = Db::open(&path, "N1");
            db.register("alice", "pw", None).unwrap(); // global
            db.register_channel("#c", "alice").unwrap(); // local
            db.set_mlock("#c", "nt", "").unwrap(); // local
            // Only the account advances the version vector.
            assert_eq!(db.version_vector().get("N1"), Some(&(0, 0)), "channels don't advance the vector");
            // A fresh peer is offered the account, never the channel.
            let missing = db.missing_for(&HashMap::new());
            assert_eq!(missing.len(), 1, "only the global account entry is offered: {missing:?}");
            assert!(matches!(missing[0].event, Event::AccountRegistered(_)));
        }
        // Reopen: node-local channel state replays from disk unchanged.
        let db = Db::open(&path, "N1");
        assert!(db.exists("alice"));
        assert_eq!(db.channel("#c").map(|c| c.lock_on.clone()), Some("nt".to_string()), "channel state persists locally");
        assert_eq!(db.version_vector().get("N1"), Some(&(0, 0)), "vector unchanged after replay");
    }

    #[test]
    fn akick_add_del_and_match() {
        let mut db = Db::open(tmp("akick"), "N1");
        db.register_channel("#c", "founder").unwrap();
        db.akick_add("#c", "*!*@bad.host", "spam").unwrap();
        // Also an account extban (the evasion-proof kind) and a realname extban.
        db.akick_add("#c", "account:baddie", "gone").unwrap();
        db.akick_add("#c", "realname:*viagra*", "spam").unwrap();
        let info = db.channel("#c").unwrap();
        let t = |nick, ident, host, gecos, account| echo_api::BanTarget {
            nick,
            ident,
            host,
            realhost: host,
            ip: "0.0.0.0",
            gecos,
            account,
            server: "irc.test",
            fingerprint: None,
            channels: Vec::new(),
        };
        assert!(info.akick_match(&t("evil", "~e", "bad.host", "", None)).is_some(), "host mask");
        assert!(info.akick_match(&t("good", "~g", "ok.host", "", None)).is_none());
        assert!(info.akick_match(&t("x", "y", "ok.host", "", Some("baddie"))).is_some(), "account extban");
        assert!(info.akick_match(&t("x", "y", "ok.host", "cheap VIAGRA now", None)).is_some(), "realname extban");
        assert!(info.akick_match(&t("x", "y", "ok.host", "hello", None)).is_none());
        assert!(db.akick_del("#c", "*!*@bad.host").unwrap());
        assert!(!db.akick_del("#c", "*!*@bad.host").unwrap());
    }

    // SET SNOTICE toggles the per-account server-notice preference (default off).
    #[test]
    fn snotice_pref_toggles() {
        let mut db = Db::open(tmp("snotice"), "N1");
        db.register("bob", "pw", None).unwrap();
        assert!(!db.account_wants_snotice("bob"), "default is a normal notice");
        db.set_account_snotice("bob", true).unwrap();
        assert!(db.account_wants_snotice("bob"));
        db.set_account_snotice("bob", false).unwrap();
        assert!(!db.account_wants_snotice("bob"));
    }

    // LEVELS grants are additive (default = unchanged), tier-gated, and reversible.
    #[test]
    fn levels_grant_is_additive_and_tier_gated() {
        let mut db = Db::open(tmp("levels"), "N1");
        db.register_channel("#c", "founder").unwrap();
        db.access_add("#c", "aop", "op").unwrap();
        db.access_add("#c", "vop", "voice").unwrap();
        // caps_of lives on the ChannelView the Store builds (levels are typed there).
        let view = |db: &Db| echo_api::Store::channel(db, "#c").unwrap();
        // Baseline: no LEVELS set → an AOP can op but can't manage the access list.
        assert!(view(&db).levels.is_empty(), "no overrides by default");
        assert!(view(&db).caps_of(Some("aop")).op);
        assert!(!view(&db).caps_of(Some("aop")).access, "AOP lacks access mgmt by default");
        // Grant ACCESS to AOP-and-above.
        db.level_set("#c", "ACCESS", "AOP").unwrap();
        assert!(view(&db).caps_of(Some("aop")).access, "AOP now manages the access list");
        assert!(!view(&db).caps_of(Some("vop")).access, "VOP is below AOP — not granted");
        assert!(view(&db).caps_of(Some("aop")).op, "existing caps untouched");
        // Reset restores the default.
        assert!(db.level_reset("#c", "ACCESS").unwrap());
        assert!(!view(&db).caps_of(Some("aop")).access);
        assert!(!db.level_reset("#c", "ACCESS").unwrap(), "already default");
    }

    // The auto-join list adds, updates a key in place, removes case-insensitively,
    // and replays from the event log after a reopen.
    #[test]
    fn ajoin_add_del_and_persist() {
        let p = tmp("ajoin");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "pw", None).unwrap();
            assert!(db.ajoin_add("alice", "#chat", "").unwrap(), "newly added");
            assert!(!db.ajoin_add("alice", "#chat", "sekret").unwrap(), "re-add updates the key, not newly added");
            db.ajoin_add("alice", "#dev", "").unwrap();
            assert_eq!(db.ajoin_list("alice").len(), 2);
            assert_eq!(db.ajoin_list("alice")[0].key, "sekret", "key updated in place");
            assert!(db.ajoin_del("alice", "#CHAT").unwrap(), "case-insensitive remove");
            assert!(!db.ajoin_del("alice", "#chat").unwrap(), "already gone");
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.ajoin_list("alice").len(), 1, "list replays from the log");
        assert_eq!(db.ajoin_list("alice")[0].channel, "#dev");
    }

    // Channel SET options default off, toggle, and replay from the log.
    #[test]
    fn channel_settings_toggle_and_persist() {
        let p = tmp("chansettings");
        {
            let mut db = Db::open(&p, "N1");
            db.register_channel("#c", "boss").unwrap();
            assert!(!db.channel("#c").unwrap().settings.signkick, "defaults off");
            db.set_channel_setting("#c", ChanSetting::SignKick, true).unwrap();
            db.set_channel_setting("#c", ChanSetting::Private, true).unwrap();
            db.set_channel_setting("#c", ChanSetting::Private, false).unwrap();
            let s = db.channel("#c").unwrap().settings;
            assert!(s.signkick && !s.private, "one flag on, the other flipped back off");
        }
        let s = Db::open(&p, "N1").channel("#c").unwrap().settings;
        assert!(s.signkick && !s.private, "settings replay from the log");
    }

    // Access ranks order founder > sop > op > halfop > voice > none, matching the
    // ircd prefix ranks so PEACE tells every tier apart (the old u8 collapsed
    // SOP≡AOP and halfop≡voice).
    #[test]
    fn access_rank_orders_all_tiers() {
        use echo_api::Rank;
        let mut db = Db::open(tmp("rank"), "N1");
        db.register_channel("#c", "boss").unwrap();
        db.access_add("#c", "sop1", "sop").unwrap();
        db.access_add("#c", "op1", "op").unwrap();
        db.access_add("#c", "hop1", "halfop").unwrap();
        db.access_add("#c", "v1", "voice").unwrap();
        let cv = Store::channel(&db, "#c").unwrap();
        assert_eq!(cv.access_rank(Some("boss")), Rank::Founder);
        assert_eq!(cv.access_rank(Some("SOP1")), Rank::Admin, "case-insensitive");
        assert_eq!(cv.access_rank(Some("op1")), Rank::Op);
        assert_eq!(cv.access_rank(Some("hop1")), Rank::Halfop);
        assert_eq!(cv.access_rank(Some("v1")), Rank::Voice);
        assert_eq!(cv.access_rank(Some("nobody")), Rank::None);
        assert_eq!(cv.access_rank(None), Rank::None);
        // The whole point: each tier strictly outranks the next one down.
        assert!(cv.access_rank(Some("boss")) > cv.access_rank(Some("sop1")));
        assert!(cv.access_rank(Some("sop1")) > cv.access_rank(Some("op1")), "SOP outranks AOP");
        assert!(cv.access_rank(Some("op1")) > cv.access_rank(Some("hop1")));
        assert!(cv.access_rank(Some("hop1")) > cv.access_rank(Some("v1")), "halfop outranks voice");
    }

    // Suspension sets/lifts, expires lazily, and replays from the log.
    #[test]
    fn suspend_lifts_expires_and_persists() {
        let p = tmp("suspend");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "password1", None).unwrap();
            assert!(!db.is_suspended("alice"));
            db.suspend_account("alice", "oper", "spamming", None).unwrap();
            assert!(db.is_suspended("alice"));
            assert_eq!(db.suspension("alice").unwrap().reason, "spamming");
            assert!(db.unsuspend_account("alice").unwrap());
            assert!(!db.is_suspended("alice"));
            assert!(!db.unsuspend_account("alice").unwrap(), "already lifted");
            // A past expiry is not active, but the record still shows in INFO.
            db.suspend_account("alice", "oper", "temp", Some(1)).unwrap();
            assert!(!db.is_suspended("alice"), "expired suspension is inactive");
            assert!(db.suspension("alice").is_some());
        }
        {
            let mut db = Db::open(&p, "N1");
            db.suspend_account("alice", "oper", "again", None).unwrap();
        }
        assert!(Db::open(&p, "N1").is_suspended("alice"), "suspension replays from the log");
    }

    // A channel suspension lifts, expires lazily, and survives compaction + reopen.
    #[test]
    fn channel_suspend_lifts_persists_and_compacts() {
        let p = tmp("chansuspend");
        let mut db = Db::open(&p, "N1");
        db.register_channel("#c", "boss").unwrap();
        db.suspend_channel("#c", "oper", "raided", Some(1)).unwrap();
        assert!(!db.is_channel_suspended("#c"), "a past expiry is inactive");
        db.suspend_channel("#c", "oper", "raided", None).unwrap();
        assert!(db.is_channel_suspended("#c"));
        db.compact().unwrap(); // the snapshot must retain the suspension
        drop(db);
        let db = Db::open(&p, "N1");
        assert!(db.is_channel_suspended("#c"), "survives compaction + reopen");
        assert_eq!(db.channel_suspension("#c").unwrap().by, "oper");
    }

    // The bot registry adds (case-insensitively unique), deletes, and replays.
    #[test]
    fn bots_add_del_and_persist() {
        let p = tmp("bots");
        {
            let mut db = Db::open(&p, "N1");
            assert_eq!(db.bots().count(), 0);
            db.bot_add("Bendy", "bot", "services.host", "A helper").unwrap();
            assert!(matches!(db.bot_add("bendy", "x", "y", "z"), Err(ChanError::Exists)), "dup is case-insensitive");
            assert_eq!(db.bots().count(), 1);
            assert!(db.bot_del("BENDY").unwrap(), "case-insensitive delete");
            assert!(!db.bot_del("bendy").unwrap(), "already gone");
        }
        {
            let mut db = Db::open(&p, "N1");
            db.bot_add("Botty", "b", "h", "g").unwrap();
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.bots().count(), 1, "bots replay from the log");
        assert_eq!(db.bots().next().unwrap().nick, "Botty");
    }

    // Memos send, mark read on read, delete (shifting indices), and replay.
    #[test]
    fn memos_send_read_delete_and_persist() {
        let p = tmp("memos");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "password1", None).unwrap();
            assert_eq!(db.unread_memos("alice"), 0);
            db.memo_send("alice", "bob", "hello there", false).unwrap();
            db.memo_send("alice", "carol", "second", false).unwrap();
            assert_eq!(db.unread_memos("alice"), 2);
            let m = db.memo_read("alice", 0).unwrap();
            assert_eq!(m.from, "bob");
            assert_eq!(db.unread_memos("alice"), 1, "reading marks it read");
            assert!(db.memo_del("alice", 0));
            assert_eq!(db.memo_list("alice").len(), 1);
            assert_eq!(db.memo_list("alice")[0].text, "second", "delete shifts indices");
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.memo_list("alice").len(), 1, "memos replay from the log");
        assert_eq!(db.unread_memos("alice"), 1);
    }

    // CANCEL recalls the sender's most recent unread memo; CHECK reports read-state.
    #[test]
    fn memo_cancel_and_check() {
        let mut db = Db::open(tmp("memo-cc"), "N1");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.memo_send("alice", "bob", "hi", false).unwrap();
        db.memo_send("alice", "bob", "you there?", false).unwrap();

        assert_eq!(db.memo_check("alice", "bob").map(|(read, _)| read), Some(false), "unread so far");
        assert!(db.memo_cancel("alice", "bob"), "recalls the most recent unread");
        assert_eq!(db.memo_list("alice").len(), 1, "one memo cancelled");

        db.memo_read("alice", 0); // alice reads the remaining memo
        assert!(!db.memo_cancel("alice", "bob"), "a read memo can't be recalled");
        assert_eq!(db.memo_check("alice", "bob").map(|(read, _)| read), Some(true), "now shows read");

        assert_eq!(db.memo_check("alice", "carol"), None, "no memo from carol");
        assert!(!db.memo_cancel("alice", "carol"));
    }

    // A wrong code is tolerated a few times, then the code is burned so it can't
    // be ground down online even though it is short.
    #[test]
    fn code_burns_after_too_many_wrong_guesses() {
        let mut db = Db::open(tmp("code"), "N1");
        db.scram_iterations = 4096;
        db.register("alice", "password", None).unwrap();
        let code = db.issue_code("alice", CodeKind::Reset);
        for _ in 0..CODE_TRIES {
            assert!(!db.take_code("alice", CodeKind::Reset, "WRONG000"), "wrong guess fails");
        }
        assert!(!db.take_code("alice", CodeKind::Reset, &code), "the real code is now burned too");
    }

    // Password auth backs off after a few failures and the throttle clears on success.
    #[test]
    fn auth_throttle_locks_then_clears() {
        let mut db = Db::open(tmp("throttle"), "N1");
        for _ in 0..=AUTH_FREE_TRIES {
            db.note_auth("mallory", false);
        }
        assert!(db.auth_lockout("mallory").is_some(), "locked out after the free tries");
        db.note_auth("mallory", true);
        assert!(db.auth_lockout("mallory").is_none(), "a success clears the throttle");
    }

    // Locally-authored events get an incrementing per-origin seq and a ticking
    // Lamport clock.
    #[test]
    fn append_stamps_monotonic_metadata() {
        let (mut log, ev) = EventLog::open(tmp("append"), "nodeA".into());
        assert!(ev.is_empty());
        log.append(cert("x", "f1")).unwrap();
        log.append(cert("x", "f2")).unwrap();
        assert_eq!(log.versions.get("nodeA"), Some(&(0, 1))); // epoch 0, seqs 0 then 1
        assert_eq!(log.lamport, 2);
        assert_eq!(log.next_seq(), 2);
    }

    // Reopening the log recovers the clocks so seqs are never reused.
    #[test]
    fn reopen_recovers_clocks() {
        let p = tmp("reopen");
        {
            let (mut log, _) = EventLog::open(p.clone(), "nodeA".into());
            log.append(cert("x", "f1")).unwrap();
            log.append(cert("x", "f2")).unwrap();
        }
        let (log, events) = EventLog::open(p, "nodeA".into());
        assert_eq!(events.len(), 2);
        assert_eq!(log.next_seq(), 2);
        assert_eq!(log.lamport, 2);
    }

    // Ingesting a peer's entry applies it once and advances the Lamport clock;
    // a re-delivered entry is dropped (gossip convergence).
    #[test]
    fn ingest_is_idempotent() {
        let (mut log, _) = EventLog::open(tmp("ingest"), "local".into());
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 5, epoch: 0, sig: None, event: cert("x", "f") };
        assert!(log.ingest(entry.clone()).unwrap().is_some(), "first ingest applies");
        assert_eq!(log.versions.get("peer"), Some(&(0, 0)));
        assert_eq!(log.lamport, 6, "receive rule: max(local, remote) + 1");
        assert!(log.ingest(entry).unwrap().is_none(), "duplicate ingest is a no-op");
    }

    // The gossip seam folds a peer's account into local state.
    #[test]
    fn db_ingest_folds_peer_account() {
        let mut db = Db::open(tmp("dbingest"), "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        let bob = Account {
            name: "bob".into(), email: None,
            ts: 0, home: "peer".into(), scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![], suspension: None, memos: vec![], memo_ignore: vec![], memo_notify: true, memo_limit: None, greet: String::new(), no_autoop: false, no_protect: false, hide_status: false, snotice: false, language: None, vhost: None, vhost_request: None, last_seen: 0, noexpire: false, expiry_warned: false, oper_note: None,
        };
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 1, epoch: 0, sig: None, event: Event::AccountRegistered(Box::new(bob)) };
        db.ingest(entry).unwrap();
        assert!(db.exists("bob"), "peer's account is present locally");
        assert!(db.exists("alice"), "local account still there");
    }

    // Compaction collapses churn to one entry per account and survives a reload.
    #[test]
    fn compact_preserves_state_and_shrinks() {
        let p = tmp("compact");
        let mut db = Db::open(&p, "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        for i in 0..10u32 {
            let fp = format!("{i:032x}");
            db.certfp_add("alice", &fp).unwrap();
            db.certfp_del("alice", &fp).unwrap();
        }
        let kept = "bb".repeat(16);
        db.certfp_add("bob", &kept).unwrap();

        let before = db.log.len();
        db.compact().unwrap();
        assert!(db.log.len() < before, "log shrank: {before} -> {}", db.log.len());
        assert_eq!(db.log.len(), 2, "one entry per account");

        drop(db);
        let db = Db::open(&p, "local");
        assert!(db.authenticate("alice", "pw").is_some(), "password survives compaction");
        assert!(db.certfps("alice").is_empty(), "churned certs are gone");
        assert_eq!(db.certfps("bob"), &[kept][..], "kept cert survives");
    }

    #[test]
    fn channel_directory_events_reach_the_outbound_subscriber() {
        // A gRPC directory subscriber (a website mirror) reads the outbound stream.
        // Account events are Global and always flowed; channel events are Local and
        // were dropped before reaching outbound, so a mirror never saw registrations.
        let (tx, mut rx) = tokio::sync::broadcast::channel(64);
        let mut db = Db::open(tmp("chan-sub"), "N1");
        db.scram_iterations = 4096;
        db.set_outbound(tx);
        db.register("alice", "pw", None).unwrap();
        db.register_channel("#c", "alice").unwrap();
        let mut saw_channel = false;
        while let Ok(entry) = rx.try_recv() {
            if matches!(entry.event(), Event::ChannelRegistered { name, .. } if name == "#c") {
                saw_channel = true;
            }
        }
        assert!(saw_channel, "channel registration must reach the outbound directory stream");
    }

    #[test]
    fn compaction_preserves_channel_last_used_and_levels() {
        let p = tmp("compact-chan");
        let mut db = Db::open(&p, "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.register_channel("#chan", "alice").unwrap();
        let reg_ts = db.channel("#chan").unwrap().ts;
        // A LEVELS override and recent activity, both held outside ChannelRegistered.
        db.level_set("#chan", "SET", "AOP").unwrap();
        let active = reg_ts + 100_000; // past the 1-day activity-coalesce threshold
        db.mark_channel_used("#chan", active);
        assert_eq!(db.channel("#chan").unwrap().last_used, active);

        db.compact().unwrap();
        drop(db);
        let db = Db::open(&p, "local");
        let c = db.channel("#chan").expect("channel survives compaction");
        // Before the fix, the snapshot emitted only ChannelRegistered, so replay
        // reset last_used to reg_ts (risking wrong expiry) and dropped the override.
        assert_eq!(c.last_used, active, "inactivity clock survives compaction");
        assert!(c.levels.iter().any(|(cap, role)| cap == "SET" && role == "AOP"), "LEVELS override survives: {:?}", c.levels);
    }

    // An account provisioned from a SCRAM verifier alone (external authority)
    // must authenticate over the PLAIN / IDENTIFY path (db.authenticate), not
    // only over SCRAM — the verifier is the sole credential, so a backfilled
    // member can still `/msg NickServ IDENTIFY`.
    #[test]
    fn provisioned_account_authenticates_over_plain() {
        let mut db = Db::open(tmp("prov-plain"), "N1");
        db.scram_iterations = 4096;
        let creds = Db::derive_credentials("hunter2", 4096).unwrap();
        db.provision_account("ext", &creds.scram256, "", None).unwrap();

        // The verifier is the only credential on file, and PLAIN/IDENTIFY works.
        assert!(db.test_verifier("ext").is_some(), "provisioned: verifier is the credential");
        assert_eq!(db.authenticate("ext", "hunter2"), Some("ext"), "right password logs in");
        assert!(db.authenticate("ext", "wrong").is_none(), "wrong password rejected");
    }

    // The migration flow: an Anope import creates the account with NO verifier
    // (one-way hash can't move), then the authority provisions the verifier. That
    // second provision must SET the credential on the existing account, not be
    // refused — otherwise every migrated member is locked out of password login.
    #[test]
    fn provision_sets_verifier_on_an_imported_account() {
        let p = tmp("prov-imported");
        {
            let mut db = Db::open(&p, "N1");
            db.migrate_append(Event::AccountRegistered(Box::new(Account {
                name: "mig".into(), email: Some("m@x".into()), ts: 1, home: "N1".into(),
                scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![],
                suspension: None, memos: vec![], memo_ignore: vec![], memo_notify: true,
                memo_limit: None, greet: String::new(), no_autoop: false, no_protect: false,
                hide_status: false, snotice: false, language: None, vhost: None, vhost_request: None, last_seen: 1,
                noexpire: false, expiry_warned: false, oper_note: None,
            }))).unwrap();
        }
        // Reopen so the imported account is live in memory (as after a restart).
        let mut db = Db::open(&p, "N1");
        db.scram_iterations = 4096;
        assert!(db.authenticate("mig", "hunter2").is_none(), "imported account has no verifier yet");
        let creds = Db::derive_credentials("hunter2", 4096).unwrap();
        db.provision_account("mig", &creds.scram256, "", None).unwrap();
        assert_eq!(db.authenticate("mig", "hunter2"), Some("mig"), "provision set the verifier on the existing account");
    }

    // A peer with an empty log converges from a node that has already compacted.
    #[test]
    fn compacted_node_still_converges() {
        let mut a = Db::open(tmp("compA"), "A");
        a.scram_iterations = 4096;
        a.register("alice", "pw", None).unwrap();
        let fp = "cc".repeat(16);
        a.certfp_add("alice", &fp).unwrap();
        a.compact().unwrap();

        let mut b = Db::open(tmp("compB"), "B");
        b.scram_iterations = 4096;
        for entry in a.missing_for(&b.version_vector()) {
            b.ingest(entry).unwrap();
        }
        assert!(b.exists("alice"), "B converges from a compacted node");
        assert_eq!(b.certfps("alice"), &[fp][..], "certs arrive folded into the snapshot");
    }

    fn akill(origin: &str, epoch: u64, seq: u64, mask: &str) -> LogEntry {
        LogEntry::for_test_epoch(origin, epoch, seq, seq + 1, Event::AkillAdded {
            kind: "G".into(), mask: mask.into(), setter: "op".into(), reason: "x".into(), ts: 0, expires: None,
        })
    }

    // The snapshot-epoch fix, part 1: a peer holding an origin's PARTIAL state still
    // converges across that origin's compaction (the forward epoch jump is accepted).
    // This is exactly the case the earlier strict-ordering attempt broke.
    #[test]
    fn lagging_peer_converges_across_a_compaction() {
        let mut a = Db::open(tmp("epochA"), "AAA");
        a.scram_iterations = 4096;
        a.register("u0", "pw", None).unwrap();
        a.register("u1", "pw", None).unwrap();

        // B syncs A's initial (epoch 0) state, then lags.
        let mut b = Db::open(tmp("epochB"), "BBB");
        b.scram_iterations = 4096;
        for e in a.missing_for(&b.version_vector()) {
            b.ingest(e).unwrap();
        }
        assert!(b.exists("u0") && b.exists("u1"), "B has A's initial state");

        // A advances and COMPACTS (epoch 0 -> 1, seqs reset to 0).
        a.register("u2", "pw", None).unwrap();
        a.compact().unwrap();

        // B, still at epoch 0, must converge across the epoch jump.
        for e in a.missing_for(&b.version_vector()) {
            b.ingest(e).unwrap();
        }
        assert!(b.exists("u2"), "B converges across A's compaction (epoch jump adopted)");
    }

    // Live-critical: after a compaction bumps the epoch and resets seqs, further local
    // appends continue correctly, and the epoch/next-seq reconstruct across a reopen.
    #[test]
    fn append_after_compaction_continues_and_survives_reopen() {
        let path = tmp("epochAppend");
        {
            let mut db = Db::open(&path, "AAA");
            db.scram_iterations = 4096;
            db.register("u0", "pw", None).unwrap();
            db.compact().unwrap(); // epoch 0 -> 1, seqs reset
            db.register("u1", "pw", None).unwrap();
            assert!(db.exists("u0") && db.exists("u1"));
        }
        let mut db = Db::open(&path, "AAA");
        db.scram_iterations = 4096;
        db.register("u2", "pw", None).unwrap();
        assert!(db.exists("u0") && db.exists("u1") && db.exists("u2"), "state survives compaction + reopen + append");
        assert_eq!(db.version_vector().get("AAA").map(|c| c.0), Some(1), "epoch stays 1 after one compaction (reopen doesn't re-bump)");
    }

    // Durability: a compaction whose snapshot has NO Global events (only channels)
    // must still persist the bumped epoch, or a restart resets it to 0 and later
    // writes diverge from peers.
    #[test]
    fn epoch_survives_restart_after_an_all_local_compaction() {
        let path = tmp("epochLocal");
        {
            let mut db = Db::open(&path, "AAA");
            db.scram_iterations = 4096;
            db.register_channel("#c", "founder").unwrap(); // Local only — no Global entry
            db.compact().unwrap(); // epoch 0 -> 1, all-Local snapshot
        }
        let mut db = Db::open(&path, "AAA");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap(); // first Global entry after restart
        assert_eq!(db.version_vector().get("AAA").map(|c| c.0), Some(1), "epoch recovered from Local entries, not reset to 0");
    }

    // The snapshot-epoch fix, part 2: an out-of-order relay WITHIN an epoch (a future
    // seq ahead of ours) is deferred — the version vector doesn't advance past the
    // gap — and the entries apply once the gap fills in order.
    #[test]
    fn out_of_order_within_an_epoch_is_deferred_then_fills() {
        let mut b = Db::open(tmp("epochOOO"), "BBB");
        b.ingest(akill("CCC", 0, 0, "*@a")).unwrap();
        assert_eq!(b.version_vector().get("CCC"), Some(&(0, 0)));
        // seq 2 before seq 1: dropped, version stays at (0,0).
        b.ingest(akill("CCC", 0, 2, "*@c")).unwrap();
        assert_eq!(b.version_vector().get("CCC"), Some(&(0, 0)), "a gap within the epoch is not applied");
        // seq 1 fills the gap, then the re-delivered seq 2 is contiguous.
        b.ingest(akill("CCC", 0, 1, "*@b")).unwrap();
        assert_eq!(b.version_vector().get("CCC"), Some(&(0, 1)));
        b.ingest(akill("CCC", 0, 2, "*@c")).unwrap();
        assert_eq!(b.version_vector().get("CCC"), Some(&(0, 2)), "the gap filled, seq 2 applies");
    }

    // The snapshot-epoch fix, part 3: a higher epoch is adopted ONLY from its seq 0,
    // so a relayed higher-epoch entry arriving before the snapshot's start is deferred.
    #[test]
    fn a_new_epoch_is_adopted_only_from_seq_zero() {
        let mut b = Db::open(tmp("epochNew"), "BBB");
        b.ingest(akill("CCC", 0, 0, "*@a")).unwrap();
        assert_eq!(b.version_vector().get("CCC"), Some(&(0, 0)));
        // Epoch 1 seq 3 arrives (relay ahead of the new snapshot's seq 0): deferred.
        b.ingest(akill("CCC", 1, 3, "*@x")).unwrap();
        assert_eq!(b.version_vector().get("CCC"), Some(&(0, 0)), "new epoch not adopted before its seq 0");
        // Its seq 0 arrives: adopt the new epoch (the compaction reset).
        b.ingest(akill("CCC", 1, 0, "*@y")).unwrap();
        assert_eq!(b.version_vector().get("CCC"), Some(&(1, 0)), "new epoch adopted from seq 0");
    }

    // Tier C: a node accepts a signed entry from a trusted origin, and rejects one
    // from an origin it doesn't trust — even if that origin signed it validly.
    #[test]
    fn gossip_signing_accepts_trusted_and_rejects_untrusted() {
        use super::sign::{self, Signing};
        use std::collections::HashMap;
        let (a_sec, a_pub) = sign::generate();
        let (b_sec, _) = sign::generate();
        let (c_sec, _) = sign::generate();

        let mut a = Db::open(tmp("signA"), "AAA");
        a.scram_iterations = 4096;
        a.set_gossip_signing(Signing::new(&a_sec, &HashMap::new()).unwrap());
        a.register("alice", "pw", None).unwrap();

        // B trusts A's public key (and its own, though unused here).
        let mut b = Db::open(tmp("signB"), "BBB");
        b.scram_iterations = 4096;
        b.set_gossip_signing(Signing::new(&b_sec, &HashMap::from([("AAA".to_string(), a_pub)])).unwrap());
        for entry in a.missing_for(&b.version_vector()) {
            b.ingest(entry).unwrap();
        }
        assert!(b.exists("alice"), "a signed entry from a trusted origin is accepted");

        // C signs validly with its own key, but B doesn't trust origin CCC.
        let mut c = Db::open(tmp("signC"), "CCC");
        c.scram_iterations = 4096;
        c.set_gossip_signing(Signing::new(&c_sec, &HashMap::new()).unwrap());
        c.register("mallory", "pw", None).unwrap();
        for entry in c.missing_for(&b.version_vector()) {
            b.ingest(entry).unwrap();
        }
        assert!(!b.exists("mallory"), "an entry from an untrusted origin is rejected");
    }

    // With signing off, the serialized log carries no `sig` field — byte-identical
    // to a pre-signing deployment (the compatibility guarantee).
    #[test]
    fn unsigned_entries_omit_the_sig_field() {
        let entry = LogEntry::for_test("A", 0, 1, Event::AccountDropped { account: "x".into() });
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"sig\""), "no sig field when unsigned: {json}");
    }

    // Channels register (case-insensitively unique), persist, and drop.
    #[test]
    fn channels_register_drop_and_persist() {
        let p = tmp("chan");
        let mut db = Db::open(&p, "local");
        db.register_channel("#Chat", "alice").unwrap();
        assert!(matches!(db.register_channel("#chat", "bob"), Err(ChanError::Exists)), "dup is case-insensitive");
        assert_eq!(db.channel("#CHAT").map(|c| c.founder.as_str()), Some("alice"));

        drop(db);
        let mut db = Db::open(&p, "local");
        assert_eq!(db.channel("#chat").map(|c| c.founder.as_str()), Some("alice"), "survives reopen");
        db.drop_channel("#chat").unwrap();
        assert!(db.channel("#chat").is_none());
        assert!(matches!(db.drop_channel("#chat"), Err(ChanError::NoChannel)));
    }

    // Mode lock persists, renders the applied string, and detects violations.
    #[test]
    fn mode_lock_persists_and_enforces() {
        let p = tmp("mlock");
        let mut db = Db::open(&p, "local");
        db.register_channel("#chan", "alice").unwrap();
        db.set_mlock("#chan", "nt", "s").unwrap();

        let info = db.channel("#chan").unwrap();
        assert_eq!(info.lock_modes(), "+rnt-s");
        assert_eq!(info.enforce("-nt"), Some("+nt".to_string())); // locked-on removed
        assert_eq!(info.enforce("+s"), Some("-s".to_string()));   // locked-off added
        assert_eq!(info.enforce("-r"), Some("+r".to_string()));   // +r always locked
        assert_eq!(info.enforce("+m"), None);                     // unrelated mode ignored

        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#chan").unwrap().lock_modes(), "+rnt-s", "survives reopen");
    }

    // A param mode lock (+f flood) carries its value through render, enforcement,
    // and a reopen — the Anope FLOOD/JOINFLOOD migration must not lose it.
    #[test]
    fn param_mode_lock_carries_its_value() {
        let p = tmp("mlock_param");
        let mut db = Db::open(&p, "local");
        db.register_channel("#chan", "alice").unwrap();
        db.set_mlock_params("#chan", "ntf", "", vec![('f', "mute:7:8s".to_string())]).unwrap();

        let info = db.channel("#chan").unwrap();
        assert_eq!(info.lock_modes(), "+rntf mute:7:8s");
        // Removing the locked param mode re-asserts it with its value.
        assert_eq!(info.enforce("-f"), Some("+f mute:7:8s".to_string()));

        drop(db);
        let db = Db::open(&p, "local");
        let info = db.channel("#chan").unwrap();
        assert_eq!(info.lock_params, vec![('f', "mute:7:8s".to_string())], "param survives reopen");
        assert_eq!(info.lock_modes(), "+rntf mute:7:8s");
    }

    // Access list drives join modes, is case-insensitive, and persists.
    #[test]
    fn access_list_grants_join_modes() {
        let p = tmp("access");
        let mut db = Db::open(&p, "local");
        db.register_channel("#c", "boss").unwrap();
        db.access_add("#c", "alice", "op").unwrap();
        db.access_add("#c", "bob", "voice").unwrap();

        let info = db.channel("#c").unwrap();
        assert_eq!(info.join_mode("boss"), Some("+qo")); // founder: owner + op
        assert_eq!(info.join_mode("ALICE"), Some("+o")); // op, case-insensitive
        assert_eq!(info.join_mode("bob"), Some("+v"));   // voice
        assert_eq!(info.join_mode("nobody"), None);

        assert!(db.access_del("#c", "alice").unwrap());
        assert!(!db.access_del("#c", "alice").unwrap());

        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#c").unwrap().join_mode("bob"), Some("+v"), "survives reopen");
        assert_eq!(db.channel("#c").unwrap().join_mode("alice"), None, "removal survives reopen");
    }

    // A jupe must survive a services restart — otherwise every juped server is
    // silently un-juped on restart and can relink.
    #[test]
    fn jupes_survive_a_restart() {
        let p = tmp("jupepersist");
        let sid = {
            let mut db = Db::open(&p, "N1");
            let sid = db.jupe_add("rogue.example", "abuse");
            assert_eq!(db.jupes().len(), 1, "juped while live");
            sid
        };
        let db = Db::open(&p, "N1");
        assert_eq!(db.jupes(), vec![("rogue.example".to_string(), sid, "abuse".to_string())], "the jupe replays from the log");
    }

    // StatServ / Stats-API counters are snapshotted to the log, so they survive a
    // restart instead of resetting to zero.
    #[test]
    fn stat_counters_survive_a_restart() {
        let p = tmp("statspersist");
        let counters: std::collections::BTreeMap<String, u64> =
            [("chanserv.register".to_string(), 7u64), ("nickserv.identify".to_string(), 42u64)].into_iter().collect();
        let chans = vec![("#devs".to_string(), 6u64, vec![("reverse".to_string(), 5u64), ("Keiko".to_string(), 1u64)])];
        {
            let mut db = Db::open(&p, "N1");
            db.persist_stats(&counters, chans.clone()).unwrap();
            assert_eq!(db.persisted_stats(), counters, "stored while live");
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.persisted_stats(), counters, "counters replay from the log after a restart");
        assert_eq!(db.persisted_chan_stats(), chans, "per-channel activity replays too");
    }

    #[test]
    fn incidents_survive_a_restart() {
        let p = tmp("incpersist");
        let incidents = vec![
            ("i1".to_string(), 1000u64, "[REGISTER] baddie tried a look-alike nick".to_string()),
            ("i2".to_string(), 1001u64, "kicked spammer from #chan".to_string()),
        ];
        {
            let mut db = Db::open(&p, "N1");
            db.persist_incidents(9, incidents.clone()).unwrap();
            assert_eq!(db.persisted_incidents(), (9, incidents.clone()), "stored while live");
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.persisted_incidents(), (9, incidents), "incidents replay from the log after a restart");
    }

    // Fold parity: the live state after a broad sequence of writes must equal the
    // state rebuilt by replaying the same log — every event's manual live mutation
    // has to match its `apply()` arm, or a restart silently changes the data.
    // A canonical Debug snapshot of every persisted collection, sorted so the
    // string is order-independent. Shared by the fold-parity and compaction tests.
    fn broad_snapshot(db: &Db) -> String {
        let mut a: Vec<_> = db.accounts().cloned().collect();
        a.sort_by(|x, y| x.name.cmp(&y.name));
        let mut c: Vec<_> = db.channels().cloned().collect();
        c.sort_by(|x, y| x.name.cmp(&y.name));
        let mut b: Vec<_> = db.bots().cloned().collect();
        b.sort_by(|x, y| x.nick.cmp(&y.nick));
        let mut gn = db.groups();
        gn.sort();
        let gv: Vec<_> = gn.iter().filter_map(|n| db.group(n)).collect();
        let mut ak = db.akills();
        ak.sort_by(|x, y| x.mask.cmp(&y.mask));
        let mut fb = db.forbids();
        fb.sort_by(|x, y| x.mask.cmp(&y.mask));
        let mut of = db.vhost_offers().to_vec();
        of.sort();
        let mut vf = db.vhost_forbidden().to_vec();
        vf.sort();
        let mut jp = db.jupes();
        jp.sort();
        let mut nw = db.news(NewsKind::Logon);
        nw.extend(db.news(NewsKind::Oper));
        let rp = db.reports(false);
        let hp = db.help_tickets(false);
        let mut se = db.session_exceptions();
        se.sort();
        let mut op = db.opers_list();
        op.sort();
        let vt = db.vhost_template().map(str::to_string);
        format!("{a:?}\n{c:?}\n{b:?}\n{gv:?}\n{ak:?}\n{fb:?}\n{of:?}\n{vf:?}\n{jp:?}\n{nw:?}\n{rp:?}\n{hp:?}\n{se:?}\n{op:?}\n{vt:?}")
    }

    // Exercise ~45 event types, ending with a drop that must purge references.
    fn build_broad_state(db: &mut Db) {
        db.scram_iterations = 4096;
        db.register("alice", "pw", Some("a@x.io".into())).unwrap();
            db.register("bob", "pw", None).unwrap();
            db.register("carol", "pw", None).unwrap();
            db.register_channel("#chan", "bob").unwrap();
            db.register_channel("#other", "carol").unwrap();
            db.access_add("#chan", "alice", "op").unwrap();
            db.akick_add("#chan", "*!*@bad.host", "spam").unwrap();
            db.set_desc("#chan", "a place").unwrap();
            db.set_url("#chan", "https://x.io").unwrap();
            db.set_channel_email("#chan", "s@x.io").unwrap();
            db.set_mlock("#chan", "nt", "s").unwrap();
            db.set_channel_setting("#chan", ChanSetting::Private, true).unwrap();
            db.set_successor("#other", Some("alice")).unwrap();
            db.set_greet("alice", "hi there").unwrap();
            db.set_account_autoop("alice", false).unwrap();
            db.set_account_kill("alice", false).unwrap();
            db.set_account_hide_status("alice", true).unwrap();
            db.ajoin_add("alice", "#chan", "").unwrap();
            db.set_vhost("alice", "alice.vhost", "oper", None).unwrap();
            db.certfp_add("alice", "aabbccddeeff00112233445566778899").unwrap();
            db.suspend_account("bob", "oper", "bad", None).unwrap();
            db.memo_send("carol", "alice", "hello there", false).unwrap();
            db.group_register("!grp", "alice").unwrap();
            db.group_set_flags("!grp", "carol", "").unwrap();
            db.group_register("!other", "bob").unwrap();
            db.group_set_flags("!other", "alice", "").unwrap();
            db.akill_add(XlineKind::Gline, "*@evil", "oper", "spam", None).unwrap();
            db.forbid_add(ForbidKind::Nick, "bad*", "oper", "squat").unwrap();
            db.vhost_offer_add("cool.vhost").unwrap();
            db.vhost_forbid_add("(?i)admin").unwrap();
            db.set_vhost_template(Some("$account.users.example".into())).unwrap();
            db.jupe_add("rogue.server", "abuse");
            // Bots, entrymsg, noexpire, oper notes, news, reports, help, opers,
            // session exceptions — the rest of the event surface.
            db.bot_add("Botty", "bot", "serv.host", "Helper").unwrap();
            db.assign_bot("#chan", "Botty").unwrap();
            db.set_default_bot(Some("Botty")).unwrap();
            db.set_entrymsg("#chan", "welcome").unwrap();
            db.set_account_noexpire("bob", true).unwrap();
            db.set_channel_noexpire("#chan", true).unwrap();
            db.set_account_note("bob", Some("watch this one".into()));
            db.set_channel_note("#chan", Some("chan note".into()));
            db.set_email("carol", Some("c@x.io".into())).unwrap();
            db.news_add(NewsKind::Logon, "welcome all", "oper");
            db.news_add(NewsKind::Oper, "staff notice", "oper");
            let rid = db.report_file("carol", "carol.host", "bob", "spam").unwrap();
            db.report_close(rid);
            let hid = db.help_request("carol", "carol.host", "help me").unwrap();
            db.help_take(hid, "bob");
            db.oper_grant("carol", vec!["admin".into()], None);
            db.session_except_add("*@trusted.host", 10, "trusted");
        db.group_set_founder("!other", "carol").unwrap();
        // Removal / mutation events — where live-vs-apply asymmetries hide.
        db.set_vhost("bob", "bob.temp", "oper", None).unwrap();
        db.del_vhost("bob").unwrap();
        db.suspend_account("carol", "oper", "oops", None).unwrap();
        db.unsuspend_account("carol").unwrap();
        db.akill_add(XlineKind::Qline, "spam*", "oper", "nick", None).unwrap();
        db.akill_del(XlineKind::Qline, "spam*").unwrap();
        db.forbid_add(ForbidKind::Chan, "#evil*", "oper", "bad").unwrap();
        db.forbid_del(ForbidKind::Chan, "#evil*").unwrap();
        let nid = db.news_add(NewsKind::Logon, "temp notice", "oper");
        db.news_del(nid);
        db.certfp_add("bob", "1122334455667788990011223344556677889900").unwrap();
        db.certfp_del("bob", "1122334455667788990011223344556677889900").unwrap();
        db.access_add("#chan", "carol", "voice").unwrap();
        db.access_del("#chan", "carol").unwrap();
        db.group_set_flags("!other", "bob", "").unwrap();
        db.group_del_member("!other", "bob").unwrap();
        db.memo_read("carol", 0);
        // The compound one: dropping alice must purge her access, successorship
        // and group standing — identically in the live path and on replay.
        db.drop_account("alice").unwrap();
        db.drop_channel("#other").unwrap();
    }

    // Fold parity: live state after the sequence == state replayed from the log.
    #[test]
    fn live_state_matches_replay_after_a_broad_sequence() {
        let p = tmp("foldparity");
        let live = {
            let mut db = Db::open(&p, "N1");
            build_broad_state(&mut db);
            broad_snapshot(&db)
        };
        let replayed = broad_snapshot(&Db::open(&p, "N1"));
        assert_eq!(live, replayed, "live state must equal the state replayed from the log");
    }

    // Compaction parity: rewriting the log to a snapshot must not lose anything —
    // the state after compact()+reopen must equal the state before.
    #[test]
    fn compaction_preserves_all_state() {
        let p = tmp("compactparity");
        {
            let mut db = Db::open(&p, "N1");
            build_broad_state(&mut db);
        }
        let before = broad_snapshot(&Db::open(&p, "N1"));
        {
            let mut db = Db::open(&p, "N1");
            db.compact().unwrap();
        }
        let after = broad_snapshot(&Db::open(&p, "N1"));
        assert_eq!(before, after, "compaction must preserve every persisted field");
    }

    // Gossip convergence: a fresh peer that backfills a node's log via the version
    // vector must arrive at the same GLOBAL state (accounts + network bans + groups).
    // Channels/jupes are Local and deliberately don't replicate, so they're excluded.
    #[test]
    fn gossip_converges_global_state_to_a_peer() {
        let pa = tmp("gossipA");
        let mut a = Db::open(&pa, "N1");
        a.scram_iterations = 4096;
        a.register("alice", "pw", Some("a@x.io".into())).unwrap();
        a.register("bob", "pw", None).unwrap();
        a.set_greet("alice", "hi there").unwrap();
        a.set_account_kill("alice", false).unwrap();
        a.suspend_account("bob", "op", "bad", None).unwrap();
        a.akill_add(XlineKind::Gline, "*@evil", "op", "spam", None).unwrap();
        a.forbid_add(ForbidKind::Nick, "bad*", "op", "squat").unwrap();
        a.group_register("!g", "alice").unwrap();
        a.group_set_flags("!g", "bob", "").unwrap();

        let pb = tmp("gossipB");
        let mut b = Db::open(&pb, "N2");
        for entry in a.missing_for(&b.version_vector()) {
            b.ingest(entry).unwrap();
        }

        let gsnap = |db: &Db| {
            let mut ac: Vec<_> = db.accounts().cloned().collect();
            ac.sort_by(|x, y| x.name.cmp(&y.name));
            let mut ak = db.akills();
            ak.sort_by(|x, y| x.mask.cmp(&y.mask));
            let mut fb = db.forbids();
            fb.sort_by(|x, y| x.mask.cmp(&y.mask));
            let mut gn = db.groups();
            gn.sort();
            let gv: Vec<_> = gn.iter().filter_map(|n| db.group(n)).collect();
            format!("{ac:?}\n{ak:?}\n{fb:?}\n{gv:?}")
        };
        assert_eq!(gsnap(&a), gsnap(&b), "peer B must converge to A's global state");
    }

    // Dropping an account erases every reference to it — channel access and
    // successorship, group membership and foundership — so a later re-registration
    // of the same name can't inherit its standing. Holds live and after replay.
    #[test]
    fn dropping_an_account_purges_all_its_references() {
        let p = tmp("droppurge");
        let mut db = Db::open(&p, "local");
        db.scram_iterations = 4096;
        db.register("bob", "pw", None).unwrap();
        db.register("carol", "pw", None).unwrap();
        db.register("alice", "pw", None).unwrap();
        db.register_channel("#foo", "bob").unwrap();
        db.access_add("#foo", "alice", "op").unwrap();
        db.register_channel("#bar", "carol").unwrap();
        db.set_successor("#bar", Some("alice")).unwrap();
        db.group_register("!alicegrp", "alice").unwrap();
        db.group_register("!bobgrp", "bob").unwrap();
        db.group_set_flags("!bobgrp", "alice", "").unwrap();

        // Sanity: every reference is in place.
        assert_eq!(db.channel("#foo").unwrap().join_mode("alice"), Some("+o"), "alice starts as an op");
        assert_eq!(db.channel_successor("#bar").as_deref(), Some("alice"));
        assert!(db.group("!bobgrp").unwrap().members.iter().any(|m| m.account.eq_ignore_ascii_case("alice")));
        assert!(db.group("!alicegrp").is_some());

        // Dropping alice erases all of them.
        assert!(db.drop_account("alice").unwrap());
        assert_eq!(db.channel("#foo").unwrap().join_mode("alice"), None, "access grant purged");
        assert_eq!(db.channel_successor("#bar"), None, "successorship purged");
        assert!(!db.group("!bobgrp").unwrap().members.iter().any(|m| m.account.eq_ignore_ascii_case("alice")), "group membership purged");
        assert!(db.group("!alicegrp").is_none(), "founderless group dropped");

        // Re-registering the name must not inherit the old op access.
        db.register("alice", "pw2", None).unwrap();
        assert_eq!(db.channel("#foo").unwrap().join_mode("alice"), None, "re-registration inherits nothing");

        // And the purge survives a reload (the fold matches live state).
        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#foo").unwrap().join_mode("alice"), None, "purge holds after replay");
        assert_eq!(db.channel_successor("#bar"), None, "successor purge holds after replay");
    }

    #[test]
    fn caps_kicker_triggers_on_ratio_not_uppercase_count() {
        let k = KickerSettings { caps: true, ..Default::default() };
        // 9 uppercase in an 18-char line is ~50% caps and over the length floor —
        // it must trip even though the uppercase count is below caps_min (a prior
        // `upper >= min` bug let it slip through).
        assert_eq!(k.violation("AAAAAAAAA hi there"), Some("Turn caps lock off!"));
        // A short or low-ratio line still doesn't trip.
        assert_eq!(k.violation("Hello there"), None);
        assert_eq!(k.violation("YO"), None, "too short for the length floor");
    }
