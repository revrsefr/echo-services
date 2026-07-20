use echo_api::{human_time, AuthThen, Store};
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

// IDENTIFY [account] <password>: log in. The account defaults to the current
// nick, so both the bare-password and account+password forms work.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (account_name, password) = match (args.get(1), args.get(2)) {
        (Some(account), Some(password)) => (*account, *password),
        (Some(password), None) => (from.nick, *password),
        _ => {
            ctx.notice(me, from.uid, "Syntax: IDENTIFY [account] <password>");
            return;
        }
    };
    let Some((account, verifier)) = precheck(me, from, "IDENTIFY", account_name, ctx, db) else {
        return;
    };
    // Already identified to this account: skip the (wasted) verify.
    if from.account == Some(account.as_str()) {
        ctx.notice(me, from.uid, t!(ctx, "You're already identified as \x02{account}\x02.", account = account));
        return;
    }
    ctx.defer_authenticate(
        verifier,
        password,
        AuthThen::Identify { uid: from.uid.to_string(), agent: me.to_string(), name: account_name.to_string(), account },
    );
}

// Shared validation for the password-login commands (IDENTIFY, LOGIN): the account
// must exist, not be suspended, not be throttled, and have a password verifier.
// Returns the (canonical account, verifier) for the deferred verify, or None after
// emitting the failure to `from`. `cmd` names the command in the FAIL/audit lines.
pub(crate) fn precheck(me: &str, from: &Sender, cmd: &str, account_name: &str, ctx: &mut ServiceCtx, db: &mut dyn Store) -> Option<(String, String)> {
    // Distinguish an unregistered account from a wrong password.
    if !db.exists(account_name) {
        ctx.fail(me, from.uid, cmd, "ACCOUNT_NOT_REGISTERED", t!(ctx, "\x02{account_name}\x02 isn't registered.", account_name = account_name));
        return None;
    }
    // A suspended account can't be logged into (checked before the password so it
    // doesn't reveal whether the password was right). Tell them who, when and why,
    // and when it lifts, so they know what happened and who to reach.
    if let Some(acc) = db.resolve_account(account_name).map(str::to_string) {
        if db.is_suspended(&acc) {
            if let Some(s) = db.suspension(&acc) {
                let mut msg = t!(ctx, "\x02{acc}\x02 is suspended, so you can't log in to it right now. It was suspended by \x02{by}\x02 on {when}", acc = acc, by = s.by, when = human_time(s.ts));
                if s.reason.trim().is_empty() {
                    msg.push('.');
                } else {
                    msg.push_str(&t!(ctx, " — reason: {reason}", reason = s.reason));
                }
                if let Some(exp) = s.expires {
                    msg.push_str(&t!(ctx, " The suspension is due to lift on {when}.", when = human_time(exp)));
                }
                msg.push_str(&t!(ctx, " If you think this is a mistake, please contact the network staff."));
                ctx.fail(me, from.uid, cmd, "ACCOUNT_SUSPENDED", msg);
            }
            return None;
        }
    }
    // Refuse while throttled, so a password can't be brute-forced.
    if let Some(secs) = db.auth_lockout(account_name) {
        ctx.fail(me, from.uid, cmd, "RATE_LIMITED", t!(ctx, "Too many failed attempts. Please wait {secs}s and try again.", secs = secs));
        return None;
    }
    // Fetch the verifier cheaply and hand the (~1s) PBKDF2 verify to the engine to
    // run off the reactor — never verify under the engine lock. The login finish
    // happens in Engine::complete_authenticate.
    match db.scram_verifier(account_name) {
        None => {
            // Exists but has no verifier (e.g. cert-only) — a password can't match.
            // Report it to the auth feed too, or probing a cert-only account is a
            // blind spot the deferred wrong-password path doesn't have.
            db.note_auth(account_name, false);
            ctx.count("nickserv.identify_fail");
            ctx.auth_report(false, Some(account_name), &format!("NickServ {cmd}"), from.uid, Some("no password set"));
            ctx.fail(me, from.uid, cmd, "INVALID_CREDENTIALS", "Invalid password. Please try again.");
            None
        }
        Some((account, verifier)) => Some((account, verifier)),
    }
}
