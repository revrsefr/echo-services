// Email content: renders the HTML templates in ../templates/email and pairs each
// with a plaintext fallback. The link layer sends both as multipart/alternative.

pub struct Mail {
    pub subject: String,
    pub text: String,
    pub html: String,
}

const BASE: &str = include_str!("../templates/email/base.html");

// The masthead: a logo image beside the brand name when a logo URL is set,
// otherwise the brand name as an accent eyebrow.
fn brand_mark(brand: &str, accent: &str, logo: &str) -> String {
    let (brand, accent) = (escape(brand), escape(accent));
    if logo.is_empty() {
        format!("<span style=\"font-size:12px;font-weight:700;letter-spacing:1.6px;text-transform:uppercase;color:{accent};\">{brand}</span>")
    } else {
        format!(
            "<img src=\"{}\" width=\"40\" height=\"40\" alt=\"\" style=\"display:inline-block;border-radius:9px;vertical-align:middle;\"><span style=\"display:inline-block;margin-left:12px;vertical-align:middle;font-size:18px;font-weight:800;letter-spacing:.2px;color:#0f172a;\">{brand}</span>",
            escape(logo)
        )
    }
}

fn render(brand: &str, accent: &str, logo: &str, title: &str, message: &str, code: &str, note: &str) -> String {
    BASE.replace("{{brand_mark}}", &brand_mark(brand, accent, logo))
        .replace("{{brand}}", &escape(brand))
        .replace("{{accent}}", &escape(accent))
        .replace("{{title}}", &escape(title))
        .replace("{{message}}", &escape(message))
        .replace("{{code}}", &escape(code))
        .replace("{{note}}", &escape(note))
}

pub fn reset(brand: &str, accent: &str, logo: &str, account: &str, code: &str, lang: &str) -> Mail {
    let acc = || vec![("account", account.to_string())];
    Mail {
        subject: crate::render(lang, "Password reset for {account}", &acc()),
        text: crate::render(
            lang,
            "Your password reset code for {account} is: {code}\nIt expires in 15 minutes.\nReset with:\n  /msg NickServ RESETPASS {account} {code} <newpassword>\n",
            &[("account", account.to_string()), ("code", code.to_string())],
        ),
        html: render(
            brand,
            accent,
            logo,
            &crate::render(lang, "Password reset", &[]),
            &crate::render(lang, "Use this code to reset the password for your account {account}.", &acc()),
            code,
            &crate::render(lang, "This code expires in 15 minutes. If you didn't ask to reset it, ignore this email.", &[]),
        ),
    }
}

pub fn confirm(brand: &str, accent: &str, logo: &str, account: &str, code: &str, lang: &str) -> Mail {
    let acc = || vec![("account", account.to_string())];
    Mail {
        subject: crate::render(lang, "Confirm your {account} registration", &acc()),
        text: crate::render(
            lang,
            "Confirm your account {account} with:\n  /msg NickServ CONFIRM {code}\nThe code expires in 15 minutes.\n",
            &[("account", account.to_string()), ("code", code.to_string())],
        ),
        html: render(
            brand,
            accent,
            logo,
            &crate::render(lang, "Confirm your account", &[]),
            &crate::render(lang, "Welcome! Confirm the email for your account {account} with the code below.", &acc()),
            code,
            &crate::render(lang, "This code expires in 15 minutes.", &[]),
        ),
    }
}

/// What an inactivity-expiry warning is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryTarget {
    Account,
    Channel,
}

impl ExpiryTarget {
    fn word(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Channel => "channel",
        }
    }
}

// Warn the owner of an account or channel that inactivity will soon expire it.
// `remaining` is a human span ("7 days") and takes the prominent code slot.
pub fn expiry_warning(brand: &str, accent: &str, logo: &str, kind: ExpiryTarget, name: &str, remaining: &str, lang: &str) -> Mail {
    let word = crate::render(lang, kind.word(), &[]);
    let keep = crate::render(
        lang,
        if kind == ExpiryTarget::Channel {
            "To keep it, have a member join the channel before then. Otherwise it will be removed."
        } else {
            "To keep it, just identify to it before then. Otherwise it will be removed."
        },
        &[],
    );
    let base = || {
        vec![
            ("word", word.clone()),
            ("name", name.to_string()),
            ("remaining", remaining.to_string()),
        ]
    };
    Mail {
        subject: crate::render(lang, "Your {word} {name} is about to expire", &[("word", word.clone()), ("name", name.to_string())]),
        text: crate::render(
            lang,
            "Your {word} {name} has been inactive and will expire in {remaining}.\n{keep}\n",
            &[("word", word.clone()), ("name", name.to_string()), ("remaining", remaining.to_string()), ("keep", keep.clone())],
        ),
        html: render(
            brand,
            accent,
            logo,
            &crate::render(lang, "About to expire", &[]),
            &crate::render(lang, "Your {word} {name} has been inactive and will expire in {remaining}.", &base()),
            remaining,
            &keep,
        ),
    }
}

// Escape the few characters that matter inside HTML text so a value can't break
// out of the template.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
