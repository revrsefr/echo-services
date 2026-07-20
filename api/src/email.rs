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

#[allow(clippy::too_many_arguments)]
fn render(brand: &str, accent: &str, logo: &str, title: &str, message: &str, code: &str, note: &str, button: &str) -> String {
    // `message` carries the account name (attacker-influenceable). Substitute every
    // OTHER slot first and `{{message}}` LAST, so a message that literally contains
    // `{{code}}`/`{{note}}` (an account named that) is inserted verbatim rather than
    // splicing in the real code. `button` is trusted markup built below, not escaped.
    BASE.replace("{{brand_mark}}", &brand_mark(brand, accent, logo))
        .replace("{{brand}}", &escape(brand))
        .replace("{{accent}}", &escape(accent))
        .replace("{{title}}", &escape(title))
        .replace("{{code}}", &escape(code))
        .replace("{{note}}", &escape(note))
        .replace("{{button}}", button)
        .replace("{{message}}", &escape(message))
}

// Percent-encode a URL query value (RFC 3986 unreserved set passes through).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// A one-click call-to-action button for the HTML email.
fn action_button(accent: &str, url: &str, label: &str) -> String {
    format!(
        "<tr><td align=\"center\" style=\"padding:22px 36px 0;\"><a href=\"{}\" style=\"display:inline-block;background:{};color:#ffffff;font-size:15px;font-weight:700;text-decoration:none;padding:14px 34px;border-radius:11px;\">{}</a></td></tr>",
        escape(url),
        escape(accent),
        escape(label),
    )
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
            "",
        ),
    }
}

pub fn confirm(brand: &str, accent: &str, logo: &str, account: &str, code: &str, confirm_url: &str, lang: &str) -> Mail {
    let acc = || vec![("account", account.to_string())];
    // A one-click confirm link when a web endpoint is configured, else code-only.
    let link = if confirm_url.is_empty() {
        String::new()
    } else {
        format!("{}?account={}&code={}", confirm_url.trim_end_matches('/'), percent_encode(account), percent_encode(code))
    };
    let mut text = crate::render(
        lang,
        "Confirm your account {account} with:\n  /msg NickServ CONFIRM {code}\nThe code expires in 15 minutes.\n",
        &[("account", account.to_string()), ("code", code.to_string())],
    );
    if !link.is_empty() {
        text.push_str(&crate::render(lang, "Or confirm in one click: {link}", &[("link", link.clone())]));
        text.push('\n');
    }
    let button = if link.is_empty() {
        String::new()
    } else {
        action_button(accent, &link, &crate::render(lang, "Confirm now", &[]))
    };
    Mail {
        subject: crate::render(lang, "Confirm your {account} registration", &acc()),
        text,
        html: render(
            brand,
            accent,
            logo,
            &crate::render(lang, "Confirm your account", &[]),
            &crate::render(lang, "Welcome! Confirm the email for your account {account} with the code below.", &acc()),
            code,
            &crate::render(lang, "This code expires in 15 minutes.", &[]),
            &button,
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
            "",
        ),
    }
}

// Escape the few characters that matter inside HTML text so a value can't break
// out of the template.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_link_present_only_when_url_set() {
        let with = confirm("Brand", "#000000", "", "alice", "ABC123", "https://x.net/confirm", "en");
        assert!(with.text.contains("https://x.net/confirm?account=alice&code=ABC123"), "text link: {}", with.text);
        assert!(with.html.contains("href=\"https://x.net/confirm?account=alice&amp;code=ABC123\""), "html button href escaped");
        assert!(with.html.contains("Confirm now"), "button label");

        let none = confirm("Brand", "#000000", "", "alice", "ABC123", "", "en");
        assert!(!none.text.contains("one click"), "no link line: {}", none.text);
        assert!(!none.html.contains("Confirm now"), "no button");
    }

    #[test]
    fn confirm_link_percent_encodes_the_account() {
        let m = confirm("B", "#000000", "", "a[b", "K", "https://x/confirm", "en");
        assert!(m.text.contains("account=a%5Bb&code=K"), "encoded account: {}", m.text);
    }

    #[test]
    fn confirm_url_trailing_slash_is_trimmed() {
        let m = confirm("B", "#000000", "", "z", "K", "https://x/confirm/", "en");
        assert!(m.text.contains("https://x/confirm?account=z"), "trimmed: {}", m.text);
    }
}
