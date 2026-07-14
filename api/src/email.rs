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

pub fn reset(brand: &str, accent: &str, logo: &str, account: &str, code: &str) -> Mail {
    Mail {
        subject: format!("Password reset for {account}"),
        text: format!(
            "Your password reset code for {account} is: {code}\nIt expires in 15 minutes.\nReset with:\n  /msg NickServ RESETPASS {account} {code} <newpassword>\n"
        ),
        html: render(
            brand,
            accent,
            logo,
            "Password reset",
            &format!("Use this code to reset the password for your account {account}."),
            code,
            "This code expires in 15 minutes. If you didn't ask to reset it, ignore this email.",
        ),
    }
}

pub fn confirm(brand: &str, accent: &str, logo: &str, account: &str, code: &str) -> Mail {
    Mail {
        subject: format!("Confirm your {account} registration"),
        text: format!(
            "Confirm your account {account} with:\n  /msg NickServ CONFIRM {code}\nThe code expires in 15 minutes.\n"
        ),
        html: render(
            brand,
            accent,
            logo,
            "Confirm your account",
            &format!("Welcome! Confirm the email for your account {account} with the code below."),
            code,
            "This code expires in 15 minutes.",
        ),
    }
}

// Warn the owner of an account or channel that inactivity will soon expire it.
// `kind` is "account" or "channel", `remaining` a human span ("7 days"). The
// remaining span takes the prominent code slot.
pub fn expiry_warning(brand: &str, accent: &str, logo: &str, kind: &str, name: &str, remaining: &str) -> Mail {
    let keep = if kind == "channel" {
        "To keep it, have a member join the channel before then. Otherwise it will be removed."
    } else {
        "To keep it, just identify to it before then. Otherwise it will be removed."
    };
    Mail {
        subject: format!("Your {kind} {name} is about to expire"),
        text: format!(
            "Your {kind} {name} has been inactive and will expire in {remaining}.\n{keep}\n"
        ),
        html: render(
            brand,
            accent,
            logo,
            "About to expire",
            &format!("Your {kind} {name} has been inactive and will expire in {remaining}."),
            remaining,
            keep,
        ),
    }
}

// Escape the few characters that matter inside HTML text so a value can't break
// out of the template.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
