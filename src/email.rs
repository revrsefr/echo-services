// Email content: renders the HTML templates in ../templates/email and pairs each
// with a plaintext fallback. The link layer sends both as multipart/alternative.

pub struct Mail {
    pub subject: String,
    pub text: String,
    pub html: String,
}

const BASE: &str = include_str!("../templates/email/base.html");

fn render(brand: &str, accent: &str, title: &str, message: &str, code: &str, note: &str) -> String {
    BASE.replace("{{brand}}", &escape(brand))
        .replace("{{accent}}", &escape(accent))
        .replace("{{title}}", &escape(title))
        .replace("{{message}}", &escape(message))
        .replace("{{code}}", &escape(code))
        .replace("{{note}}", &escape(note))
}

pub fn reset(brand: &str, accent: &str, account: &str, code: &str) -> Mail {
    Mail {
        subject: format!("Password reset for {account}"),
        text: format!(
            "Your password reset code for {account} is: {code}\nIt expires in 15 minutes.\nReset with:\n  /msg NickServ RESETPASS {account} {code} <newpassword>\n"
        ),
        html: render(
            brand,
            accent,
            "Password reset",
            &format!("Use this code to reset the password for your account {account}."),
            code,
            "This code expires in 15 minutes. If you didn't ask to reset it, ignore this email.",
        ),
    }
}

pub fn confirm(brand: &str, accent: &str, account: &str, code: &str) -> Mail {
    Mail {
        subject: format!("Confirm your {account} registration"),
        text: format!(
            "Confirm your account {account} with:\n  /msg NickServ CONFIRM {code}\nThe code expires in 15 minutes.\n"
        ),
        html: render(
            brand,
            accent,
            "Confirm your account",
            &format!("Welcome! Confirm the email for your account {account} with the code below."),
            code,
            "This code expires in 15 minutes.",
        ),
    }
}

// Escape the few characters that matter inside HTML text so a value can't break
// out of the template.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
