// Password policy for REGISTER and SET PASSWORD. Anope enforces a minimum
// length and forbids the password matching the nick; we do the same, plus an
// upper bound so a huge password can't be used to burn CPU in the key
// derivation. Length is measured in characters, the cap in bytes (what the
// hasher actually processes).

pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_PASSWORD_BYTES: usize = 300;

// Validate a new password for the account/nick it will protect. On rejection,
// returns the message to show the user.
pub fn validate_password(password: &str, owner: &str) -> Result<(), &'static str> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err("That password is too short — please use at least 8 characters.");
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("That password is too long.");
    }
    if password.eq_ignore_ascii_case(owner) {
        return Err("Your password can't be the same as your nick. Please choose another.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_reasonable_password() {
        assert!(validate_password("correct horse", "alice").is_ok());
    }

    #[test]
    fn rejects_short_password() {
        assert!(validate_password("short", "alice").is_err());
        assert!(validate_password("1234567", "alice").is_err()); // 7 chars
        assert!(validate_password("12345678", "alice").is_ok()); // 8 chars
    }

    #[test]
    fn rejects_password_equal_to_nick() {
        assert!(validate_password("Password", "password").is_err()); // case-insensitive
    }

    #[test]
    fn rejects_overlong_password() {
        assert!(validate_password(&"x".repeat(MAX_PASSWORD_BYTES + 1), "alice").is_err());
    }
}
