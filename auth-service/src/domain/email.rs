use validator::validate_email;
use color_eyre::eyre::{eyre, Result};
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Email(pub String);

impl Email {
    /// Parses a string slice into an `Email`.
    ///
    /// Returns `Ok(Email)` if the string is a valid email address,
    /// and `Err(&'static str)` otherwise.
    pub fn parse(email_string: &str) -> Result<Self> {
        if email_string.is_empty() {
            // return Err("Email cannot be empty.");
            return Err(eyre!("Email cannot be empty."));
        }

        if !email_string.contains('@') {
            // return Err("Email must contain an '@' symbol.");
            return Err(eyre!("Email must contain an '@' symbol."));
        }

        if !validate_email(email_string) {
            // return Err("Invalid email format.");   
            return Err(eyre!("Invalid email format."));
        }

        Ok(Email(email_string.to_string()))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_email() {
        let email = "test@example.com";
        assert!(Email::parse(email).is_ok());
    }

    #[test]
    fn test_parse_empty_email() {
        let email = "";
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn test_parse_email_without_at_symbol() {
        let email = "testexample.com";
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn test_parse_invalid_email_format() {
        let email = "test@";
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn test_parse_invalid_email_with_spaces() {
        let email = "test user@example.com";
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn test_parse_complex_valid_email() {
        let email = "test.user+tag-123@sub.example.com";
        assert!(Email::parse(email).is_ok());
    }

    #[test]
    fn test_as_ref() {
        let email_str = "test@example.com";
        let email = Email(email_str.to_string());
        assert_eq!(email.as_ref(), email_str);
    }
}
