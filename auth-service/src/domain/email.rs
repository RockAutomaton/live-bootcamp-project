use std::hash::Hash;
use validator::validate_email;
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)]
pub struct Email(pub Secret<String>);

impl Email {
    // Updated!
    pub fn parse(s: Secret<String>) -> Result<Email> {
        if validate_email(s.expose_secret()) {
            Ok(Self(s))
        } else {
            Err(eyre!(format!(
                "{} is not a valid email.",
                s.expose_secret()
            )))
        }
    }
}

// Updated!
impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_email() {
        let email = "test@example.com";
        assert!(Email::parse(Secret::new(email.to_string())).is_ok());
    }

    #[test]
    fn test_parse_empty_email() {
        let email = "";
        assert!(Email::parse(Secret::new(email.to_string())).is_err());
    }

    #[test]
    fn test_parse_email_without_at_symbol() {
        let email = "testexample.com";
        assert!(Email::parse(Secret::new(email.to_string())).is_err());
    }

    #[test]
    fn test_parse_invalid_email_format() {
        let email = "test@";
        assert!(Email::parse(Secret::new(email.to_string())).is_err());
    }

    #[test]
    fn test_parse_invalid_email_with_spaces() {
        let email = "test user@example.com";
        assert!(Email::parse(Secret::new(email.to_string())).is_err());
    }

    #[test]
    fn test_parse_complex_valid_email() {
        let email = "test.user+tag-123@sub.example.com";
        assert!(Email::parse(Secret::new(email.to_string())).is_ok());
    }

    #[test]
    fn test_as_ref() {
        let email_str = "test@example.com";
        let email = Email(Secret::new(email_str.to_string()));
        assert_eq!(email.as_ref().expose_secret(), email_str);
    }
}
