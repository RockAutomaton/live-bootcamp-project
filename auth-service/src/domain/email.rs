use validator::validate_email;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Email(String);

impl Email {
    /// Parses a string slice into an `Email`.
    ///
    /// Returns `Ok(Email)` if the string is a valid email address,
    /// and `Err(&'static str)` otherwise.
    pub fn parse(email_string: &str) -> Result<(), &'static str> {
        if email_string.is_empty() {
            return Err("Email cannot be empty.");
        }

        if !email_string.contains('@') {
            return Err("Email must contain an '@' symbol.");
        }

        if !validate_email(email_string) {
            return Err("Invalid email format.");   
        }

        Ok(())
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
        assert_eq!(Email::parse(email), Ok(()));
    }

    #[test]
    fn test_parse_empty_email() {
        let email = "";
        assert_eq!(Email::parse(email), Err("Email cannot be empty."));
    }

    #[test]
    fn test_parse_email_without_at_symbol() {
        let email = "testexample.com";
        assert_eq!(Email::parse(email), Err("Email must contain an '@' symbol."));
    }

    #[test]
    fn test_parse_invalid_email_format() {
        let email = "test@";
        assert_eq!(Email::parse(email), Err("Invalid email format."));
    }

    #[test]
    fn test_parse_invalid_email_with_spaces() {
        let email = "test user@example.com";
        assert_eq!(Email::parse(email), Err("Invalid email format."));
    }

    #[test]
    fn test_parse_complex_valid_email() {
        let email = "test.user+tag-123@sub.example.com";
        assert_eq!(Email::parse(email), Ok(()));
    }

    #[test]
    fn test_as_ref() {
        let email_str = "test@example.com";
        let email = Email(email_str.to_string());
        assert_eq!(email.as_ref(), email_str);
    }
}
