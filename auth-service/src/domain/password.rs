use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)] // Updated!
pub struct Password(pub Secret<String>);

impl Password {
    /// Parses a string slice into a `Password`.
    ///
    /// Returns `Ok(Password)` if the string is a valid password,
    /// and `Err(&'static str)` otherwise.
    pub fn parse(s: Secret<String>) -> Result<Password> {
        // Length check
        if s.expose_secret().len() < 8 {
            return Err(eyre!("Password must be at least 8 characters long."));
        }

        // Check for uppercase
        if !s.expose_secret().chars().any(|c| c.is_uppercase()) {
            return Err(eyre!("Password must contain at least one uppercase letter."));
        }

        // Check for lowercase
        if !s.expose_secret().chars().any(|c| c.is_lowercase()) {
            return Err(eyre!("Password must contain at least one lowercase letter."));
        }

        // Check for digit
        if !s.expose_secret().chars().any(|c| c.is_numeric()) {
            return Err(eyre!("Password must contain at least one digit."));
        }

        // Check for special character
        if !s.expose_secret().chars().any(|c| !c.is_alphanumeric()) {
            return Err(eyre!("Password must contain at least one special character."));
        }

        Ok(Password(s))
    }
}

impl AsRef<Secret<String>> for Password { // Updated!
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl PartialEq for Password { // New!
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the secret in a
        // controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

#[cfg(test)]
mod tests {
    use super::Password;

    use secrecy::Secret; // New!

    #[test]
    fn empty_string_is_rejected() {
        let password = Secret::new("".to_string()); // Updated!
        assert!(Password::parse(password).is_err());
    }
    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = Secret::new("1234567".to_string()); // Updated!
        assert!(Password::parse(password).is_err());
    }

    #[test]
    fn test_valid_password() {
        let result = Password::parse(Secret::new("Password123!".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_too_short() {
        let result = Password::parse(Secret::new("Abc12!".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_password_no_uppercase() {
        let result = Password::parse(Secret::new("password123!".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_password_no_lowercase() {
        let result = Password::parse(Secret::new("PASSWORD123!".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_password_no_digit() {
        let result = Password::parse(Secret::new("PasswordAbc!".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_password_no_special_char() {
        let result = Password::parse(Secret::new("Password123".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_password_edge_case_exactly_eight_chars() {
        let result = Password::parse(Secret::new("Passw1!d".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_with_spaces() {
        let result = Password::parse(Secret::new("Password 123!".to_string()));
        assert!(result.is_ok());
    }
}
