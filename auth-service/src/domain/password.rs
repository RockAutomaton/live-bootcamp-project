#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Password(String);

impl Password {
    /// Parses a string slice into a `Password`.
    ///
    /// Returns `Ok(Password)` if the string is a valid password,
    /// and `Err(&'static str)` otherwise.
    pub fn parse(password_string: &str) -> Result<(), &'static str> {
        // Length check
        if password_string.len() < 8 {
            return Err("Password must be at least 8 characters long.");
        }

        // Check for uppercase
        if !password_string.chars().any(|c| c.is_uppercase()) {
            return Err("Password must contain at least one uppercase letter.");
        }

        // Check for lowercase
        if !password_string.chars().any(|c| c.is_lowercase()) {
            return Err("Password must contain at least one lowercase letter.");
        }

        // Check for digit
        if !password_string.chars().any(|c| c.is_numeric()) {
            return Err("Password must contain at least one digit.");
        }

        // Check for special character
        if !password_string.chars().any(|c| !c.is_alphanumeric()) {
            return Err("Password must contain at least one special character.");
        }

        Ok(())
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_password() {
        let result = Password::parse("Password123!");
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_password_too_short() {
        let result = Password::parse("Abc12!");
        assert_eq!(result, Err("Password must be at least 8 characters long."));
    }

    #[test]
    fn test_password_no_uppercase() {
        let result = Password::parse("password123!");
        assert_eq!(result, Err("Password must contain at least one uppercase letter."));
    }

    #[test]
    fn test_password_no_lowercase() {
        let result = Password::parse("PASSWORD123!");
        assert_eq!(result, Err("Password must contain at least one lowercase letter."));
    }

    #[test]
    fn test_password_no_digit() {
        let result = Password::parse("PasswordAbc!");
        assert_eq!(result, Err("Password must contain at least one digit."));
    }

    #[test]
    fn test_password_no_special_char() {
        let result = Password::parse("Password123");
        assert_eq!(result, Err("Password must contain at least one special character."));
    }

    #[test]
    fn test_password_edge_case_exactly_eight_chars() {
        let result = Password::parse("Passw1!d");
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_password_with_spaces() {
        let result = Password::parse("Password 123!");
        assert_eq!(result, Ok(()));
    }
}
