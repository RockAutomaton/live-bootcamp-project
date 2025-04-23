#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Token(pub String);

impl Token {
    /// Parses a string slice into a `Token`.
    ///
    /// Returns `Ok(Token)` if the string is a valid token,
    /// and `Err(&'static str)` otherwise.
    pub fn parse(token: &str) -> Result<Token, &'static str> {
        if token.trim().is_empty() {
            return Err("Token cannot be empty")
        }
        Ok(Token(token.to_string()))
    }
    


}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}