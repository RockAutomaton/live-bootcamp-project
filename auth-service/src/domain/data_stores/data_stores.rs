use uuid::Uuid;

use crate::domain::User;
use crate::domain::Password;
use crate::domain::Email;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn check_banned_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum BannedTokenStoreError {
    BannedTokenError,
    UnexpectedError,
}


// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        // Use the `parse_str` function from the `uuid` crate to ensure `id` is a valid UUID
        Uuid::parse_str(&id)
            .map_err(|_| "Invalid LoginAttemptId".to_string())
            .map(|_| LoginAttemptId(id))
    }
}

impl Default for LoginAttemptId { // Implementing Default for LoginAttemptId to generate a random UUID to use as a default value
    fn default() -> Self {
        // Use the `uuid` crate to generate a random version 4 UUID
        let uuid = Uuid::new_v4();
        let id = uuid.to_string();
        LoginAttemptId(id)
    }
}


impl AsRef<str> for LoginAttemptId { // Implementing AsRef<str> for LoginAttemptId to allow easy conversion to &str
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        // Ensure `code` is a valid 6-digit code
        if code.len() == 6 && code.chars().all(|c| c.is_digit(10)) { // Check if all characters are digits and length is 6
            Ok(TwoFACode(code))
        } else {
            Err("Invalid TwoFACode".to_string())
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        let code = rand::random::<u32>() % 1_000_000; // Generate a random number between 0 and 999999
        let code_str = format!("{:06}", code); // Format it as a 6-digit string
        TwoFACode(code_str) // Return the 6-digit code
    }
}

// Implementing AsRef<str> for TwoFACode to allow easy conversion to &str
impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}