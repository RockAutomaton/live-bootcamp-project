use std::sync::Arc;

use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use color_eyre::eyre::Context;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Add Code", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        // TODO:
        // 1. Create a new key using the get_key helper function.
        // 2. Create a TwoFATuple instance.
        // 3. Use serde_json::to_string to serialize the TwoFATuple instance into a JSON string. 
        // Return TwoFACodeStoreError::UnexpectedError if serialization fails.
        // 4. Call the set_ex command on the Redis connection to set a new key/value pair with an expiration time (TTL). 
        // The value should be the serialized 2FA tuple.
        // The expiration time should be set to TEN_MINUTES_IN_SECONDS.
        // Return TwoFACodeStoreError::UnexpectedError if casting fails or the call to set_ex fails.

        let key = get_key(&email);
        let two_fa_tuple = TwoFATuple(login_attempt_id.as_ref().to_string(), code.as_ref().to_string());
        let serialized = serde_json::to_string(&two_fa_tuple).map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;

        let _: () = self.conn.write().await.set_ex(key, serialized, TEN_MINUTES_IN_SECONDS).map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        Ok(())
    }

    #[tracing::instrument(name = "Remove Code", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {

        let key = get_key(&email);
        let _: () = self.conn.write().await.del(key).map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        Ok(())
    }

    #[tracing::instrument(name = "Get Code", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {

        let key = get_key(&email);
        let mut conn = self.conn.write().await;
        let value: String = conn.get(&key).map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;
        let two_fa_tuple: TwoFATuple = serde_json::from_str(&value).map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        let login_attempt_id = LoginAttemptId::parse(two_fa_tuple.0).map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        let two_fa_code = TwoFACode::parse(two_fa_tuple.1).map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        Ok((login_attempt_id, two_fa_code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}