use std::sync::Arc;
use color_eyre::eyre::{eyre, Result};
use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};
use secrecy::{ExposeSecret, Secret};
pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    #[tracing::instrument(name = "Store Token", skip_all)]
    async fn store_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        // TODO:
        // 1. Create a new key using the get_key helper function.
        // 2. Call the set_ex command on the Redis connection to set a new key/value pair with an expiration time (TTL). 
        // The value should simply be a `true` (boolean value).
        // The expiration time should be set to TOKEN_TTL_SECONDS.
        // NOTE: The TTL is expected to be a u64 so you will have to cast TOKEN_TTL_SECONDS to a u64. 
        // Return BannedTokenStoreError::UnexpectedError if casting fails or the call to set_ex fails.

        let key = get_key(&token.expose_secret());
        let ttl = TOKEN_TTL_SECONDS as u64;
        let _: () = self.conn.write().await.set_ex(key, "true", ttl).map_err(|e| BannedTokenStoreError::UnexpectedError(e.into()))?;
        Ok(())
    }

    #[tracing::instrument(name = "Check Banned Token", skip_all)]
    async fn check_banned_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        // Check if the token exists by calling the exists method on the Redis connection
        let key = get_key(&token.expose_secret());
        let mut conn = self.conn.write().await;
        let exists: bool = conn.exists(key).map_err(|e| BannedTokenStoreError::UnexpectedError(e.into()))?;
        Ok(exists)
    }
}




// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}