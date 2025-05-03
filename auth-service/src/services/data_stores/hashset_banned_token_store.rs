use std::collections::HashSet;

use crate::domain::data_stores::*;

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    banned_tokens: HashSet<String>
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.banned_tokens.insert(token);
        Ok(())
    }

    async fn check_banned_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>{
        Ok(self.banned_tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreError};

    #[tokio::test]
    async fn test_store_token_success() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "token123".to_string();
        let result = store.store_token(token.clone()).await;
        assert!(result.is_ok());
        assert!(store.banned_tokens.contains(&token));
    }

    #[tokio::test]
    async fn test_check_banned_token_not_banned() {
        let store = HashsetBannedTokenStore::default();
        let token = "token123".to_string();
        let result = store.check_banned_token(&token).await;
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_check_banned_token_banned() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "token123".to_string();
        let _ = store.store_token(token.clone()).await;
        let result = store.check_banned_token(&token).await;
        assert_eq!(result.unwrap(), true);
    }
}