use std::collections::HashSet;

use crate::domain::data_stores::*;

#[derive(Default)]
struct HashsetBannedTokenStore {
    banned_tokens: HashSet<String>
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let inserted = self.banned_tokens.insert(token);
        if inserted {
            Ok(())
        } else {
            Err(BannedTokenStoreError::UnexpectedError)
        }
    }

    async fn check_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>{
        if self.banned_tokens.contains(&token) { 
            return Err(BannedTokenStoreError::BannedTokenError);
        }

        Ok(())
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
    async fn test_store_token_duplicate() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "token123".to_string();
        let _ = store.store_token(token.clone()).await;
        let result = store.store_token(token.clone()).await;
        assert!(matches!(result, Err(BannedTokenStoreError::UnexpectedError)));
    }

    #[tokio::test]
    async fn test_check_banned_token_not_banned() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "token123".to_string();
        let result = store.check_banned_token(token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_banned_token_banned() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "token123".to_string();
        let _ = store.store_token(token.clone()).await;
        let result = store.check_banned_token(token.clone()).await;
        assert!(matches!(result, Err(BannedTokenStoreError::BannedTokenError)));
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let mut store = HashsetBannedTokenStore::default();
        let tokens = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        for token in &tokens {
            assert!(store.store_token(token.clone()).await.is_ok());
        }
        for token in &tokens {
            assert!(matches!(
                store.check_banned_token(token.clone()).await,
                Err(BannedTokenStoreError::BannedTokenError)
            ));
        }
        let not_banned = "not_banned".to_string();
        assert!(store.check_banned_token(not_banned).await.is_ok());
    }
}