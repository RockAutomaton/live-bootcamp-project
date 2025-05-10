use std::collections::HashMap;
use secrecy::Secret;
use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some(code) => Ok(code.clone()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::email::Email;

    #[tokio::test]
    async fn test_add_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("test@email.net".to_string())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let stored_code = store.get_code(&email).await.unwrap();
        assert_eq!(stored_code.0, login_attempt_id);
        assert_eq!(stored_code.1, code);
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("remove@email.net".to_string())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("654321".to_string()).unwrap();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        store.remove_code(&email).await.unwrap();
        let result = store.get_code(&email).await;
        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn test_get_code_nonexistent_email() {
        let store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("nonexistent@email.net".to_string())).unwrap();
        let result = store.get_code(&email).await;
        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn test_overwrite_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("overwrite@email.net".to_string())).unwrap();
        let login_attempt_id1 = LoginAttemptId::default();
        let code1 = TwoFACode::parse("111111".to_string()).unwrap();
        store
            .add_code(email.clone(), login_attempt_id1.clone(), code1.clone())
            .await
            .unwrap();

        let login_attempt_id2 = LoginAttemptId::default();
        let code2 = TwoFACode::parse("222222".to_string()).unwrap();
        store
            .add_code(email.clone(), login_attempt_id2.clone(), code2.clone())
            .await
            .unwrap();

        let stored_code = store.get_code(&email).await.unwrap();
        assert_eq!(stored_code.0, login_attempt_id2);
        assert_eq!(stored_code.1, code2);
    }

    #[tokio::test]
    async fn test_remove_code_nonexistent_email() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("doesnotexist@email.net".to_string())).unwrap();
        // Should not error even if email does not exist
        let result = store.remove_code(&email).await;
        assert!(result.is_ok());
    }
}