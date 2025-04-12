use std::collections::HashMap;
use crate::domain::User;
use crate::domain::data_stores::*;



#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);

        Ok(())
    }

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(User {
                email: user.email.clone(),
                password: user.password.clone(),
                requires_2fa: user.requires_2fa,
            }),
            None => Err(UserStoreError::UserNotFound)
        }
    }
    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        // Check if user exists in the HashMap using the email
        match self.users.get(email) {
            // If user exists, check if password matches
            Some(user) => {
                if user.password == password {
                    Ok(()) // Password matches, return success
                } else {
                    Err(UserStoreError::InvalidCredentials) // Password doesn't match
                }
            },
            // If user doesn't exist
            None => Err(UserStoreError::UserNotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::User;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), true );

        // Test adding a new user
        let result = store.add_user(user.clone());
        assert!(result.await.is_ok());

        // Test adding the same user again should fail
        let result = store.add_user(user).await;
        assert_eq!(result, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), true );


        // Add a user first
        let _ = store.add_user(user.clone()).await;

        // Test getting an existing user
        let result = store.get_user("test@example.com").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().email, "test@example.com");

        // Test getting a non-existent user
        let result = store.get_user("nonexistent@example.com").await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: true
        };

        // Add a user first
        let _ = store.add_user(user).await;

        // Test with correct credentials
        let result = store.validate_user("test@example.com", "password123").await;
        assert!(result.is_ok());

        // Test with incorrect password
        let result = store.validate_user("test@example.com", "wrongpassword").await;
        assert_eq!(result, Err(UserStoreError::InvalidCredentials));

        // Test with non-existent user
        let result = store.validate_user("nonexistent@example.com", "password123").await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }
}