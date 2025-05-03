use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use sqlx::PgPool;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User,
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        if self.get_user(email).await.is_err() {
            return Err(UserStoreError::UserNotFound);
        }
    
        let query = sqlx::query!(
            "SELECT password_hash FROM users WHERE email = $1",
            email.as_ref(),
        );
    
        let user = query.fetch_one(&self.pool).await.map_err(|_| UserStoreError::UserNotFound)?;
        
        // Verify the password
        match verify_password_hash(
            user.password_hash, 
            password.as_ref().to_string()
        ).await {
            Ok(_) => Ok(()),
            Err(_) => Err(UserStoreError::InvalidCredentials), // Return error, don't panic
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let query = sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref(),
        );

        let user = query.fetch_one(&self.pool).await.map_err(|_| UserStoreError::UserNotFound)?;

        Ok(User {
            email: Email::parse(&user.email).unwrap(),
            password: Password::parse(&user.password_hash).unwrap(), // Treating the stored value as a hash
            requires_2fa: user.requires_2fa,
        })
    }

    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Hash the password
        let password_hash = compute_password_hash(user.password.as_ref().to_string())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;
        
        let query = sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref(),
            password_hash,  // Store the hash, not the raw password
            user.requires_2fa,
        );

        query.execute(&self.pool).await.map_err(|_| UserStoreError::UnexpectedError)?;
        Ok(())
    }
}


async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let result = tokio::task::spawn_blocking(move || {
        let expected_password_hash = PasswordHash::new(&expected_password_hash)
            .map_err(|e| Box::<dyn Error + Send + Sync>::from(e.to_string()))?;
        
        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &expected_password_hash)
            .map_err(|e| Box::<dyn Error + Send + Sync>::from(e.to_string()))
    }).await
    .map_err(|e| Box::<dyn Error + Send + Sync>::from(e.to_string()))??;

    Ok(())
}

async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    let password_hash = tokio::task::spawn_blocking(move || {
        let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None)
                .map_err(|e| Box::<dyn Error + Send + Sync>::from(e.to_string())).unwrap()
        )
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Box::<dyn Error + Send + Sync>::from(e.to_string())).unwrap()
        .to_string()
    }).await.unwrap(); 

    Ok(password_hash)
}
