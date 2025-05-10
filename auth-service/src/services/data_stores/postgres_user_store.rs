use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};

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
    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
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
            Err(_) => Err(UserStoreError::InvalidCredentials),
        }
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
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

    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Hash the password
        let password_hash = compute_password_hash(user.password.as_ref().to_string())
            .await
            .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;
        
        let query = sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref(),
            password_hash,  // Store the hash, not the raw password
            user.requires_2fa,
        );

        query.execute(&self.pool).await.map_err(|e| UserStoreError::UnexpectedError(e.into()))?;
        Ok(())
    }
}

#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<()> { // Changed!
    let current_span: tracing::Span = tracing::Span::current();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let expected_password_hash: PasswordHash<'_> =
                PasswordHash::new(&expected_password_hash)?;

            Argon2::default()
                .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                .wrap_err("failed to verify password hash")
        })
    })
    .await;

    result?
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: String) -> Result<String> { // Changed!
    let current_span: tracing::Span = tracing::Span::current();

    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(password_hash)
            // Err(eyre!("oh no!")) // New!
        })
    })
    .await;

    result?
}