use auth_service::{
    app_state::AppState, get_redis_client, services::data_stores::{
        postgres_user_store::PostgresUserStore, redis_banned_token_store::RedisBannedTokenStore, redis_two_fa_code_store::RedisTwoFACodeStore,
    }, utils::constants::{prod, REDIS_HOST_NAME}, Application
};
use auth_service::{
    get_postgres_pool, services::mock_email_client::MockEmailClient, utils::constants::DATABASE_URL,
};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;
    // let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    // let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::new(RwLock::new(configure_redis())))));
    // let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(Arc::new(RwLock::new(configure_redis())))));
    let email_client = Arc::new(RwLock::new(MockEmailClient));
    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}