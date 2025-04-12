use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::data_stores::UserStore;

// Type alias using the trait instead of concrete implementation
pub type UserStoreType = Arc<RwLock<dyn UserStore + Send + Sync>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
}

impl AppState {
    pub fn new(user_store: UserStoreType) -> Self {
        Self { user_store }
    }
}
