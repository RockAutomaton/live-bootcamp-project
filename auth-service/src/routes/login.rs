use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::*};
use crate::domain::AuthAPIError;

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    

    let email = match Email::parse(&request.email) {
        Ok(email) => email,
        Err(_) => return Err(AuthAPIError::InvalidCredentials),
    };

    let password= match Password::parse(&request.password) {
        Ok(password) => password,
        Err(_) => return Err(AuthAPIError::InvalidCredentials)
    };

    let user_store = &state.user_store.read().await;

    let valid_user = match user_store.validate_user(&email, &password).await{
        Ok(()) => {},
        Err(_) => return Err(AuthAPIError::IncorrectCredentials)
    };

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return Err(AuthAPIError::IncorrectCredentials)
    };

    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LoginResponse {
    pub message: String,
}