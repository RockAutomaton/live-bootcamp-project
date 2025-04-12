use std::sync::Arc;

use crate::{app_state::AppState, domain::{user, AuthAPIError, User}};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

pub async fn signup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError>{
    // Create a new `User` instance using data in the `request`

    let email = request.email;
    let password = request.password;

    // Email validation: Check if it's empty or doesn't contain '@'
    if email.is_empty() || !email.contains('@') {
        return Err(AuthAPIError::InvalidCredentials);
    }

    // Password validation: Check if it's less than 8 characters
    if password.len() < 8 {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;
    
    match user_store.get_user(&user.email) {
        Ok(user) => return Err(AuthAPIError::UserAlreadyExists),
        Err(_) => {} // User doesn't exist, continue with signup
    }

    match user_store.add_user(user) {
        Ok(_) => {}
        Err(_) => return Err(AuthAPIError::UnexpectedError)
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}
