use std::sync::Arc;

use crate::{app_state::AppState, domain::*};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};
use secrecy::Secret;
#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError>{

    // Email validation: Check if it's empty or doesn't contain '@'
    let email = match Email::parse(Secret::new(request.email)) {
        Ok(email) => email,
        Err(_) => return Err(AuthAPIError::InvalidCredentials),
    };

    // Password validation: Check if it's less than 8 characters
    let password= match Password::parse(request.password) {
        Ok(password) => password,
        Err(_) => return Err(AuthAPIError::InvalidCredentials)
    };

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;
    
    match user_store.get_user(&user.email).await {
        Ok(_) => return Err(AuthAPIError::UserAlreadyExists),
        Err(_) => {} // User doesn't exist, continue with signup
    }

    match user_store.add_user(user).await {
        Ok(_) => {}
        Err(e) => return Err(AuthAPIError::UnexpectedError(e.into()))
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}
