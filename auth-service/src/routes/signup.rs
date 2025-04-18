use std::sync::Arc;

use crate::{app_state::AppState, domain::*};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

pub async fn signup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError>{
    // Create a new `User` instance using data in the `request`

    // let email = Email::parse(&request.email).unwrap();
    // let password = Password::parse(&request.password).unwrap();

    // Email validation: Check if it's empty or doesn't contain '@'
    let email = match Email::parse(&request.email) {
        Ok(email) => email,
        Err(_) => return Err(AuthAPIError::InvalidCredentials),
    };

    // Password validation: Check if it's less than 8 characters
    let password= match Password::parse(&request.password) {
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
