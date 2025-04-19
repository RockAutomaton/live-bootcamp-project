use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::*};
use crate::domain::AuthAPIError;
use crate::utils::auth::generate_auth_cookie;

pub async fn login(
    State(state): State<Arc<AppState>>,
    jar: CookieJar, // New!
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    

    let email = match Email::parse(&request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let password= match Password::parse(&request.password) {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };

    let user_store = &state.user_store.read().await;

    let valid_user = match user_store.validate_user(&email, &password).await{
        Ok(()) => {},
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials))
    };

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials))
    };

    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(auth_cookie) => auth_cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError))
    }; 

    let updated_jar = jar.add(auth_cookie);
    
    (updated_jar, Ok(StatusCode::OK.into_response()))
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