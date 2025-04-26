use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde::Serialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password},
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let password = match Password::parse(&request.password) {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let email = match Email::parse(&request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let user_store = &state.user_store.read().await;

    if user_store.validate_user(&email, &password).await.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    // let auth_cookie = match generate_auth_cookie(&user.email) {
    //     Ok(cookie) => cookie,
    //     Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    // };

    // let updated_jar = jar.add(auth_cookie);

    // (updated_jar, Ok(StatusCode::OK.into_response()))

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

// New!
async fn handle_2fa(
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // TODO: Return a TwoFactorAuthResponse. The message should be "2FA required".
    // The login attempt ID should be "123456". We will replace this hard-coded login attempt ID soon!
    let response = TwoFactorAuthResponse {
        message: "2FA required".to_string(),
        login_attempt_id: "123456".to_string(),
    };
    let json_response = Json(LoginResponse::TwoFactorAuth(response));
    let status_code = StatusCode::PARTIAL_CONTENT;
    (jar, Ok((status_code, json_response)))
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };
    let updated_jar = jar.add(auth_cookie);
    let json_response = Json(LoginResponse::RegularAuth);
    let status_code = StatusCode::OK;
    (updated_jar, Ok((status_code, json_response)))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
