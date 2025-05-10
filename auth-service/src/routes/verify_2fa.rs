use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use std::sync::Arc;
use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> impl IntoResponse {
    let email = match Email::parse(&request.email) {
        Ok(email) => email,
        Err(_) => return (jar, AuthAPIError::InvalidCredentials.into_response()),
    };

    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
        Ok(login_attempt_id) => login_attempt_id,
        Err(_) => return (jar, AuthAPIError::InvalidCredentials.into_response()),
    };

    let two_fa_code = match TwoFACode::parse(request.code) {
        Ok(two_fa_code) => two_fa_code,
        Err(_) => return (jar, AuthAPIError::InvalidCredentials.into_response()),
    };

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    let code_tuple = match two_fa_code_store
        .get_code(&email)
        .await
    {
        Ok(tuple) => tuple,
        Err(_) => return (jar, AuthAPIError::IncorrectCredentials.into_response()),
    };

    if code_tuple.0 != login_attempt_id || code_tuple.1 != two_fa_code {
        return (jar, AuthAPIError::IncorrectCredentials.into_response());
    }

    if let Err(e) = two_fa_code_store
        .remove_code(&email)
        .await
    {
        return (jar, AuthAPIError::UnexpectedError(e.into()).into_response())
    }

    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, AuthAPIError::UnexpectedError(e.into()).into_response()),
    };

    let updated_jar = jar.add(auth_cookie);
    (updated_jar, StatusCode::OK.into_response())
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    email: String,
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,
    #[serde(rename = "2FACode")]
    code: String,
}