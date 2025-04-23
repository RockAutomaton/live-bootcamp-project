use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::domain::{AuthAPIError, Token};
use crate::utils::{auth::validate_token, constants::JWT_COOKIE_NAME};

pub async fn verify_token(
    jar: CookieJar,
    Json(request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // First check if we have an auth cookie
    let auth_cookie = jar.get(JWT_COOKIE_NAME)
        .ok_or(AuthAPIError::InvalidToken)?;

    // Validate the token from the cookie
    match validate_token(auth_cookie.value()).await {
        Ok(_) => {},
        Err(_) => return Err(AuthAPIError::InvalidToken),
    }

    // Then validate the token from the request
    let _ = match Token::parse(&request.token) {
        Ok(_) => {}
        Err(_) => return Err(AuthAPIError::InvalidToken),
    };

    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
pub struct TokenRequest {
    pub token: String,
}
