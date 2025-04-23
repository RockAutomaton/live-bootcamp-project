use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::domain::AuthAPIError;
use crate::utils::auth::validate_token;

pub async fn verify_token(
    _jar: CookieJar,
    Json(request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the JWT token
    validate_token(&request.token)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
pub struct TokenRequest {
    pub token: String,
}
