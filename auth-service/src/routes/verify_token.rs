use std::sync::Arc;

use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use crate::{app_state::AppState, domain::*};

use crate::domain::AuthAPIError;
use crate::utils::auth::validate_token;

#[tracing::instrument(name = "Verify Token", skip_all)]
pub async fn verify_token(
    _jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the JWT token
    validate_token(&request.token, state.banned_token_store.clone())
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
pub struct TokenRequest {
    pub token: String,
}
