use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use crate::app_state::AppState;
use color_eyre::eyre::Result;
use crate::{
    domain::AuthAPIError, utils::{auth::validate_token, constants::JWT_COOKIE_NAME}
};
use secrecy::Secret;
#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken))
    };

    let token = cookie.value().to_owned();

    

    // Validate JWT token by calling `validate_token` from the auth service.
    // If the token is valid you can ignore the returned claims for now.
    // Return AuthAPIError::InvalidToken if validation fails.
    match validate_token(&token, state.banned_token_store.clone()).await {
        Ok(_) => {},
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    }

    match state.banned_token_store.write().await.store_token(Secret::new(token.to_owned())).await  {
        Ok(_) => println!("Token stored in banned store"), // Debug print
        Err(e) => {
            println!("Failed to store token: {:?}", e); // Debug print
            return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
        }
    } 
    
    // Remove the JWT cookie from the jar
    let jar = jar.remove(JWT_COOKIE_NAME);
    
    (jar, Ok(StatusCode::OK))
}