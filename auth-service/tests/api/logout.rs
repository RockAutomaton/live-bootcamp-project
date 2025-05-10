use crate::helpers::{get_random_email, TestApp};

use auth_service::utils::constants::JWT_COOKIE_NAME;
use reqwest::Url;
use serde_json::json;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new().await;

    // Do not set the JWT cookie
    let response = app.post_logout().await;
    assert_eq!(response.status(), 400);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status(), 401);
    app.clean_up().await;
}




#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty()); // Changed: should NOT be empty after login
    
    let token = auth_cookie.value();

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);

    // Verify the cookie was removed
    let logout_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME);
    
    // Cookie should be removed (or have empty value) after logout
    match logout_cookie {
        Some(cookie) => assert!(cookie.value().is_empty()),
        None => (), // Cookie completely removed is also valid
    }


    let banned_token_store = app.banned_token_store.read().await;
    let contains_token = banned_token_store
        .check_banned_token(token)
        .await
        .expect("Failed to check if token is banned");
    assert!(contains_token);
    drop(banned_token_store); // Drop the read lock before cleanup
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new().await;

    // Register and login to get a valid JWT cookie
    // Register and login to get a valid JWT cookie
    let email = get_random_email();
    let password = "Password123!";
    let signup_body = json!({
        "email": email,
        "password": password,
        "requires2FA": false
    });

    let login_body = json!({
        "email": email,
        "password": password,
    });

    app.post_signup(&signup_body).await;
    app.post_login(&login_body).await;
    // First logout should succeed
    
    let response1 = app.post_logout().await;
    assert_eq!(response1.status(), 200);

    // Second logout should fail with 400 (no JWT cookie)
    let response2 = app.post_logout().await;
    assert_eq!(response2.status(), 400);
    app.clean_up().await;
}