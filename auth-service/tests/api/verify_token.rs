use auth_service::utils::constants::JWT_COOKIE_NAME;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    
    let mut app = TestApp::new().await;
    let body = serde_json::json!({
        "ewqe": ""
    });

    let response = app.post_verify_token(&body).await;
    assert_eq!(
        response.status().as_u16(),
        422,
        "Failed for input: {:?}",
        response
    );
    app.clean_up().await;
}



#[tokio::test]
async fn should_return_200_valid_token() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();
    let body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": false
    });

    let _ = app.post_signup(&body).await; // Will work

    let response = app.post_login(&body).await;

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    let token_request_body = serde_json::json!({
        "token": auth_cookie.value()
    });

    let token_response = app.post_verify_token(&token_request_body).await;
    assert_eq!(200, token_response.status().as_u16());
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();
    let body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": false
    });

    let _ = app.post_signup(&body).await; // Will work

    let response = app.post_login(&body).await;
    
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    println!("{}", &auth_cookie.value());

    // Complete the logout - this should invalidate the token
    let logout_response = app.post_logout().await;

    let auth_cookie = logout_response
    .cookies()
    .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
    .expect("No auth cookie found");

    let token_request_body = serde_json::json!({
        "token": auth_cookie.value()
    });

    // Now verify the token - it should be rejected with 401
    let token_response = app.post_verify_token(&token_request_body).await;
    
    // Assert that we got a 401 response indicating the token is invalid
    assert_eq!(401, token_response.status().as_u16());
    app.clean_up().await;
}


#[tokio::test]
async fn should_return_401_if_banned_token() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();
    let body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": false
    });

    let _ = app.post_signup(&body).await; // Will work

    let login_response1 = app.post_login(&body).await;
    
    let auth_cookie = login_response1
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    app.post_logout().await;
    let token_request_body = serde_json::json!({
        "token": auth_cookie.value()
    });
    let verify_result = app.post_verify_token(&token_request_body).await;
    assert_eq!(401, verify_result.status().as_u16());
    app.clean_up().await;
}