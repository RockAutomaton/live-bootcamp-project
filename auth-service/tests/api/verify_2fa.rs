use auth_service::{
    domain::Email,
    routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};
use secrecy::{ExposeSecret, Secret};
use wiremock::{matchers::{method, path}, Mock, ResponseTemplate};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    // Example of correctly formatted JSON
    // {
    //     "email": "user@example.com",
    //     "loginAttemptId": "string",
    //     "2FACode": "string"
    //   }

    let mut app = TestApp::new().await;

    let body = serde_json::json!({
        "login_attempt_id": "invalid",
        "code": "invalid"
    });
    let response = app.post_verify_2fa(&body).await; 
    assert_eq!(response.status(), 422);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let body = serde_json::json!({
        "email": "invalid",
        "loginAttemptId": "invalid",
        "2FACode": "invalid"
    });
    let response = app.post_verify_2fa(&body).await; 
    assert_eq!(response.status(), 400);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    // Set up email server mock
    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    // Create a user with a random email and password
    let email = get_random_email();
    let password = "Password123!";
    let login_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    });

    app.post_signup(&login_body).await;

    // get the login attempt id
    let login_response = app.post_login(&login_body).await;
    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .unwrap()
        .login_attempt_id;

    // Attempt to verify 2FA with incorrect credentials
    let body = serde_json::json!({
        "email": email,
        "loginAttemptId": login_attempt_id,
        "2FACode": "123456"
    });

    let response = app.post_verify_2fa(&body).await;
    assert_eq!(response.status(), 401);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;

    // Set up email server mock
    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2) // Expect 2 requests since we call login twice
        .mount(&app.email_server)
        .await;

    let email: Email = Email::parse(Secret::new(get_random_email())).unwrap();
    let password = "Password123!";
    let login_body = serde_json::json!({
        "email": &email.as_ref().expose_secret(),
        "password": password,
        "requires2FA": true
    });

    app.post_signup(&login_body).await;
    let login_response = app.post_login(&login_body).await;
    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .unwrap()
        .login_attempt_id;
    let code = app.two_fa_code_store.read().await.get_code(&email.clone()).await.unwrap().1;

    app.post_login(&login_body).await;
    let body = serde_json::json!({
        "email": &email.as_ref().expose_secret(),
        "loginAttemptId": login_attempt_id,
        "2FACode": code.as_ref()
    });
    let response = app.post_verify_2fa(&body).await;
    assert_eq!(response.status(), 401);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {    
    let mut app = TestApp::new().await;

    // Set up email server mock
    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2) // Expect 2 requests since we call login twice
        .mount(&app.email_server)
        .await;

    let email: Email = Email::parse(Secret::new(get_random_email())).unwrap();
    let password = "Password123!";
    let login_body = serde_json::json!({
        "email": &email.as_ref().expose_secret(),
        "password": password,
        "requires2FA": true
    });
    app.post_signup(&login_body).await;
    let login_response = app.post_login(&login_body).await; 
    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .unwrap()
        .login_attempt_id;
    let code = app.two_fa_code_store.read().await.get_code(&email.clone()).await.unwrap().1;
    let body = serde_json::json!({
        "email": &email.as_ref().expose_secret(),
        "loginAttemptId": login_attempt_id,
        "2FACode": code.as_ref()
    });
    let _login_response = app.post_login(&login_body).await; 

    let response = app.post_verify_2fa(&body).await;
    assert_eq!(response.status(), 401);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let mut app = TestApp::new().await;

    // Set up email server mock
    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let email: Email = Email::parse(Secret::new(get_random_email())).unwrap();
    let password = "Password123!";
    let login_body = serde_json::json!({
        "email": &email.as_ref().expose_secret(),
        "password": password,
        "requires2FA": true
    });

    // Sign up and login
    app.post_signup(&login_body).await;
    let login_response = app.post_login(&login_body).await;
    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .unwrap()
        .login_attempt_id;

    // Get the actual 2FA code from the store
    let (_, code) = app.two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .unwrap();

    // Verify with the correct code
    let verify_body = serde_json::json!({
        "email": &email.as_ref().expose_secret(),
        "loginAttemptId": login_attempt_id,
        "2FACode": code.as_ref()
    });

    let response = app.post_verify_2fa(&verify_body).await;
    assert_eq!(response.status(), 200);

    // Verify we got a valid JWT cookie
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}