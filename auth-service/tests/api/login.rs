use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    domain::Email,
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use secrecy::Secret;
use wiremock::{matchers::{method, path}, Mock, ResponseTemplate};
#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();

    let body = serde_json::json!({
        "email": random_email,
    });

    let response = app.post_login(&body).await;
    assert_eq!(
        response.status().as_u16(),
        422,
        "Failed for input: {:?}",
        response
    );
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message. 
    let mut app = TestApp::new().await;
    let test_cases = [
        serde_json::json!({
            "email": "12323hotmail.com",
            "password": "password123"
        }),
        serde_json::json!({
            "email": "12323@hotmail.com",
            "password": "pass"
        }),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await; // call `post_signup`
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.  
    let mut app = TestApp::new().await;
    let random_email = get_random_email();
    let body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": false
    });

    // Create a user 
    let _ = app.post_signup(&body).await; // Will work

    // Attempt Login with different password

    let body = serde_json::json!({
        "email": random_email,
        "password": "Password456!",
        "requires2FA": false
    });

    let response = app.post_login(&body).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        response
    );
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
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

    assert!(!auth_cookie.value().is_empty());
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();
    let body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": true
    });

    // Set up email server mock
    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let _ = app.post_signup(&body).await; // Will work
    
    // Single login attempt
    let response = app.post_login(&body).await;
    assert_eq!(response.status().as_u16(), 206);

    let login_attempt_id = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse")
        .login_attempt_id;

    // Get the stored code from this single attempt
    let stored_code = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email)).unwrap())
        .await
        .expect("Failed to get code from store");

    // Verify the login attempt IDs match
    let stored_login_attempt_id = stored_code.0.as_ref().to_string();
    assert_eq!(stored_login_attempt_id, login_attempt_id);
    app.clean_up().await;
}