use crate::helpers::{get_random_email, TestApp};
use auth_service::ErrorResponse;
use axum::http::response;

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;
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
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message. 
    let app = TestApp::new().await;
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
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.  
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": true
    });

    // Create a user 
    let _ = app.post_signup(&body).await; // Will work

    // Attempt Login with different password

    let body = serde_json::json!({
        "email": random_email,
        "password": "Password456!",
        "requires2FA": true
    });

    let response = app.post_login(&body).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        response
    );
}