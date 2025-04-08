// This struct encapsulates our application-related logic.
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    routing::post,
    serve::Serve,
    Router,
};
use std::error::Error;
use tower_http::services::ServeDir;

pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

// Takes email, password, and 2fa code as input
async fn signup() -> impl IntoResponse {
    StatusCode::OK.into_response() 
}    

async fn login() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
async fn logout() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
async fn verify_2fa() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
async fn verify_token() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token));

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        let app = Application { server, address };
        Ok(app)
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

// Leaving as an example
