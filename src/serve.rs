use std::net::SocketAddr;
use axum::{Router, routing::get};

#[tokio::main]
pub async fn run(host: String, port: u16) {
    let addr = format!("{}:{}", host, port).parse::<SocketAddr>().unwrap();
    tracing::info!("Starting server on {}", addr);

    let app = Router::new().route("/", get(handler));

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> &'static str {
    "Hello, World!"
}