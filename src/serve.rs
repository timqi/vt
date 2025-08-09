use crate::security::{load_auth_cipher, AesGcmCrypto};
use aes_gcm::aead::rand_core::le;
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

fn create_auth_middleware(
    auth_token: [u8; 32],
    auth_cipher: Arc<AesGcmCrypto>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone {
    move |request: Request, next: Next| {
        let auth_token = auth_token;
        let auth_cipher = Arc::clone(&auth_cipher);

        Box::pin(async move { auth_middleware_impl(request, next, auth_token, auth_cipher).await })
    }
}

async fn auth_middleware_impl(
    request: Request,
    next: Next,
    auth_token: [u8; 32],
    auth_cipher: Arc<AesGcmCrypto>,
) -> Response {
    let auth_header = match request.headers().get(axum::http::header::AUTHORIZATION) {
        Some(header) => match header.to_str() {
            Ok(s) => s,
            Err(_) => return (StatusCode::FORBIDDEN, "invalid auth header").into_response(),
        },
        None => return (StatusCode::FORBIDDEN, "missing auth header").into_response(),
    };
    let mut parts = auth_header.split_whitespace();
    match parts.next() {
        Some("vault") => {}
        _ => return (StatusCode::FORBIDDEN, "invalid auth scheme").into_response(),
    }

    match parts.next() {
        Some(token) => match BASE64_STANDARD.decode(token) {
            Ok(token_bytes) => {
                let hash = Sha256::digest(&Sha256::digest(token_bytes));
                let mut req_token = [0u8; 32];
                req_token.copy_from_slice(&hash[..32]);
                if req_token != auth_token {
                    return (StatusCode::FORBIDDEN, "invalid auth token").into_response();
                }
            }
            Err(_) => return (StatusCode::FORBIDDEN, "can't decode auth token").into_response(),
        },
        None => return (StatusCode::FORBIDDEN, "missing auth token").into_response(),
    };

    let (parts, body) = request.into_parts();
    let decrypted_req = match to_bytes(body, usize::MAX).await {
        Ok(body_bytes) => match auth_cipher.decrypt(&body_bytes) {
            Ok(decrypted_bytes) => {
                match std::str::from_utf8(&decrypted_bytes) {
                    Ok(s) => info!("request body: {}", s),
                    Err(_) => info!("Decrypted request body: <non-UTF8 data>"),
                }
                Request::from_parts(parts, Body::from(decrypted_bytes))
            }
            Err(_) => return (StatusCode::FORBIDDEN, "decryption failed").into_response(),
        },
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read request body",
            )
                .into_response()
        }
    };

    let response = next.run(decrypted_req).await;

    let (parts, body) = response.into_parts();
    match to_bytes(body, usize::MAX).await {
        Ok(raw_bytes) => {
            match std::str::from_utf8(&raw_bytes) {
                Ok(s) => info!("response body: {}", s),
                Err(_) => info!("raw response body: <non-UTF8 data>"),
            }
            match auth_cipher.encrypt(&raw_bytes) {
                Ok(encrypted_bytes) => Response::from_parts(parts, Body::from(encrypted_bytes)),
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "encryption failed").into_response()
                }
            }
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read response body",
            )
                .into_response()
        }
    }
}

async fn log_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();
    let (body_content, response) = match status {
        StatusCode::OK => ("".to_string(), response),
        _ => {
            let (parts, body) = response.into_parts();
            match to_bytes(body, usize::MAX).await {
                Ok(body_bytes) => match std::str::from_utf8(&body_bytes) {
                    Ok(s) => (
                        s.to_string(),
                        Response::from_parts(parts, Body::from(body_bytes)),
                    ),
                    Err(_) => (
                        "response body: <non-UTF8 data>".to_string(),
                        Response::from_parts(parts, Body::from(body_bytes)),
                    ),
                },
                Err(_) => (
                    "invalid body".to_string(),
                    Response::from_parts(parts, Body::empty()),
                ),
            }
        }
    };

    info!(
        "{:?} {} {} {:?} {}",
        status, method, uri, duration, body_content
    );
    response
}

#[tokio::main]
pub async fn serve(host: String, port: u16) {
    let addr = format!("{}:{}", host, port).parse::<SocketAddr>().unwrap();
    tracing::info!("Starting server on {}", addr);

    let (auth_token, auth_cipher) = load_auth_cipher().expect("load auth");
    let app = Router::new()
        .route("/decrypt", post(do_decrypt))
        .layer(middleware::from_fn(create_auth_middleware(
            auth_token,
            Arc::new(auth_cipher),
        )))
        .layer(middleware::from_fn(log_middleware));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct DecryptReq {
    items: Vec<String>,
}

#[derive(Serialize)]
struct DecryptRes {
    success: bool,
    message: String,
    decrypted_items: HashMap<String, String>,
}

async fn do_decrypt(Json(payload): Json<DecryptReq>) -> Json<DecryptRes> {
    let mut decrypted_items = HashMap::new();
    for item in payload.items {
        let decrypted_value = format!("decrypted_{}", item);
        decrypted_items.insert(item, decrypted_value);
    }

    let response = DecryptRes {
        success: true,
        message: "Decryption completed".to_string(),
        decrypted_items,
    };

    Json(response)
}
