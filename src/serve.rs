use crate::security::{decode_auth_cipher_from_b64, load_auth_cipher, AesGcmCrypto};

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
        Some(token) => match decode_auth_cipher_from_b64(token) {
            Ok(req_token) => {
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

pub async fn serve(host: String, port: u16) {
    let addr = format!("{}:{}", host, port).parse::<SocketAddr>().unwrap();
    tracing::info!("Starting server on {}", addr);

    let (auth_token, auth_cipher) = load_auth_cipher().expect("load auth");
    let app = Router::new()
        .route("/decrypt", post(do_decrypt))
        .route("/encrypt", post(do_encrypt))
        .layer(middleware::from_fn(create_auth_middleware(
            auth_token,
            Arc::new(auth_cipher),
        )))
        .layer(middleware::from_fn(log_middleware));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
pub struct DecryptReq {
    pub items: Vec<String>,
}

#[derive(Serialize)]
pub struct DecryptRes {
    pub success: bool,
    pub message: String,
    pub decrypted_items: HashMap<String, String>,
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

#[derive(Deserialize, Serialize)]
pub struct EncryptItem {
    pub plain: String,
    pub t: String,
}

#[derive(Deserialize, Serialize)]
pub struct EncryptReq {
    pub items: Vec<EncryptItem>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptRes {
    pub success: bool,
    pub message: String,
    pub encrypted_items: Vec<String>,
}

async fn do_encrypt(Json(payload): Json<EncryptReq>) -> Json<EncryptRes> {
    let mut encrypted_items = Vec::new();
    for item in payload.items {
        let encrypted_value = format!("encrypted_{}", item.plain);
        encrypted_items.push(encrypted_value);
    }

    let response = EncryptRes {
        success: true,
        message: "Encryption completed".to_string(),
        encrypted_items,
    };

    Json(response)
}
