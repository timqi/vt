use crate::security::{
    decode_auth_cipher_from_b64, load_mac_cipher, load_passcode_ciphers, local_authentication,
    AesGcmCrypto,
};

use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use totp_rs::{Algorithm, Secret, TOTP};
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

#[derive(Clone)]
struct AppState {
    passphrase_cipher: Arc<AesGcmCrypto>,
}

pub async fn serve(host: String, port: u16) -> Result<()> {
    let (auth_token, auth_cipher, passphrase_cipher) =
        load_passcode_ciphers().map_err(|e| anyhow::anyhow!("Not initialized? {}", e))?;

    let addr = format!("{}:{}", host, port).parse::<SocketAddr>().unwrap();
    tracing::info!("Starting server on {}", addr);

    let app = Router::new()
        .route("/decrypt", post(handler_decrypt))
        .route("/encrypt", post(handler_encrypt))
        .with_state(AppState {
            passphrase_cipher: Arc::new(passphrase_cipher),
        })
        .layer(middleware::from_fn(create_auth_middleware(
            auth_token,
            Arc::new(auth_cipher),
        )))
        .layer(middleware::from_fn(log_middleware));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct EncryptItem {
    pub plaintext: String,
    pub t: SecretType,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct CryptoResItem {
    pub result: String,
    pub err_message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    RAW,
    TOTP,
    UNKNOWN,
}

impl SecretType {
    pub fn from_str(s: &str) -> SecretType {
        match s.to_lowercase().as_str() {
            "raw" | "0" => SecretType::RAW,
            "totp" | "1" => SecretType::TOTP,
            _ => SecretType::UNKNOWN,
        }
    }
}

impl SecretType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretType::RAW => "0",
            SecretType::TOTP => "1",
            SecretType::UNKNOWN => "_",
        }
    }
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

async fn handler_decrypt(
    State(state): State<AppState>,
    Json(payload): Json<Vec<String>>,
) -> impl IntoResponse {
    if !local_authentication(&format!("decrypt {} items", payload.len())) {
        return (StatusCode::FORBIDDEN, "User Rejected").into_response();
    }
    Json(do_decrypt(&state.passphrase_cipher, payload)).into_response()
}

async fn handler_encrypt(
    State(state): State<AppState>,
    Json(payload): Json<Vec<EncryptItem>>,
) -> Json<Vec<CryptoResItem>> {
    Json(do_encrypt(&state.passphrase_cipher, payload))
}

pub fn do_encrypt(passphrase_cipher: &AesGcmCrypto, items: Vec<EncryptItem>) -> Vec<CryptoResItem> {
    let cipher = load_mac_cipher(passphrase_cipher).expect("load mac cipher");
    let mut encrypted_items = Vec::<CryptoResItem>::new();
    for item in items {
        let item = match cipher.encrypt(item.plaintext.as_bytes()) {
            Ok(encrypted_value) => CryptoResItem {
                result: format!(
                    "vt://mac/{}{}",
                    item.t,
                    BASE64_URL_SAFE_NO_PAD.encode(encrypted_value)
                ),
                err_message: String::new(),
            },
            Err(e) => CryptoResItem {
                result: String::new(),
                err_message: e.to_string(),
            },
        };
        encrypted_items.push(item);
    }
    encrypted_items
}

pub fn do_decrypt(passphrase_cipher: &AesGcmCrypto, items: Vec<String>) -> Vec<CryptoResItem> {
    let cipher = load_mac_cipher(passphrase_cipher).expect("load mac cipher");
    let mut decrypted_items = Vec::<CryptoResItem>::new();
    let b64_to_decrypted = |b64_str: &str| -> anyhow::Result<String> {
        let raw_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(b64_str.as_bytes())
            .map_err(|e| anyhow::anyhow!("base64 decode error: {}", e))?;
        let decrypted_bytes = cipher.decrypt(&raw_bytes)?;
        String::from_utf8(decrypted_bytes).map_err(|e| anyhow::anyhow!("decryption error: {}", e))
    };
    for item in items {
        let prefix = "vt://mac/";
        let decrypted_result: Result<String> = if item.starts_with(prefix) {
            let item = item[prefix.len()..].to_string();
            match SecretType::from_str(item[..1].as_ref()) {
                SecretType::RAW => b64_to_decrypted(&item[1..]),
                SecretType::TOTP => match b64_to_decrypted(&item[1..]) {
                    Ok(decrypted_str) => match Secret::Encoded(decrypted_str).to_bytes() {
                        Ok(secret_bytes) => {
                            let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret_bytes);
                            totp.generate_current()
                                .map_err(|e| anyhow::anyhow!("TOTP generate error: {}", e))
                        }
                        Err(e) => Err(anyhow::anyhow!("TOTP secret encode error: {}", e)),
                    },
                    Err(e) => Err(e),
                },
                SecretType::UNKNOWN => Err(anyhow::anyhow!("unknown secret type")),
            }
        } else {
            Err(anyhow::anyhow!("not a vt item"))
        };
        decrypted_items.push(match decrypted_result {
            Ok(decrypted_value) => CryptoResItem {
                result: decrypted_value,
                err_message: String::new(),
            },
            Err(e) => CryptoResItem {
                result: String::new(),
                err_message: e.to_string(),
            },
        });
    }
    decrypted_items
}

#[cfg(test)]
mod tests {

    #[test]
    #[ignore]
    fn test_encrypt_decrypt() {}
}
