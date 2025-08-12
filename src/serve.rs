use crate::security::{load_mac_cipher, load_passcode_ciphers, local_authentication, AesGcmCrypto};

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
use tracing::{info, warn};

fn create_auth_middleware(
    auth_cipher: Arc<AesGcmCrypto>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone {
    move |request: Request, next: Next| {
        let auth_cipher = Arc::clone(&auth_cipher);

        Box::pin(async move { auth_middleware_impl(request, next, auth_cipher).await })
    }
}

async fn auth_middleware_impl(
    request: Request,
    next: Next,
    auth_cipher: Arc<AesGcmCrypto>,
) -> Response {
    let request_path = request.uri().path().to_string();

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
            Err(_) => {
                return (
                    StatusCode::FORBIDDEN,
                    "Decryption req failed, Wrong VT_AUTH ?",
                )
                    .into_response()
            }
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
    if !response.status().is_success() {
        return response;
    }

    let (parts, body) = response.into_parts();
    match to_bytes(body, usize::MAX).await {
        Ok(raw_bytes) => {
            match std::str::from_utf8(&raw_bytes) {
                Ok(s) => {
                    if request_path == "/decrypt" {
                        let modified_s = regex::Regex::new(r#""result":"[^"]*""#)
                            .unwrap()
                            .replace_all(s, r#""result":"****""#)
                            .to_string();
                        info!("response body: {}", modified_s);
                    } else {
                        info!("response body: {}", s);
                    }
                }
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
            warn!("Failed to read response body in auth middleware");
            return (StatusCode::INTERNAL_SERVER_ERROR, "auth middleware").into_response();
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

pub async fn serve(addr: &str) -> Result<()> {
    let (auth_cipher, passphrase_cipher) =
        load_passcode_ciphers().map_err(|e| anyhow::anyhow!("Not initialized? {}", e))?;

    let addr = addr.parse::<SocketAddr>()?;
    tracing::info!("Starting server on {}", addr);

    let app = Router::new()
        .route("/decrypt", post(handler_decrypt))
        .route("/encrypt", post(handler_encrypt))
        .with_state(AppState {
            passphrase_cipher: Arc::new(passphrase_cipher),
        })
        .layer(middleware::from_fn(create_auth_middleware(Arc::new(
            auth_cipher,
        ))))
        .layer(middleware::from_fn(log_middleware));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct EncryptItem {
    pub plaintext: String,
    pub t: SecretType,
}

#[derive(Deserialize, Serialize)]
pub struct DecryptReq {
    pub host: String,
    pub command: String,
    pub items: Vec<String>,
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
    Json(payload): Json<DecryptReq>,
) -> impl IntoResponse {
    let local_auth_message = format!(
        "decrypt {} items from {} to run `{}`",
        payload.items.len(),
        payload.host,
        payload.command,
    );
    if !local_authentication(&local_auth_message) {
        return (StatusCode::FORBIDDEN, "User Rejected").into_response();
    }
    if let Ok(cipher) = load_mac_cipher(&state.passphrase_cipher) {
        Json(do_decrypt(&cipher, payload.items)).into_response()
    } else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to load passphrase cipher",
        )
            .into_response();
    }
}

async fn handler_encrypt(
    State(state): State<AppState>,
    Json(payload): Json<Vec<EncryptItem>>,
) -> impl IntoResponse {
    if let Ok(cipher) = load_mac_cipher(&state.passphrase_cipher) {
        Json(do_encrypt(&cipher, payload)).into_response()
    } else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to load passphrase cipher",
        )
            .into_response();
    }
}

pub fn do_encrypt(cipher: &AesGcmCrypto, items: Vec<EncryptItem>) -> Vec<CryptoResItem> {
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

pub fn do_decrypt(cipher: &AesGcmCrypto, items: Vec<String>) -> Vec<CryptoResItem> {
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
