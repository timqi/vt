use crate::core::{do_decrypt, do_encrypt, DecryptReq, EncryptItem};
use crate::security::{
    derive_passcode_ciphers, load_mac_cipher, local_authentication, AesGcmCrypto,
};
use crate::store::KeychainStore;

use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

/// Maximum request/response body size (1 MB).
const MAX_BODY_SIZE: usize = 1024 * 1024;

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
    let decrypted_req = match to_bytes(body, MAX_BODY_SIZE).await {
        Ok(body_bytes) => match auth_cipher.decrypt(&body_bytes) {
            Ok(decrypted_bytes) => {
                match std::str::from_utf8(&decrypted_bytes) {
                    Ok(s) => {
                        let modified_s = regex::Regex::new(r#""plaintext":"[^"]*""#)
                            .unwrap()
                            .replace_all(s, r#""plaintext":"****""#)
                            .to_string();
                        info!("request body: {}", modified_s)
                    }
                    Err(_) => info!("Decrypted request body: <non-UTF8 data>"),
                }
                Request::from_parts(parts, Body::from(decrypted_bytes))
            }
            Err(_) => return (StatusCode::FORBIDDEN, "Request failed").into_response(),
        },
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Request failed").into_response(),
    };

    let response = next.run(decrypted_req).await;

    let (parts, body) = response.into_parts();
    match to_bytes(body, MAX_BODY_SIZE).await {
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
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Request failed").into_response()
                }
            }
        }
        Err(_) => {
            warn!("Failed to read response body in auth middleware");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Request failed").into_response();
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
            match to_bytes(body, MAX_BODY_SIZE).await {
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
    /// Cached for the lifetime of the server. Holds the key needed to decrypt
    /// the master passphrase blob inside the keychain store, but not the
    /// master key itself — that's re-derived per request via `load_mac_cipher`
    /// so the AES-GCM master key only lives across one operation.
    ///
    /// If `vt secret rotate-passcode` runs against a live server the cached
    /// cipher will go stale and decrypt requests will start failing; the
    /// rotate command prints a warning telling the operator to restart.
    passphrase_cipher: Arc<AesGcmCrypto>,
    store: Arc<KeychainStore>,
}

pub async fn serve(
    addr: &str,
    enable_http: bool,
    ssh_idle_timeout: u64,
    auth_cache_mode: crate::ssh_agent::AuthCacheMode,
    auth_cache_duration: u64,
) -> Result<()> {
    // Single keychain read: load the store once and derive both ciphers from
    // it. Previously this was two reads (`passcode` + `passphrase` items),
    // doubling the first-run prompt count.
    let store = KeychainStore::load().map_err(|e| anyhow::anyhow!("Not initialized? {}", e))?;
    let (auth_cipher, passphrase_cipher) = derive_passcode_ciphers(&store)?;

    // Start SSH agent
    let ssh_handle = tokio::spawn(async move {
        if let Err(e) = crate::ssh_agent::run_ssh_agent(
            false,
            ssh_idle_timeout,
            auth_cache_mode,
            auth_cache_duration,
        )
        .await
        {
            tracing::warn!("SSH agent failed: {}", e);
        }
    });

    if enable_http {
        let addr = addr.parse::<SocketAddr>()?;
        tracing::info!("Starting HTTP server on {}", addr);

        let app = Router::new()
            .route("/decrypt", post(handler_decrypt))
            .route("/encrypt", post(handler_encrypt))
            .with_state(AppState {
                passphrase_cipher: Arc::new(passphrase_cipher),
                store: Arc::new(store),
            })
            .layer(middleware::from_fn(create_auth_middleware(Arc::new(
                auth_cipher,
            ))))
            .layer(middleware::from_fn(log_middleware))
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE));

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    } else {
        tracing::info!("HTTP server disabled, running SSH agent only");
        ssh_handle.await?;
    }

    Ok(())
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
    if let Ok(cipher) = load_mac_cipher(&state.store, &state.passphrase_cipher) {
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
    if let Ok(cipher) = load_mac_cipher(&state.store, &state.passphrase_cipher) {
        Json(do_encrypt(&cipher, payload)).into_response()
    } else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to load passphrase cipher",
        )
            .into_response();
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[ignore]
    fn test_encrypt_decrypt() {}
}
