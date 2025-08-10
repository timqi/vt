use std::vec;

use crate::security::{
    create_and_save_passcode_passphrase, decode_auth_cipher_from_b64, load_passcode_ciphers,
    AesGcmCrypto,
};
use crate::serve::{CryptoResItem, EncryptItem, SecretType};
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, info};

pub fn init() -> Result<()> {
    let passphrase_result = load_passcode_ciphers();
    if passphrase_result.is_ok() {
        eprintln!("Error: already initialized");
        std::process::exit(1);
    }
    create_and_save_passcode_passphrase().expect("create passcode & passphrase");
    Ok(())
}

async fn authed_request<T: Serialize, R: DeserializeOwned>(path: &str, req_body: &T) -> Result<R> {
    let base_url = "http://127.0.0.1:5757";
    let url = format!("{}{}", base_url, path);

    let token = std::env::var("VT_AUTH").context("VT_AUTH environment variable not set")?;
    debug!("Using auth token: {}", token);
    let auth_header = format!("vault {}", token);
    let req_body = serde_json::to_vec(req_body)?;
    let cipher = AesGcmCrypto::new(&decode_auth_cipher_from_b64(&token)?)?;
    let encrypted_body = cipher.encrypt(&req_body)?;
    debug!("Encrypted request body: {:?}", req_body);

    let client = reqwest::Client::new();
    let res = client
        .post(&url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json")
        .body(encrypted_body)
        .send()
        .await
        .context("Failed to send request")?;

    let status = res.status();
    info!("Status: {}", status);

    let res_bytes = res.bytes().await.context("Failed to read response body")?;
    let decrypted_body = cipher.decrypt(&res_bytes)?;
    let res_body: R =
        serde_json::from_slice(&decrypted_body).context("Failed to parse response body")?;

    Ok(res_body)
}

pub async fn create() -> Result<()> {
    let req_body = vec![
        EncryptItem {
            plaintext: "item1".to_string(),
            t: SecretType::RAW,
        },
        EncryptItem {
            plaintext: "BMVWRJFTJ43P7QDQ".to_string(),
            t: SecretType::TOTP,
        },
    ];

    let res = authed_request::<Vec<EncryptItem>, Vec<CryptoResItem>>("/encrypt", &req_body).await?;
    println!("Items: {:?}", res);
    Ok(())
}

pub async fn read(vt: String) -> Result<()> {
    // authed_request("/decrypt", req_body)
    println!("Received vt: {}", vt);
    let vt = vec![vt];
    let res = authed_request::<Vec<String>, Vec<CryptoResItem>>("/decrypt", &vt).await?;

    println!("Items: {:?}", res);
    Ok(())
}
