use crate::security::{
    create_and_save_passcode_passphrase, decode_auth_cipher_from_b64, load_passphrase_decipher,
    AesGcmCrypto,
};
use crate::serve::{EncryptItem, EncryptReq, EncryptRes};
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, info};

pub fn init() {
    let passphrase_result = load_passphrase_decipher();
    if passphrase_result.is_ok() {
        eprintln!("Error: already initialized");
        std::process::exit(1);
    }
    create_and_save_passcode_passphrase().expect("create passcode & passphrase")
}

async fn authed_request<T: Serialize, R: DeserializeOwned>(path: &str, req_body: &T) -> Result<R> {
    let base_url = "http://127.0.0.1:5757";
    let url = format!("{}{}", base_url, path);

    let token = std::env::var("VT_AUTH").context("VT_AUTH environment variable not set")?;
    debug!("Using auth token: {}", token);
    let auth_header = format!("vault {}", token);

    // TODO: Encrypt the request body

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
    // let decrypted_body = cipher.decrypt(&res_bytes)?;
    let decrypted_body = res_bytes;
    let res_body: R =
        serde_json::from_slice(&decrypted_body).context("Failed to parse response body")?;

    Ok(res_body)
}

pub async fn encrypt() {
    let req_body = EncryptReq {
        items: vec![EncryptItem {
            plain: "item1".to_string(),
            t: "totp".to_string(),
        }],
    };

    match authed_request::<EncryptReq, EncryptRes>("/encrypt", &req_body).await {
        Ok(res_body) => {
            println!("Success: {}", res_body.success);
            println!("Message: {}", res_body.message);
            println!("Encrypted Items: {:?}", res_body.encrypted_items);
        }
        Err(e) => {
            eprintln!("Error: {:#?}", e);
        }
    }
}
