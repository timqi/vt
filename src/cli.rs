use std::vec;

use crate::security::{
    create_and_save_passcode_passphrase, decode_auth_cipher_from_b64, load_passcode_ciphers,
    AesGcmCrypto,
};
use crate::serve::{CryptoResItem, EncryptItem, SecretType};
use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{self, Write};
use tracing::{debug};

pub fn init() -> Result<()> {
    let passphrase_result = load_passcode_ciphers();
    if passphrase_result.is_ok() {
        eprintln!("Error: already initialized");
        std::process::exit(1);
    }
    create_and_save_passcode_passphrase().expect("create passcode & passphrase");
    Ok(())
}

pub struct VTClient {
    base_url: String,
    auth_token: String,
}

impl VTClient {
    pub fn new(mut base_url: String, auth_token: String) -> Self {
        debug!("Using auth token: {}", auth_token);
        if !base_url.starts_with("http://") {
            base_url = format!("http://{}", base_url);
        }
        VTClient {
            base_url,
            auth_token,
        }
    }

    pub async fn authed_request<T: Serialize, R: DeserializeOwned>(
        self,
        path: &str,
        req_body: &T,
    ) -> Result<R> {
        let url = format!("{}{}", self.base_url, path);
        let auth_header = format!("vault {}", self.auth_token);

        let req_body = serde_json::to_vec(req_body)?;
        let cipher = AesGcmCrypto::new(&decode_auth_cipher_from_b64(&self.auth_token)?)?;
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
        let res_bytes = res.bytes().await.context("Failed to read response body")?;
        if status.is_success() {
            let decrypted_body = cipher.decrypt(&res_bytes)?;
            let res_body: R =
                serde_json::from_slice(&decrypted_body).context("Failed to parse response body")?;
            Ok(res_body)
        } else {
            let res_str = String::from_utf8_lossy(&res_bytes);
            Err(anyhow::anyhow!("status: {:?} body: {}", status, res_str))
        }
    }
}

pub async fn create(vt_client: VTClient) -> Result<()> {
    print!("Enter secret type (raw/totp) [default: raw]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().is_empty() {
        input = "raw".to_string();
    }
    debug!("User input for secret type: '{}'", input);
    let secret_type = SecretType::from_str(&input.trim().to_lowercase());
    if secret_type == SecretType::UNKNOWN {
        return Err(anyhow::anyhow!("Invalid secret type: {}", input));
    }

    let secret = rpassword::prompt_password("Enter secret: ").context("Failed to read password")?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(anyhow::anyhow!("Secret cannot be empty"));
    }
    println!(
        "Secret entered: {}****{}",
        &secret[..2],
        &secret[secret.len() - 2..]
    );

    debug!("User input for secret: '{}'", secret);

    let res = vt_client
        .authed_request::<Vec<EncryptItem>, Vec<CryptoResItem>>(
            "/encrypt",
            &vec![EncryptItem {
                plaintext: secret.to_string(),
                t: secret_type,
            }],
        )
        .await?;
    if res[0].err_message != "" {
        return Err(anyhow::anyhow!("Failed to create secret: {}", res[0].err_message));
    }
    println!("Created item: {}", res[0].result);
    Ok(())
}

pub async fn read(vt_client: VTClient, vt: String) -> Result<()> {
    let vt = vec![vt];
    let res = vt_client
        .authed_request::<Vec<String>, Vec<CryptoResItem>>("/decrypt", &vt)
        .await?;
    ensure!(res.len() == 1, "Expected exactly one item in response");
    ensure!(res[0].err_message.is_empty(), "Error decrypting item: {}", res[0].err_message);
    println!("{}", res[0].result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    fn create_vt_client() -> VTClient {
        VTClient::new(
            "http://127.0.0.1:5757".to_owned(),
            "MY5hkACZQZbqfpuYaWjnzlbpGVQYhwqynnrpkek568g".to_string(),
        )
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "requires server"]
    async fn test_create_items() {
        let vt_client = create_vt_client();

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

        let res = vt_client
            .authed_request::<Vec<EncryptItem>, Vec<CryptoResItem>>("/encrypt", &req_body)
            .await
            .expect("Failed to create items");

        debug!(
            "Created items (json): {}",
            serde_json::to_string_pretty(&res).unwrap()
        );
        assert!(!res.is_empty(), "Expected non-empty response");
        assert_eq!(res.len(), 2, "Expected two items in response");
    }
}
