use std::vec;

use crate::security::{
    create_and_save_passcode_passphrase, decode_auth_cipher_from_b64, load_passcode_ciphers,
    AesGcmCrypto,
};
use crate::serve::{CryptoResItem, EncryptItem, SecretType};
use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{self, Write};
use tracing::debug;

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
        return Err(anyhow::anyhow!(
            "Failed to create secret: {}",
            res[0].err_message
        ));
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
    ensure!(
        res[0].err_message.is_empty(),
        "Error decrypting item: {}",
        res[0].err_message
    );
    print!("{}", res[0].result);
    Ok(())
}

async fn decrypt_from_multi_str(
    vt_client: VTClient,
    original_str_vec: Vec<String>,
) -> Result<Vec<String>> {
    let mut encrypted_vec = Vec::<String>::new();
    // Extract 'vt://xxx/urlsafebase64encoded' patterns from the string
    let vt_pattern = regex::Regex::new(r"vt://[^/]+/[A-Za-z0-9_-]+").unwrap();
    for item in &original_str_vec {
        for vt_match in vt_pattern.find_iter(item) {
            debug!("Found encrypted item: {}", vt_match.as_str());
            encrypted_vec.push(vt_match.as_str().to_string());
        }
    }

    let res = vt_client
        .authed_request::<Vec<String>, Vec<CryptoResItem>>("/decrypt", &encrypted_vec)
        .await?;
    ensure!(
        res.len() == encrypted_vec.len(),
        "Expected same number of items in response"
    );
    let decrypted_vec: Vec<String> = res
        .into_iter()
        .filter_map(|item| {
            if item.err_message.is_empty() {
                Some(item.result)
            } else {
                Some(item.err_message)
            }
        })
        .collect();

    // Create a mapping from encrypted vault items to decrypted values
    let mut secret_map = std::collections::HashMap::new();
    for (i, encrypted) in encrypted_vec.iter().enumerate() {
        if i < decrypted_vec.len() {
            secret_map.insert(encrypted.clone(), decrypted_vec[i].clone());
        }
    }
    debug!("secret_map: {:?}", secret_map);

    // Replace encrypted vault items with decrypted values in original strings
    let mut result_vec = Vec::new();
    for original_str in original_str_vec {
        let mut result_str = original_str.clone();
        for (encrypted_item, decrypted_value) in &secret_map {
            result_str = result_str.replace(encrypted_item, decrypted_value);
        }
        result_vec.push(result_str);
    }

    Ok(result_vec)
}

pub async fn inject(
    vt_client: VTClient,
    input_file: &str,
    output_file: Option<String>,
    timeout: &u32,
    mut args: Vec<String>,
) -> Result<()> {
    let input_file_content = std::fs::read_to_string(input_file)
        .with_context(|| format!("Failed to read input file: {}", input_file))?;
    args.push(input_file_content);

    let mut decrypted_args = decrypt_from_multi_str(vt_client, args).await?;
    let output_file_content = decrypted_args.pop().unwrap();
    if let Some(output_file) = output_file {
        std::fs::write(&output_file, &output_file_content)
            .with_context(|| format!("Failed to write to output file: {}", output_file))?;
        debug!("Content written to: {}", output_file);
    } else {
        print!("{}", output_file_content);
    }

    if decrypted_args.is_empty() {
        debug!("No command to execute, exiting.");
        return Ok(());
    }

    // Execute the command with decrypted arguments
    let command = &decrypted_args[0];
    let args = &decrypted_args[1..];

    debug!("Executing command: {} with args: {:?}", command, args);

    let mut cmd = std::process::Command::new(command);
    cmd.args(args);

    // Set timeout if specified
    let child = cmd
        .spawn()
        .with_context(|| format!("Failed to execute command: {}", command))?;

    let output = if *timeout > 0 {
        // Wait with timeout
        let timeout_duration = std::time::Duration::from_secs(*timeout as u64);
        match tokio::time::timeout(
            timeout_duration,
            tokio::task::spawn_blocking(move || child.wait_with_output()),
        )
        .await
        {
            Ok(Ok(Ok(output))) => output,
            Ok(Ok(Err(e))) => return Err(anyhow::anyhow!("Command execution failed: {}", e)),
            Ok(Err(e)) => return Err(anyhow::anyhow!("Failed to join task: {}", e)),
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Command timed out after {} seconds",
                    timeout
                ))
            }
        }
    } else {
        // Wait without timeout
        tokio::task::spawn_blocking(move || child.wait_with_output())
            .await
            .context("Failed to join task")??
    };

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Command failed with exit code: {:?}\nStderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Print command output
    print!("{}", String::from_utf8_lossy(&output.stdout));

    debug!("Arguments:");
    for (i, arg) in decrypted_args.iter().enumerate() {
        debug!("  [{}]: {}", i, arg);
    }

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
