use std::collections::HashMap;
use std::{env, vec};

use crate::security::{
    create_and_save_passcode_passphrase, decode_auth_cipher_from_b64, get_keychain,
    load_passcode_ciphers, local_authentication, AesGcmCrypto,
};
use crate::serve::{CryptoResItem, EncryptItem, SecretType};
use anyhow::{ensure, Context, Result};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use tracing::debug;

pub fn init() -> Result<()> {
    let passphrase_result = load_passcode_ciphers();
    if passphrase_result.is_ok() {
        Err(anyhow::anyhow!(
            "Error: already initialized? Please delete keys in keychain of 'rusty.vault' first"
        ))?;
        std::process::exit(1);
    }
    create_and_save_passcode_passphrase(&AesGcmCrypto::generate_key(), None)?;
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

fn prompt_input_password(prompt_before: &str, prompt_after: &str) -> Result<String> {
    let secret = rpassword::prompt_password(prompt_before).context("Failed to read password")?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(anyhow::anyhow!("Secret cannot be empty"));
    }
    println!(
        "{}{}****{}",
        prompt_after,
        &secret[..2],
        &secret[secret.len() - 2..]
    );
    Ok(secret.to_string())
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

    let secret = prompt_input_password("Enter secret: ", "Secret entered: ")?;
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
    input_file: Option<String>,
    output_file: Option<String>,
    timeout: u32,
    mut args: Vec<String>,
) -> Result<()> {
    let input_file_content = if let Some(input_file) = input_file {
        debug!("Reading input file: {}", input_file);
        if !std::path::Path::new(&input_file).exists() {
            return Err(anyhow::anyhow!("Input file does not exist: {}", input_file));
        }
        std::fs::read_to_string(&input_file)
            .with_context(|| format!("Failed to read input file: {}", input_file))?
    } else {
        debug!("No input file provided, using empty content");
        String::new()
    };
    args.push(input_file_content);

    let env_vars: HashMap<String, String> = env::vars().collect();
    let env_json_str = serde_json::to_string(&env_vars)?;
    debug!("Environment variables JSON: {}", env_json_str);
    args.push(env_json_str);

    let mut decrypted_args = decrypt_from_multi_str(vt_client, args).await?;

    let decrypted_env_json_str = decrypted_args.pop().unwrap();
    let env_map: HashMap<String, String> = serde_json::from_str(&decrypted_env_json_str).unwrap();
    for (key, value) in env_map {
        env::set_var(key, value);
    }

    let output_file_content = decrypted_args.pop().unwrap();
    if let Some(output_file_path) = &output_file {
        std::fs::write(output_file_path, &output_file_content)
            .with_context(|| format!("Failed to write to output file: {}", output_file_path))?;
        debug!("Content written to: {}", output_file_path);
    } else {
        print!("{}", output_file_content);
    }

    if timeout > 0 {
        if let Some(file_to_delete) = output_file {
            // Fork the process to handle file deletion in the background.
            // This is `unsafe` because it can violate Rust's memory safety guarantees,
            // especially in a multi-threaded context. However, for our simple case
            // where the child process only sleeps and deletes a file, it's acceptable.
            let pid = unsafe { libc::fork() };

            if pid > 0 {
                // Parent process: Continue to the exec call.
                debug!("Spawned cleanup process with PID: {}", pid);
            } else if pid == 0 {
                // Child process: Sleep, delete the file, and exit.
                // Using std::thread::sleep instead of tokio::time::sleep is safer after a fork.
                std::thread::sleep(std::time::Duration::from_secs(timeout as u64));
                if let Err(e) = std::fs::remove_file(&file_to_delete) {
                    // The child is detached, so logging might not be visible.
                    // For now, we'll just note that the deletion failed.
                    eprintln!("Child process failed to delete output file: {}", e);
                }
                // The child's work is done, it must exit.
                std::process::exit(0);
            } else {
                // Fork failed.
                return Err(anyhow::anyhow!(
                    "Failed to fork cleanup process: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }

    if decrypted_args.is_empty() {
        debug!("No command to execute, exiting.");
        return Ok(());
    }

    // Execute the command with decrypted arguments
    let command = &decrypted_args[0];
    let args = &decrypted_args[1..];

    debug!("Executing command: {} with args: {:?}", command, args);

    let err = exec::Command::new(command).args(args).exec();

    Err(anyhow::anyhow!("Failed to execute command: {}", err))
}

pub async fn export_secret() -> Result<()> {
    if !local_authentication("export master secret") {
        Err(anyhow::anyhow!(
            "Local authentication failed for export master secret"
        ))?;
    }
    let (_, _, passphrase_cipher) = load_passcode_ciphers()?;
    let encrypted_passphrase = get_keychain("passphrase")?;
    let decrypted_passphrase = passphrase_cipher
        .decrypt(&encrypted_passphrase)
        .context("Failed to decrypt passphrase")?;

    let master_secret_passphrase = prompt_input_password(
        "Enter master secret passphrase: ",
        "Master secret passphrase entered: ",
    )?;
    let hash = Sha256::digest(&Sha256::digest(master_secret_passphrase.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    let export_cipher =
        AesGcmCrypto::new(&key).context("Failed to create AES-GCM cipher for master secret")?;

    let new_encrypted_passphrase_bytes = export_cipher
        .encrypt(&decrypted_passphrase)
        .context("Failed to encrypt master secret passphrase")?;
    println!(
        "Encrypted master secret passphrase (base64): {}",
        BASE64_URL_SAFE_NO_PAD.encode(new_encrypted_passphrase_bytes)
    );

    Ok(())
}

pub async fn import_secret() -> Result<()> {
    let passphrase_result = load_passcode_ciphers();
    if passphrase_result.is_ok() {
        Err(anyhow::anyhow!(
            "Error: already imported? Please delete keys in keychain of 'rusty.vault' first"
        ))?;
        std::process::exit(1);
    }
    let master_secret = prompt_input_password("Enter master secret: ", "Master secret entered: ")?;
    let encrypted_passphrase_bytes = BASE64_URL_SAFE_NO_PAD.decode(master_secret)?;

    let master_secret_passphrase = prompt_input_password(
        "Enter master secret passphrase: ",
        "Master secret passphrase entered: ",
    )?;
    let hash = Sha256::digest(&Sha256::digest(master_secret_passphrase.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    let import_cipher =
        AesGcmCrypto::new(&key).context("Failed to create AES-GCM cipher for master secret")?;

    let vt_path = env::current_exe().unwrap().to_string_lossy().to_string();
    print!("Enter absolute path of vt (Default: {}): ", vt_path);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().is_empty() {
        input = vt_path;
    } else {
        input = input.trim().to_string();
    }

    let real_passphrase = import_cipher.decrypt(&encrypted_passphrase_bytes)?;
    let passphrase_array: [u8; 32] = real_passphrase
        .try_into()
        .map_err(|_| anyhow::anyhow!("Decrypted passphrase must be exactly 32 bytes"))?;

    create_and_save_passcode_passphrase(&passphrase_array, Some(&input))
        .context("Failed to create and save passcode passphrase")?;

    Ok(())
}

pub async fn rotate_passcode(bin_absolute_path: Option<String>) -> Result<()> {
    if !local_authentication("rotate passcode") {
        Err(anyhow::anyhow!(
            "Local authentication failed for rotate passcode"
        ))?;
    }
    let (_, _, passphrase_cipher) = load_passcode_ciphers()?;
    let encrypted_passphrase = get_keychain("passphrase")?;
    let decrypted_passphrase = passphrase_cipher
        .decrypt(&encrypted_passphrase)
        .context("Failed to decrypt passphrase")?;
    let passphrase_array: [u8; 32] = decrypted_passphrase
        .try_into()
        .map_err(|_| anyhow::anyhow!("Decrypted passphrase must be exactly 32 bytes"))?;
    create_and_save_passcode_passphrase(&passphrase_array, bin_absolute_path.as_deref())?;
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
