pub mod crypto;
pub mod session;

use crate::core::crypto::AesGcmCrypto;

use anyhow::Result;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

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

#[derive(Deserialize, Serialize)]
pub struct AuthReq {
    pub host: String,
    pub reason: String,
}

#[derive(Deserialize, Serialize)]
pub struct AuthRes {
    pub approved: bool,
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
            if item.is_empty() {
                Err(anyhow::anyhow!("empty vt item after prefix"))
            } else {
                match SecretType::from_str(item[..1].as_ref()) {
                    SecretType::RAW => b64_to_decrypted(&item[1..]),
                    SecretType::TOTP => match b64_to_decrypted(&item[1..]) {
                        Ok(decrypted_str) => match Secret::Encoded(decrypted_str).to_bytes() {
                            Ok(secret_bytes) => {
                                TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret_bytes)
                                    .generate_current()
                                    .map_err(|e| anyhow::anyhow!("TOTP generate error: {}", e))
                            }
                            Err(e) => Err(anyhow::anyhow!("TOTP secret encode error: {}", e)),
                        },
                        Err(e) => Err(e),
                    },
                    SecretType::UNKNOWN => Err(anyhow::anyhow!("unknown secret type")),
                }
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
