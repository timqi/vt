//! Legacy v0/v1 record compatibility, not Keychain wrap_v compatibility.

use super::{crypto::AesGcmCrypto, CryptoResItem, SecretType, VtUrl};
use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use totp_rs::{Algorithm, Secret, TOTP};

pub(super) fn parse_legacy(rest: &str) -> Result<VtUrl> {
    // Byte access prevents non-ASCII type bytes from panicking on a slice.
    // This also handles untrusted URLs forwarded to legacy_decrypt.
    let &first = rest
        .as_bytes()
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty legacy vt body"))?;
    ensure!(first.is_ascii(), "legacy vt type byte must be ASCII");
    let type_buf = [first];
    let t = SecretType::from_str(std::str::from_utf8(&type_buf).unwrap());
    let body_b64 = rest[1..].to_string();
    ensure!(
        body_b64
            .bytes()
            .all(|b| { b.is_ascii_alphanumeric() || b == b'-' || b == b'_' }),
        "legacy vt body must be base64url-no-pad"
    );
    Ok(VtUrl::Legacy { t, body_b64 })
}

/// Server-side decryption of legacy v0/v1 URLs. Preserves the pre-envelope
/// behavior: agent decrypts the ciphertext with the master cipher, and for
/// `type=1` runs TOTP server-side (legacy clients expected the 6-digit code,
/// not the seed). Used during the migration window.
pub fn legacy_decrypt(mac_cipher: &AesGcmCrypto, url: &str) -> CryptoResItem {
    let result: Result<String> = (|| {
        let parsed = VtUrl::parse(url)?;
        let (t, body_b64) = match parsed {
            VtUrl::Legacy { t, body_b64 } => (t, body_b64),
            VtUrl::V2 { .. } => return Err(anyhow::anyhow!("legacy_decrypt called on a v2 URL")),
        };
        let raw = BASE64_URL_SAFE_NO_PAD
            .decode(body_b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("base64 decode error: {}", e))?;
        let plaintext = mac_cipher.decrypt(&raw)?;
        let plaintext_str =
            String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("decryption error: {}", e))?;
        match t {
            SecretType::RAW => Ok(plaintext_str),
            SecretType::TOTP => {
                let seed_bytes = Secret::Encoded(plaintext_str)
                    .to_bytes()
                    .map_err(|e| anyhow::anyhow!("TOTP secret encode error: {}", e))?;
                TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, seed_bytes)
                    .generate_current()
                    .map_err(|e| anyhow::anyhow!("TOTP generate error: {}", e))
            }
            SecretType::UNKNOWN => Err(anyhow::anyhow!("unknown secret type")),
        }
    })();
    match result {
        Ok(decrypted_value) => CryptoResItem {
            result: decrypted_value,
            err_message: String::new(),
        },
        Err(e) => CryptoResItem {
            result: String::new(),
            err_message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_parser_retains_permissive_type_and_body_compatibility() {
        for (body, t, body_b64) in [
            ("0", SecretType::RAW, ""),
            ("1YWJj", SecretType::TOTP, "YWJj"),
            ("_YWJj", SecretType::UNKNOWN, "YWJj"),
            ("xAA-_", SecretType::UNKNOWN, "AA-_"),
        ] {
            assert_eq!(
                VtUrl::parse(&format!("vt://mac/{body}")).unwrap(),
                VtUrl::Legacy {
                    t,
                    body_b64: body_b64.into()
                }
            );
        }
    }

    #[test]
    fn legacy_parser_preserves_errors_without_unicode_slicing_panics() {
        for (body, message) in [
            ("", "empty legacy vt body"),
            ("\u{00e9}-padding", "legacy vt type byte must be ASCII"),
            ("0abc=", "legacy vt body must be base64url-no-pad"),
            ("0abc/def", "legacy vt body must be base64url-no-pad"),
            ("0abc\n", "legacy vt body must be base64url-no-pad"),
        ] {
            assert_eq!(
                VtUrl::parse(&format!("vt://mac/{body}"))
                    .unwrap_err()
                    .to_string(),
                message
            );
        }
    }

    #[test]
    fn legacy_decrypt_keeps_raw_values_and_per_item_failure_shape() {
        let cipher = AesGcmCrypto::new(&[3; 32]).unwrap();
        let body = BASE64_URL_SAFE_NO_PAD.encode(cipher.encrypt(b"fixture").unwrap());
        let raw = legacy_decrypt(&cipher, &format!("vt://mac/0{body}"));
        assert!(raw.err_message.is_empty());
        assert_eq!(raw.result, "fixture");
        let unknown = legacy_decrypt(&cipher, &format!("vt://mac/_{body}"));
        assert!(unknown.result.is_empty());
        assert_eq!(unknown.err_message, "unknown secret type");
        for url in ["vt://mac/0A", "vt://mac/0", "not-vt"] {
            let result = legacy_decrypt(&cipher, url);
            assert!(result.result.is_empty());
            assert!(!result.err_message.is_empty());
        }
    }
}
