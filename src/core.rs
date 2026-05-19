pub mod crypto;
pub mod session;
pub mod wire;

use crate::core::crypto::AesGcmCrypto;

use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroizing;

// ---- Public types -----------------------------------------------------------

/// Per-record envelope salt (also reused as the AES-GCM nonce via `salt[..12]`).
pub const SALT_LEN: usize = 16;
/// AES-GCM nonce length (RFC 5116).
pub const NONCE_LEN: usize = 12;
/// AES-GCM tag length.
pub const TAG_LEN: usize = 16;
/// Minimum v2 blob length: salt + tag (empty plaintext).
pub const V2_MIN_BLOB_LEN: usize = SALT_LEN + TAG_LEN;

/// AAD prefix used when encrypting/decrypting v2 records. Concatenated with
/// the literal type byte (`b'0'` or `b'1'`). Binds ciphertexts to the v2
/// protocol version *and* the secret type, defeating type-flip attacks
/// (e.g. TOTP→RAW to leak the seed instead of a generated code).
pub const V2_AAD_PREFIX: &[u8] = b"vt:v2:";

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EncryptItem {
    pub plaintext: String,
    pub t: SecretType,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthReq {
    pub host: String,
    pub reason: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthRes {
    pub approved: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
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

    /// ASCII byte used in v2 URLs and as the trailing AAD byte.
    pub fn as_byte(&self) -> u8 {
        match self {
            SecretType::RAW => b'0',
            SecretType::TOTP => b'1',
            SecretType::UNKNOWN => b'_',
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

// ---- v2 wire schema ---------------------------------------------------------

/// Request from client → agent for `encrypt@vt`. The agent generates fresh
/// per-record salts (NEVER trust client-supplied salt — see below).
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EncryptReq {
    pub types: Vec<SecretType>,
}

/// One agent-generated `(salt, dek)` pair. Client uses these locally to AEAD
/// encrypt the corresponding plaintext and assemble the v2 URL. The DEK
/// crosses the wire encrypted under `auth_cipher` (same as legacy plaintext
/// did) and is zeroized after use on both sides.
///
/// NOTE: there is intentionally no `salt` field on the *request* side. Letting
/// a client supply a salt would let an attacker holding `VT_AUTH` extract the
/// salt from a stored `vt://0{salt||ct}` URL, request its DEK via
/// `encrypt@vt` (no Touch ID), and decrypt the ciphertext locally — bypassing
/// the Touch ID gate that protects `decrypt@vt`. Salt MUST originate inside
/// the agent.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EncryptResItem {
    pub salt: [u8; SALT_LEN],
    pub dek: [u8; 32],
    pub err_message: String,
}

/// One item in a `decrypt@vt` request. v2 items carry only the salt; the
/// inner ciphertext is decrypted locally by the client. Legacy items carry
/// the full URL string and continue to be decrypted server-side until users
/// have migrated.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum DecryptInput {
    /// v2: `vt://{type}{b64(salt||ct)}` — agent only sees the salt.
    V2 {
        t: SecretType,
        salt: [u8; SALT_LEN],
    },
    /// Legacy v0/v1: `vt://mac/{type}{b64(ct)}` — agent decrypts and may run
    /// TOTP server-side (legacy behavior).
    Legacy { url: String },
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DecryptReq {
    pub host: String,
    pub command: String,
    pub items: Vec<DecryptInput>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum DecryptResItem {
    /// Per-record DEK; client uses it to decrypt the inner ciphertext locally.
    V2 {
        dek: [u8; 32],
        err_message: String,
    },
    /// Plaintext or legacy-side-computed TOTP code.
    Legacy {
        result: String,
        err_message: String,
    },
}

// ---- v2 URL parsing ---------------------------------------------------------

/// Parsed `vt://...` URL. Strict parser (no `url::Url`, no normalization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VtUrl {
    /// New envelope format: `vt://{type}{b64(salt(16)||ct||tag(16))}`.
    V2 {
        t: SecretType,
        salt: [u8; SALT_LEN],
        inner_ct: Vec<u8>,
    },
    /// Legacy: `vt://mac/{type}{b64(nonce(12)||ct||tag(16))}`.
    Legacy { t: SecretType, body_b64: String },
}

impl VtUrl {
    pub fn parse(s: &str) -> Result<Self> {
        // Legacy first: it has the longer prefix.
        if let Some(rest) = s.strip_prefix("vt://mac/") {
            // Use byte-level access so a non-ASCII first byte doesn't panic
            // via `&rest[..1]` slicing at a non-char boundary. Reachable from
            // attacker-supplied URLs flowing into legacy_decrypt on the agent.
            let &first = rest
                .as_bytes()
                .first()
                .ok_or_else(|| anyhow::anyhow!("empty legacy vt body"))?;
            ensure!(first.is_ascii(), "legacy vt type byte must be ASCII");
            let type_buf = [first];
            let t = SecretType::from_str(std::str::from_utf8(&type_buf).unwrap());
            let body_b64 = rest[1..].to_string();
            ensure!(
                body_b64.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
                }),
                "legacy vt body must be base64url-no-pad"
            );
            return Ok(VtUrl::Legacy { t, body_b64 });
        }
        // v2: `vt://{type}{b64}`. No further `/` allowed.
        if let Some(rest) = s.strip_prefix("vt://") {
            ensure!(!rest.contains('/'), "v2 vt URL must not contain '/'");
            // Same panic-safety concern as the legacy arm above.
            let &first = rest
                .as_bytes()
                .first()
                .ok_or_else(|| anyhow::anyhow!("empty v2 vt body"))?;
            ensure!(first.is_ascii(), "v2 vt type byte must be ASCII");
            ensure!(rest.len() >= 2, "v2 vt URL too short");
            let type_buf = [first];
            let type_str = std::str::from_utf8(&type_buf).unwrap();
            let t = SecretType::from_str(type_str);
            // Type must be a known v2 type byte (`0` or `1`); reject `_`/UNKNOWN.
            ensure!(
                matches!(t, SecretType::RAW | SecretType::TOTP),
                "unknown v2 secret type: {}",
                type_str
            );
            let body_b64 = &rest[1..];
            let blob = BASE64_URL_SAFE_NO_PAD
                .decode(body_b64.as_bytes())
                .map_err(|e| anyhow::anyhow!("v2 base64 decode error: {}", e))?;
            ensure!(
                blob.len() >= V2_MIN_BLOB_LEN,
                "v2 blob too short ({} bytes; need >= {})",
                blob.len(),
                V2_MIN_BLOB_LEN
            );
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&blob[..SALT_LEN]);
            let inner_ct = blob[SALT_LEN..].to_vec();
            return Ok(VtUrl::V2 { t, salt, inner_ct });
        }
        Err(anyhow::anyhow!("not a vt URL: must start with vt://"))
    }
}

/// Format a v2 envelope into its canonical URL representation.
pub fn format_v2_url(t: SecretType, salt: &[u8; SALT_LEN], inner_ct: &[u8]) -> String {
    let mut blob = Vec::with_capacity(SALT_LEN + inner_ct.len());
    blob.extend_from_slice(salt);
    blob.extend_from_slice(inner_ct);
    format!("vt://{}{}", t, BASE64_URL_SAFE_NO_PAD.encode(&blob))
}

/// Build the AAD bound to a single v2 record: `b"vt:v2:" || type_byte`.
fn v2_aad(t: SecretType) -> [u8; 7] {
    let mut aad = [0u8; 7];
    aad[..6].copy_from_slice(V2_AAD_PREFIX);
    aad[6] = t.as_byte();
    aad
}

// ---- Client-side v2 crypto --------------------------------------------------

/// Encrypt one record locally with a (salt, dek) pair allocated by the agent.
/// Returns the canonical v2 URL string.
pub fn client_encrypt_v2(
    t: SecretType,
    salt: &[u8; SALT_LEN],
    dek: &[u8; 32],
    plaintext: &[u8],
) -> Result<String> {
    let cipher = AesGcmCrypto::new(dek)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&salt[..NONCE_LEN]);
    let aad = v2_aad(t);
    let inner_ct = cipher.encrypt_with_nonce_and_aad(&nonce, plaintext, &aad)?;
    Ok(format_v2_url(t, salt, &inner_ct))
}

/// Decrypt one v2 record locally given the agent-released DEK. For TOTP
/// records (`type=1`), runs `TOTP::generate_current()` on the recovered seed
/// and zeroizes the seed buffer; returns the 6-digit code. For RAW, returns
/// the recovered plaintext.
pub fn client_decrypt_v2(
    t: SecretType,
    dek: &[u8; 32],
    salt: &[u8; SALT_LEN],
    inner_ct: &[u8],
) -> Result<String> {
    let cipher = AesGcmCrypto::new(dek)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&salt[..NONCE_LEN]);
    let aad = v2_aad(t);
    let plaintext: Zeroizing<Vec<u8>> =
        cipher.decrypt_with_nonce_and_aad(&nonce, inner_ct, &aad)?;
    match t {
        SecretType::RAW => {
            let s = String::from_utf8(plaintext.to_vec())
                .map_err(|e| anyhow::anyhow!("v2 raw plaintext utf8 error: {}", e))?;
            Ok(s)
        }
        SecretType::TOTP => {
            // Seed is base32-encoded. We decode and immediately run TOTP in a
            // tight scope. KNOWN LIMITATION: `Secret::Encoded(_).to_bytes()`
            // and `TOTP::new_unchecked` both internalize the seed in plain
            // `String`/`Vec<u8>` (totp_rs does not implement `Zeroize`), so
            // the raw seed bytes linger unzeroized in the heap until those
            // values drop. The lifetime is one function call; if you need
            // stronger zeroization here, this branch needs a TOTP impl that
            // exposes a `Zeroize` API or runs the computation in a subprocess.
            let seed_str = std::str::from_utf8(&plaintext)
                .map_err(|e| anyhow::anyhow!("v2 totp seed utf8 error: {}", e))?;
            let seed_bytes = Secret::Encoded(seed_str.to_string())
                .to_bytes()
                .map_err(|e| anyhow::anyhow!("TOTP secret encode error: {}", e))?;
            let code = {
                let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, seed_bytes);
                let code = totp
                    .generate_current()
                    .map_err(|e| anyhow::anyhow!("TOTP generate error: {}", e))?;
                drop(totp);
                code
            };
            Ok(code)
        }
        SecretType::UNKNOWN => Err(anyhow::anyhow!("unknown v2 secret type")),
    }
}

// ---- Agent-side legacy decrypt ---------------------------------------------

/// Server-side decryption of legacy v0/v1 URLs. Preserves the pre-envelope
/// behavior: agent decrypts the ciphertext with the master cipher, and for
/// `type=1` runs TOTP server-side (legacy clients expected the 6-digit code,
/// not the seed). Used during the migration window.
pub fn legacy_decrypt(mac_cipher: &AesGcmCrypto, url: &str) -> CryptoResItem {
    let result: Result<String> = (|| {
        let parsed = VtUrl::parse(url)?;
        let (t, body_b64) = match parsed {
            VtUrl::Legacy { t, body_b64 } => (t, body_b64),
            VtUrl::V2 { .. } => {
                return Err(anyhow::anyhow!(
                    "legacy_decrypt called on a v2 URL"
                ))
            }
        };
        let raw = BASE64_URL_SAFE_NO_PAD
            .decode(body_b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("base64 decode error: {}", e))?;
        let plaintext = mac_cipher.decrypt(&raw)?;
        let plaintext_str = String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("decryption error: {}", e))?;
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

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::derive_dek;

    fn fixture_dek() -> [u8; 32] {
        let mac_key = [0x42u8; 32];
        let salt = [0x11u8; SALT_LEN];
        derive_dek(&mac_key, &salt)
    }

    #[test]
    fn v2_url_roundtrip() {
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        let url = client_encrypt_v2(SecretType::RAW, &salt, &dek, b"hello").unwrap();
        assert!(url.starts_with("vt://0"), "got: {}", url);
        assert!(!url.contains("mac/"), "v2 URL must not contain `mac/`");

        let parsed = VtUrl::parse(&url).unwrap();
        match parsed {
            VtUrl::V2 { t, salt: s, inner_ct } => {
                assert_eq!(t, SecretType::RAW);
                assert_eq!(s, salt);
                let pt = client_decrypt_v2(t, &dek, &s, &inner_ct).unwrap();
                assert_eq!(pt, "hello");
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn v2_blob_layout_known_vector() {
        // Salt + inner_ct length must equal SALT_LEN + plaintext.len() + TAG_LEN
        // — proves no extra nonce prefix slipped in.
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        let url = client_encrypt_v2(SecretType::RAW, &salt, &dek, b"").unwrap();
        let body_b64 = url.strip_prefix("vt://0").unwrap();
        let blob = BASE64_URL_SAFE_NO_PAD.decode(body_b64).unwrap();
        assert_eq!(blob.len(), SALT_LEN + TAG_LEN);
        assert_eq!(&blob[..SALT_LEN], &salt[..]);
    }

    #[test]
    fn v2_aad_type_tamper_rejected() {
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        // Encrypt as TOTP, then try to decrypt as RAW — type byte is in AAD,
        // tag must mismatch.
        let url = client_encrypt_v2(SecretType::TOTP, &salt, &dek, b"JBSWY3DPEHPK3PXP").unwrap();
        let parsed = VtUrl::parse(&url).unwrap();
        if let VtUrl::V2 { salt, inner_ct, .. } = parsed {
            let bad = client_decrypt_v2(SecretType::RAW, &dek, &salt, &inner_ct);
            assert!(bad.is_err(), "RAW decrypt of TOTP-AAD ciphertext must fail");
        } else {
            panic!("expected V2");
        }
    }

    #[test]
    fn v2_salt_tamper_rejected() {
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        let url = client_encrypt_v2(SecretType::RAW, &salt, &dek, b"abc").unwrap();
        let mut parsed = VtUrl::parse(&url).unwrap();
        if let VtUrl::V2 { ref mut salt, .. } = parsed {
            salt[0] ^= 0xFF; // flip a salt byte
        }
        if let VtUrl::V2 { t, salt, inner_ct } = parsed {
            // Salt is fed into HKDF (different DEK) and as nonce — both change,
            // but the test caller doesn't re-derive DEK; it uses the original
            // dek, which simulates an attacker mutating the URL. Tag must fail.
            let bad = client_decrypt_v2(t, &dek, &salt, &inner_ct);
            assert!(bad.is_err());
        }
    }

    #[test]
    fn parse_rejects_short_v2_blob() {
        // 12 bytes is shorter than V2_MIN_BLOB_LEN (32).
        let bad = format!(
            "vt://0{}",
            BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 12])
        );
        assert!(VtUrl::parse(&bad).is_err());
    }

    #[test]
    fn parse_rejects_extra_slash_in_v2() {
        // `vt://0/abcd` would be a v2 path but contains a `/`.
        let bad = "vt://0/abcdefghij";
        assert!(VtUrl::parse(bad).is_err());
    }

    #[test]
    fn parse_legacy_still_works() {
        let s = "vt://mac/0AAAAAAAAAA";
        let parsed = VtUrl::parse(s).unwrap();
        match parsed {
            VtUrl::Legacy { t, body_b64 } => {
                assert_eq!(t, SecretType::RAW);
                assert_eq!(body_b64, "AAAAAAAAAA");
            }
            _ => panic!("expected Legacy"),
        }
    }

    #[test]
    fn parse_rejects_non_ascii_v2_type_byte() {
        // Reachable via attacker-controlled `DecryptInput::Legacy { url }`; must
        // not panic on byte-slicing at a non-char boundary.
        let bad = "vt://é-padding";
        let res = VtUrl::parse(bad);
        assert!(res.is_err(), "non-ASCII v2 type byte must be rejected");
    }

    #[test]
    fn parse_rejects_non_ascii_legacy_type_byte() {
        let bad = "vt://mac/é-padding";
        let res = VtUrl::parse(bad);
        assert!(res.is_err(), "non-ASCII legacy type byte must be rejected");
    }

    #[test]
    fn parse_rejects_empty_legacy_body() {
        let res = VtUrl::parse("vt://mac/");
        assert!(res.is_err());
    }

    #[test]
    fn parse_rejects_empty_v2_body() {
        let res = VtUrl::parse("vt://");
        assert!(res.is_err());
    }

    #[test]
    fn parse_rejects_non_vt() {
        assert!(VtUrl::parse("http://example.com").is_err());
        assert!(VtUrl::parse("vt:/0abc").is_err());
        assert!(VtUrl::parse("").is_err());
    }

    #[test]
    fn parse_rejects_unknown_v2_type() {
        // Type byte `_` is reserved for UNKNOWN; v2 must reject.
        let bad = format!(
            "vt://_{}",
            BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 32])
        );
        assert!(VtUrl::parse(&bad).is_err());
    }

    #[test]
    fn legacy_decrypt_v2_url_errors() {
        // legacy_decrypt only handles legacy URLs.
        let key = [0xAAu8; 32];
        let cipher = AesGcmCrypto::new(&key).unwrap();
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        let v2 = client_encrypt_v2(SecretType::RAW, &salt, &dek, b"x").unwrap();
        let res = legacy_decrypt(&cipher, &v2);
        assert!(!res.err_message.is_empty());
    }

    #[test]
    fn v2_url_does_not_contain_mac_segment() {
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        for t in [SecretType::RAW, SecretType::TOTP] {
            let url = client_encrypt_v2(t, &salt, &dek, b"x").unwrap();
            assert!(!url.contains("mac/"), "url must not contain mac/: {}", url);
            assert!(url.starts_with("vt://"));
        }
    }
}
