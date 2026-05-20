// CF ceremony client — POST /api/challenge + WS /api/dek.
//
// Called by client.rs when the SSH agent path is unavailable (Linux, or macOS
// without a running vt ssh agent). The ceremony:
//
//   1. Load cf_config.json (worker_url + worker_auth).
//   2. Generate ephemeral X25519 keypair and per-DEK salts (16 B each).
//   3. POST /api/challenge  →  approve_url, poll_token, worker_nonce.
//   4. Print approve_url to stderr.
//   5. Open WS to /api/dek?poll_token=X.
//   6. Wait for {"status":"approved","sealed_deks_b64u":"..."}.
//   7. Open sealed_box → n DEKs (32 bytes each).
//   8. Return DEKs to caller; ephemeral secret key is wiped on drop.
//
// master_key never leaves the user's phone. The daemon never holds it.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dryoc::classic::crypto_box::{crypto_box_keypair, crypto_box_seal_open, PublicKey, SecretKey};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use zeroize::Zeroizing;

// ── Salt generation ─────────────────────────────────────────────────────────

/// Generate `n` fresh random 16-byte salts for encryption operations.
pub fn random_salts(n: usize) -> Vec<[u8; 16]> {
    (0..n)
        .map(|_| {
            let mut s = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut s);
            s
        })
        .collect()
}

// ── Config ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CfConfig {
    pub worker_url: String,
    pub worker_auth: String,
}

pub fn load_config() -> Result<CfConfig> {
    let path = config_path();
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", path.display()))
}

fn config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/vt/cf_config.json")
}

// ── Path prefix ────────────────────────────────────────────────────────────

fn derive_path_prefix(worker_auth: &str) -> String {
    let mac = hmac_sha256(worker_auth.as_bytes(), b"vt-path-prefix");
    let b64 = URL_SAFE_NO_PAD.encode(mac);
    b64[..16].to_string()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hmac_auth_header(worker_auth: &str, body: &[u8]) -> String {
    let mac = hmac_sha256(worker_auth.as_bytes(), body);
    format!("VT-HMAC {}", URL_SAFE_NO_PAD.encode(mac))
}

// ── Wire types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ChallengeReq<'a> {
    daemon_pubkey_b64u: String,
    timestamp_ms: u64,
    salts_b64u: Vec<String>,
    meta: ChallengeMeta<'a>,
}

#[derive(Serialize)]
pub struct ChallengeMeta<'a> {
    pub op_kind: &'a str,
    pub command: &'a str,
    pub host: &'a str,
    pub ip: &'a str,
    pub reason: &'a str,
}

#[derive(Deserialize)]
struct ChallengeResp {
    poll_token: String,
    approve_url: String,
    #[serde(default)]
    push_warning: String,
}

#[derive(Deserialize)]
struct WsMsg {
    status: String,
    #[serde(default)]
    sealed_deks_b64u: String,
}

// ── Main entry point ───────────────────────────────────────────────────────

/// Run the CF approval ceremony and return one DEK per salt.
///
/// `salts` — per-record salts; pass the salts from vt:// URLs for decrypt,
/// fresh random salts for encrypt, empty for auth-only. The browser derives
/// `DEK[i] = HKDF(master_key, salt[i])` and seals `[DEK...]` back.
pub async fn get_deks(
    config: &CfConfig,
    salts: &[[u8; 16]],
    meta: ChallengeMeta<'_>,
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    // 1. Ephemeral X25519 keypair (PublicKey / SecretKey are [u8; 32] type aliases)
    let (pk, sk) = crypto_box_keypair();
    let pk_b64u = URL_SAFE_NO_PAD.encode(pk);

    let n_deks = salts.len();
    let salts_b64u: Vec<String> = salts.iter().map(|s| URL_SAFE_NO_PAD.encode(s)).collect();

    // 3. POST /api/challenge
    let prefix = derive_path_prefix(&config.worker_auth);
    let challenge_url = format!("{}/{}/api/challenge", config.worker_url, prefix);
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let req_body = serde_json::to_vec(&ChallengeReq {
        daemon_pubkey_b64u: pk_b64u.clone(),
        timestamp_ms: ts_ms,
        salts_b64u: salts_b64u.clone(),
        meta,
    })?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = client
        .post(&challenge_url)
        .header("Authorization", hmac_auth_header(&config.worker_auth, &req_body))
        .header("Content-Type", "application/json")
        .body(req_body)
        .send()
        .await
        .context("POST /api/challenge")?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        bail!("challenge: HTTP {status}: {body}");
    }

    let ch: ChallengeResp = resp.json().await.context("challenge response parse")?;

    if !ch.push_warning.is_empty() {
        eprintln!("vt: push warning: {}", ch.push_warning);
    }
    eprintln!("vt: waiting for Passkey approval…");
    eprintln!("vt: approve at: {}", ch.approve_url);

    // 4. WS /api/dek?poll_token=X
    let ws_url = format!(
        "{}/{}/api/dek?poll_token={}",
        config.worker_url.replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1),
        prefix,
        ch.poll_token
    );

    let (mut ws_stream, _) = connect_async(&ws_url)
        .await
        .with_context(|| format!("WS connect {ws_url}"))?;

    // 5. Wait for approval (up to 6 minutes — DO TTL is 5 min)
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws_stream.next())
            .await
            .map_err(|_| anyhow!("approval timeout (6 min)"))?
            .ok_or_else(|| anyhow!("WS closed without result"))??;

        match msg {
            Message::Text(text) => {
                let ws: WsMsg = serde_json::from_str(&text)
                    .context("WS message parse")?;
                match ws.status.as_str() {
                    "waiting" => continue,
                    "approved" => {
                        if ws.sealed_deks_b64u.is_empty() {
                            bail!("approved message missing sealed_deks_b64u");
                        }
                        return open_sealed_deks(&ws.sealed_deks_b64u, &pk, &sk, n_deks);
                        #[allow(unreachable_code)] { drop(ws_stream); }
                    }
                    "rejected" => bail!("approval rejected by user"),
                    "expired"  => bail!("approval request expired"),
                    other => bail!("unexpected WS status: {other}"),
                }
            }
            Message::Close(_) => bail!("WS closed unexpectedly"),
            _ => continue,
        }
    }
}

fn open_sealed_deks(
    sealed_b64u: &str,
    pk: &PublicKey,
    sk: &SecretKey,
    n_deks: usize,
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    let ct = URL_SAFE_NO_PAD.decode(sealed_b64u)
        .context("sealed_deks b64u decode")?;

    // sealed_box overhead = 48 bytes (ephemeral pk 32 + mac 16)
    // plaintext = max(n_deks, 1) * 32 bytes (at least 1 even for auth-only)
    let n = n_deks.max(1);
    let expected_len = n * 32 + 48;
    if ct.len() != expected_len {
        bail!("sealed_box length {} != expected {}", ct.len(), expected_len);
    }

    let mut pt = vec![0u8; n * 32];
    crypto_box_seal_open(&mut pt, &ct, pk, sk)
        .map_err(|_| anyhow!("sealed_box open failed — possible MITM or wrong key"))?;

    // Auth-only: n_deks == 0, we just needed the approval — return no DEKs.
    if n_deks == 0 {
        pt.iter_mut().for_each(|b| *b = 0);
        return Ok(Vec::new());
    }

    let mut deks: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(n_deks);
    for i in 0..n_deks {
        let mut dek = Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&pt[i * 32..(i + 1) * 32]);
        deks.push(dek);
    }
    pt.iter_mut().for_each(|b| *b = 0);
    Ok(deks)
}
