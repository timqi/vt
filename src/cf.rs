// CF ceremony client — POST /api/challenge + WS /api/dek.
//
// Called by client.rs when the SSH agent path is unavailable (Linux, or macOS
// without a running vt ssh agent). The ceremony:
//
//   1. Read VT_PASSKEY_URL + VT_PASSKEY_TOKEN from the environment.
//   2. Generate ephemeral X25519 keypair and per-DEK salts (16 B each).
//   3. POST /api/challenge  →  approve_url, poll_token, worker_nonce.
//   4. Print approve_url to stderr.
//   5. Open WS to /api/dek?poll_token=X.
//   6. Wait for {"status":"approved","sealed_deks_b64u":"..."}.
//   7. Open sealed_box → n DEKs (32 bytes each).
//   8. Return DEKs to caller; ephemeral secret key is wiped on drop.
//
// master_key never leaves the user's phone. The daemon never holds it.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dryoc::classic::crypto_box::{crypto_box_keypair, crypto_box_seal_open, PublicKey, SecretKey};
use dryoc::classic::crypto_core::crypto_scalarmult;
use futures_util::StreamExt;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use zeroize::Zeroizing;

use crate::core::sanitize_for_display as sanitize;

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

#[derive(Debug)]
pub struct CfConfig {
    pub worker_url: String,
    pub worker_auth: String,
}

/// Read the CF worker URL + HMAC token from the environment.
///
/// Both vars are required: there is no file fallback and no implicit default,
/// so a misconfigured host fails fast rather than silently calling the wrong
/// worker.
pub fn load_config() -> Result<CfConfig> {
    let worker_url = std::env::var("VT_PASSKEY_URL")
        .context("VT_PASSKEY_URL not set")?;
    let worker_auth = std::env::var("VT_PASSKEY_TOKEN")
        .context("VT_PASSKEY_TOKEN not set")?;
    if worker_url.trim().is_empty() {
        bail!("VT_PASSKEY_URL is empty");
    }
    if worker_auth.trim().is_empty() {
        bail!("VT_PASSKEY_TOKEN is empty");
    }
    Ok(CfConfig { worker_url, worker_auth })
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

fn decode_b64u_exact<const N: usize>(b64u: &str, what: &str) -> Result<[u8; N]> {
    let v = URL_SAFE_NO_PAD.decode(b64u)
        .with_context(|| format!("{what}: b64u decode"))?;
    v.as_slice().try_into()
        .map_err(|_| anyhow!("{what}: wrong length (expected {N})"))
}

// ── Wire types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ChallengeReq {
    daemon_pubkey_b64u: String,
    timestamp_ms: u64,
    salts_b64u: Vec<String>,
    meta: ChallengeMeta,
}

/// Display-only context shown on the phone's approval page. None of these
/// fields are bound into `challenge_hash`; they exist to help the human
/// recognize "is this my session, in the place I expect?" before tapping
/// approve. The CLI fills them; the worker forwards them; the PWA renders
/// them. All strings are sanitized (control chars stripped, length-capped)
/// before they leave this process.
#[derive(Serialize, Default)]
pub struct ChallengeMeta {
    pub op_kind: String,
    pub command: String,
    pub host: String,
    pub user: String,
    pub pwd: String,
    pub tty: String,
    pub ppid_cmd: String,
    pub ssh_client: String,
    pub reason: String,
}

/// Build a `ChallengeMeta` by collecting local context from the running
/// process: hostname, $USER, cwd, controlling TTY, parent process command
/// line, and SSH_CLIENT/SSH_CONNECTION. The caller supplies the three
/// fields it already knows (`op_kind`, `command`, `reason`).
pub fn collect_meta(op_kind: &str, command: &str, reason: &str) -> ChallengeMeta {
    let client = collect_client_meta();
    ChallengeMeta {
        op_kind: sanitize(op_kind, 32),
        command: sanitize(command, 300),
        host: sanitize(&crate::client::get_hostname(), 100),
        user: client.user,
        pwd: client.pwd,
        tty: client.tty,
        ppid_cmd: client.ppid_cmd,
        ssh_client: client.ssh_client,
        reason: sanitize(reason, 200),
    }
}

/// Collect the per-process display fields shared by both the CF ceremony
/// (phone approval page) and the SSH-agent (Touch ID prompt) paths. Strings
/// are pre-sanitized (control chars stripped, length-capped).
pub fn collect_client_meta() -> crate::core::ClientMeta {
    crate::core::ClientMeta {
        user: sanitize(&username(), 64),
        pwd: sanitize(&cwd(), 200),
        tty: sanitize(&tty_name(), 40),
        ppid_cmd: sanitize(&parent_cmd(), 200),
        ssh_client: sanitize(&ssh_client_env(), 100),
    }
}

fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default()
}

fn cwd() -> String {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

#[cfg(unix)]
fn tty_name() -> String {
    // ttyname(3) on stdin; returns NULL if stdin isn't a TTY (cron, pipes).
    unsafe {
        let p = libc::ttyname(0);
        if p.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}
#[cfg(not(unix))]
fn tty_name() -> String { String::new() }

#[cfg(unix)]
fn parent_cmd() -> String {
    let ppid = unsafe { libc::getppid() };
    if ppid <= 0 {
        return String::new();
    }
    // Linux: /proc/<ppid>/cmdline is NUL-separated argv.
    #[cfg(target_os = "linux")]
    {
        if let Ok(buf) = std::fs::read(format!("/proc/{ppid}/cmdline")) {
            let parts: Vec<String> = buf
                .split(|b| *b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect();
            if !parts.is_empty() {
                return parts.join(" ");
            }
        }
    }
    // Fallback (macOS / no procfs): shell out to `ps`.
    if let Ok(out) = std::process::Command::new("ps")
        .args(["-o", "args=", "-p", &ppid.to_string()])
        .output()
    {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    String::new()
}
#[cfg(not(unix))]
fn parent_cmd() -> String { String::new() }

fn ssh_client_env() -> String {
    std::env::var("SSH_CLIENT")
        .or_else(|_| std::env::var("SSH_CONNECTION"))
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct ChallengeResp {
    poll_token: String,
    approve_url: String,
    worker_nonce_b64u: String,
    #[serde(default)]
    push_warning: String,
}

#[derive(Deserialize)]
struct WsMsg {
    status: String,
    sealed_deks_b64u: Option<String>,
    #[serde(default)]
    pwa_pk_b64u: Option<String>,
    #[serde(default)]
    binding_tag_b64u: Option<String>,
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
    meta: ChallengeMeta,
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    // Ephemeral X25519 keypair (PublicKey / SecretKey are [u8; 32] type aliases)
    let (pk, sk) = crypto_box_keypair();
    let pk_b64u = URL_SAFE_NO_PAD.encode(pk);

    let n_deks = salts.len();
    let salts_b64u: Vec<String> = salts.iter().map(|s| URL_SAFE_NO_PAD.encode(s)).collect();

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

    let worker_nonce: [u8; 16] = decode_b64u_exact(&ch.worker_nonce_b64u, "worker_nonce")?;
    let approve_challenge_hash =
        compute_approve_challenge_hash(&pk, &worker_nonce, ts_ms, salts);

    if !ch.push_warning.is_empty() {
        eprintln!("vt: push warning: {}", ch.push_warning);
    }
    eprintln!("vt: waiting for Passkey approval…");
    eprintln!("vt: approve at: {}", ch.approve_url);

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

    // Wait for approval (up to 6 minutes — DO TTL is 5 min)
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws_stream.next())
            .await
            .map_err(|_| anyhow!("approval timeout (6 min)"))?
            .ok_or_else(|| anyhow!("connection closed before approval"))?
            .map_err(|_| anyhow!("connection closed before approval"))?;

        match msg {
            Message::Text(text) => {
                let ws: WsMsg = serde_json::from_str(&text)
                    .context("WS message parse")?;
                match ws.status.as_str() {
                    "waiting" => continue,
                    "approved" => {
                        let sealed_b64u = ws.sealed_deks_b64u.as_deref()
                            .ok_or_else(|| anyhow!("approved message missing required binding fields: sealed_deks_b64u"))?;
                        let pwa_pk_b64u = ws.pwa_pk_b64u.as_deref()
                            .ok_or_else(|| anyhow!("approved message missing required binding fields: pwa_pk_b64u"))?;
                        let binding_tag_b64u = ws.binding_tag_b64u.as_deref()
                            .ok_or_else(|| anyhow!("approved message missing required binding fields: binding_tag_b64u"))?;

                        let pwa_pk: [u8; 32] = decode_b64u_exact(pwa_pk_b64u, "pwa_pk")?;
                        let binding_tag: [u8; 32] = decode_b64u_exact(binding_tag_b64u, "binding_tag")?;
                        let sealed_deks_bytes = URL_SAFE_NO_PAD.decode(sealed_b64u)
                            .context("sealed_deks b64u decode")?;

                        verify_binding(
                            &pk,
                            &sk,
                            &pwa_pk,
                            &approve_challenge_hash,
                            &sealed_deks_bytes,
                            &binding_tag,
                        )?;

                        return open_sealed_deks(sealed_b64u, &pk, &sk, n_deks);
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

fn compute_approve_challenge_hash(
    daemon_pk: &[u8; 32],
    worker_nonce: &[u8; 16],
    timestamp_ms: u64,
    salts: &[[u8; 16]],
) -> [u8; 32] {
    let mut salt_concat_hasher = Sha256::new();
    for s in salts {
        salt_concat_hasher.update(s);
    }
    let salts_hash = salt_concat_hasher.finalize();

    let mut h = Sha256::new();
    h.update(b"vt-challenge-v2");
    h.update(daemon_pk);
    h.update(worker_nonce);
    h.update(timestamp_ms.to_be_bytes());
    h.update(salts_hash);
    h.update([0x01u8]);
    h.finalize().into()
}

fn verify_binding(
    daemon_pk: &[u8; 32],
    daemon_sk: &SecretKey,
    pwa_pk: &[u8; 32],
    approve_challenge_hash: &[u8; 32],
    sealed_deks: &[u8],
    received_tag: &[u8; 32],
) -> Result<()> {
    let mut shared = Zeroizing::new([0u8; 32]);
    crypto_scalarmult(&mut *shared, daemon_sk, pwa_pk);
    // dryoc's crypto_scalarmult does not check for the all-zero output
    if *shared == [0u8; 32] {
        bail!("binding: all-zero shared secret (low-order point)");
    }

    let mut binding_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, &*shared)
        .expand(b"vt-sealed-deks-bind-v1", &mut *binding_key)
        .map_err(|_| anyhow!("binding: HKDF expand failed"))?;

    let mut transcript = Vec::with_capacity(10 + 32 + 32 + 32 + sealed_deks.len());
    transcript.extend_from_slice(b"vt-bind-v1");
    transcript.extend_from_slice(approve_challenge_hash);
    transcript.extend_from_slice(daemon_pk);
    transcript.extend_from_slice(pwa_pk);
    transcript.extend_from_slice(sealed_deks);

    let mut mac = Hmac::<Sha256>::new_from_slice(&*binding_key)
        .map_err(|_| anyhow!("binding: HMAC key init failed"))?;
    mac.update(&transcript);
    mac.verify_slice(received_tag).map_err(|_| anyhow!("binding: tag mismatch"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dryoc::classic::crypto_box::crypto_box_keypair;

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes { s.push_str(&format!("{:02x}", b)); }
        s
    }

    // Mirror of the PWA's binding construction. Returns binding_tag.
    fn pwa_build_tag(
        daemon_pk: &[u8; 32],
        pwa_sk: &[u8; 32],
        pwa_pk: &[u8; 32],
        approve_challenge_hash: &[u8; 32],
        sealed_deks: &[u8],
    ) -> [u8; 32] {
        let mut shared = [0u8; 32];
        crypto_scalarmult(&mut shared, pwa_sk, daemon_pk);
        let mut binding_key = [0u8; 32];
        Hkdf::<Sha256>::new(None, &shared)
            .expand(b"vt-sealed-deks-bind-v1", &mut binding_key)
            .unwrap();
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"vt-bind-v1");
        transcript.extend_from_slice(approve_challenge_hash);
        transcript.extend_from_slice(daemon_pk);
        transcript.extend_from_slice(pwa_pk);
        transcript.extend_from_slice(sealed_deks);
        let mut mac = Hmac::<Sha256>::new_from_slice(&binding_key).unwrap();
        mac.update(&transcript);
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result);
        tag
    }

    /// Golden vector for compute_approve_challenge_hash. Any change to the
    /// formula (domain string, byte order, field order, action byte) flips
    /// this hash. The cf-worker/src/crypto.ts side MUST produce identical
    /// output for the same inputs (with action='approve').
    #[test]
    fn approve_challenge_hash_golden_vector() {
        let daemon_pk = [0x01u8; 32];
        let worker_nonce = [0x02u8; 16];
        let ts_ms: u64 = 1_700_000_000_000;
        let salts = [[0x03u8; 16], [0x04u8; 16]];

        let h = compute_approve_challenge_hash(&daemon_pk, &worker_nonce, ts_ms, &salts);
        // Cross-validated against an independent Python SHA-256 over the same
        // byte layout — if this fails, the formula has drifted from the spec.
        let expected = "4f53ae2e9692a575f7f35bc4c6c03ad91d8cc024f08152c266d3bfdedcd6917f";
        assert_eq!(hex_encode(&h), expected);
    }

    #[test]
    fn verify_binding_happy_path() {
        let (daemon_pk, daemon_sk) = crypto_box_keypair();
        let (pwa_pk, pwa_sk) = crypto_box_keypair();
        let ach = [0x42u8; 32];
        let sealed = vec![0xAAu8; 80];
        let tag = pwa_build_tag(&daemon_pk, &pwa_sk, &pwa_pk, &ach, &sealed);

        verify_binding(&daemon_pk, &daemon_sk, &pwa_pk, &ach, &sealed, &tag)
            .expect("binding should verify");
    }

    /// pwa_pk = [0; 32] is the identity point; scalarmult against it yields
    /// all-zero shared secret. verify_binding must refuse this regardless
    /// of what tag is provided.
    #[test]
    fn verify_binding_rejects_low_order_point() {
        let (daemon_pk, daemon_sk) = crypto_box_keypair();
        let pwa_pk = [0u8; 32];
        let ach = [0x42u8; 32];
        let sealed = vec![0xAAu8; 80];
        let dummy_tag = [0u8; 32];

        let err = verify_binding(&daemon_pk, &daemon_sk, &pwa_pk, &ach, &sealed, &dummy_tag)
            .expect_err("should reject low-order point");
        let msg = err.to_string();
        assert!(
            msg.contains("low-order") || msg.contains("all-zero"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn verify_binding_rejects_flipped_tag_bit() {
        let (daemon_pk, daemon_sk) = crypto_box_keypair();
        let (pwa_pk, pwa_sk) = crypto_box_keypair();
        let ach = [0x42u8; 32];
        let sealed = vec![0xAAu8; 80];
        let mut tag = pwa_build_tag(&daemon_pk, &pwa_sk, &pwa_pk, &ach, &sealed);
        tag[0] ^= 0x01;

        let err = verify_binding(&daemon_pk, &daemon_sk, &pwa_pk, &ach, &sealed, &tag)
            .expect_err("flipped tag must fail");
        assert!(err.to_string().contains("tag mismatch"), "unexpected: {err}");
    }

    #[test]
    fn verify_binding_rejects_tampered_sealed_deks() {
        let (daemon_pk, daemon_sk) = crypto_box_keypair();
        let (pwa_pk, pwa_sk) = crypto_box_keypair();
        let ach = [0x42u8; 32];
        let original = vec![0xAAu8; 80];
        let tag = pwa_build_tag(&daemon_pk, &pwa_sk, &pwa_pk, &ach, &original);

        let mut tampered = original.clone();
        tampered[40] ^= 0x01;
        let err = verify_binding(&daemon_pk, &daemon_sk, &pwa_pk, &ach, &tampered, &tag)
            .expect_err("tampered sealed_deks must fail");
        assert!(err.to_string().contains("tag mismatch"), "unexpected: {err}");
    }
}
