// CF ceremony client — POST /api/challenge + WS /api/dek.
//
// Called by client.rs when the SSH agent path is unavailable (Linux, or macOS
// without a running vt ssh agent). The ceremony:
//
//   1. Use the resolved VT_PASSKEY_URL + VT_PASSKEY_TOKEN snapshot.
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
use std::sync::OnceLock;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use zeroize::Zeroizing;

use crate::caller_meta::collect_client_meta;
use crate::core::sanitize_for_display as sanitize;
use crate::core::sanitize_for_display_uncapped;

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

pub struct CfConfig<'a> {
    pub worker_url: &'a str,
    /// Raw `VT_PASSKEY_TOKEN`: the per-host `vt1.<id>.<secret>` token issued
    /// by `vt enroll`. See [`WorkerAuth`].
    pub worker_auth: &'a str,
    /// Requested WebAuthn user-verification level for the approval ceremony
    /// (`discouraged` | `preferred` | `required`), or `None` to take whatever
    /// the Worker's policy says. RAISE-ONLY: the Worker stores
    /// `max(policy, this)`, so this can never buy a weaker ceremony than the
    /// deployment configured. See cf-worker/src/uv_policy.ts.
    pub uv: Option<&'a str>,
}

/// Prefix of a per-host token (`vt1.<token_id>.<secret_b64u>`), issued by the
/// Worker at `vt enroll` and stored as `VT_PASSKEY_TOKEN`. The secret is
/// HKDF(master, token_id) on the Worker side (cf-worker/src/host_token.ts); the
/// host only ever holds this derived value, never the master.
pub const HOST_TOKEN_PREFIX: &str = "vt1.";

/// The HMAC key material behind `VT_PASSKEY_TOKEN`, plus the token id the
/// Worker needs to re-derive it (`VT-Token-Id` header). Nothing but a host
/// token parses: the Worker has no token-less request path.
pub struct WorkerAuth {
    key: Zeroizing<Vec<u8>>,
    pub token_id: String,
}

impl WorkerAuth {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let Some(rest) = raw.strip_prefix(HOST_TOKEN_PREFIX) else {
            bail!(
                "VT_PASSKEY_TOKEN: not a host token (expected vt1.<id>.<secret>) — run `vt enroll`"
            );
        };
        let (id, secret_b64u) = rest.split_once('.').ok_or_else(|| {
            anyhow!("VT_PASSKEY_TOKEN: malformed host token (expected vt1.<id>.<secret>)")
        })?;
        if id.len() != 16
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("VT_PASSKEY_TOKEN: malformed host token id");
        }
        let secret: [u8; 32] = decode_b64u_exact(secret_b64u, "VT_PASSKEY_TOKEN secret")?;
        Ok(Self {
            key: Zeroizing::new(secret.to_vec()),
            token_id: id.to_owned(),
        })
    }

    fn auth_header(&self, body: &[u8]) -> String {
        hmac_auth_header_raw(&self.key, body)
    }

    /// Raw HMAC key: the token's 32-byte secret.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key
    }
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Build the `VT-HMAC <b64u>` Authorization header for `body` signed with a
/// raw byte key. The agent audit path signs with an HKDF-derived 32-byte key
/// (not a UTF-8 string), so the signing primitive must accept raw bytes.
pub(crate) fn hmac_auth_header_raw(key: &[u8], body: &[u8]) -> String {
    let mac = hmac_sha256(key, body);
    format!("VT-HMAC {}", URL_SAFE_NO_PAD.encode(mac))
}

fn decode_b64u_exact<const N: usize>(b64u: &str, what: &str) -> Result<[u8; N]> {
    let v = URL_SAFE_NO_PAD
        .decode(b64u)
        .with_context(|| format!("{what}: b64u decode"))?;
    v.as_slice()
        .try_into()
        .map_err(|_| anyhow!("{what}: wrong length (expected {N})"))
}

// ── Wire types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ChallengeReq<'a> {
    daemon_pubkey_b64u: String,
    timestamp_ms: u64,
    salts_b64u: Vec<String>,
    meta: ChallengeMeta,
    /// Omitted entirely when unset, which the Worker reads as "no request".
    #[serde(skip_serializing_if = "Option::is_none")]
    uv: Option<&'a str>,
}

/// Display-only context shown on the phone's approval page. None of these
/// fields are bound into `challenge_hash`; they exist to help the human
/// recognize "is this my session, in the place I expect?" before tapping
/// approve. The CLI fills them; the worker forwards them; the PWA renders
/// them. All strings are sanitized (control chars stripped, length-capped)
/// before they leave this process.
///
/// `host` / `user` are left EMPTY (and omitted from the wire) by the CLI
/// ceremony path: the Worker fills both from the host-token record, which is
/// the only verified source. The macOS agent's audit push still sets them —
/// there the agent names the session host. tty / ppid / ssh_client were
/// dropped from the wire entirely (docs/approval-transparency.md §2b).
#[derive(Serialize, Default)]
pub struct ChallengeMeta {
    pub op_kind: String,
    pub command: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user: String,
    pub pwd: String,
    /// The repository's common git dir when inside one, else the cwd. The
    /// advisory half of the Worker's DEK-cache key: every worktree of one
    /// repository shares the grant its host token earned (docs/dek-cache.md).
    pub project: String,
    pub ppid_cmd: String,
    pub reason: String,
}

/// Build a `ChallengeMeta` by collecting local context from the running
/// process: cwd, project root, and the parent process command line. The caller
/// supplies the three fields it already knows (`op_kind`, `command`, `reason`).
pub fn collect_meta(op_kind: &str, command: &str, reason: &str) -> ChallengeMeta {
    let client = collect_client_meta();
    let project = sanitize(&project_dir(&client.pwd), 200);
    ChallengeMeta {
        op_kind: sanitize(op_kind, 32),
        command: sanitize_for_display_uncapped(command),
        host: String::new(),
        user: String::new(),
        pwd: client.pwd,
        project,
        ppid_cmd: client.ppid_cmd,
        reason: sanitize(reason, 200),
    }
}

/// `git rev-parse --git-common-dir` resolved to an absolute path, or `cwd`
/// when git is absent, `cwd` is not in a repository, or `cwd` is unknown.
/// Silent on failure: no git is the normal case on many hosts.
fn project_dir(cwd: &str) -> String {
    if cwd.is_empty() {
        return String::new();
    }
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--git-common-dir"])
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    let rel = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => return cwd.to_string(),
    };
    if rel.is_empty() {
        return cwd.to_string();
    }
    // The main worktree answers `.git` relative to cwd; linked worktrees
    // answer absolute. Canonicalize so both name the same directory.
    let joined = std::path::Path::new(cwd).join(rel);
    std::fs::canonicalize(&joined)
        .unwrap_or(joined)
        .display()
        .to_string()
}

#[derive(Deserialize)]
struct ChallengeResp {
    poll_token: String,
    approve_url: String,
    worker_nonce_b64u: String,
}

#[derive(Deserialize)]
struct WsMsg {
    status: String,
    sealed_deks_b64u: Option<String>,
    #[serde(default)]
    pwa_pk_b64u: Option<String>,
    #[serde(default)]
    binding_tag_b64u: Option<String>,
    /// Enrollment ceremonies only: the minted `vt1.…` host token.
    #[serde(default)]
    host_token: Option<String>,
}

#[derive(Serialize)]
struct EnrollReq<'a> {
    host: &'a str,
    user: &'a str,
    timestamp_ms: u64,
}

#[derive(Deserialize)]
struct EnrollResp {
    approve_url: String,
    poll_token: String,
    pair_code: String,
}

/// Structured 401 body the Worker returns for a dead host token.
#[derive(Deserialize)]
struct TokenRefused {
    error: String,
}

#[derive(Serialize)]
struct DekCacheReq<'a> {
    daemon_pubkey_b64u: String,
    salts_b64u: Vec<String>,
    timestamp_ms: u64,
    /// Full display meta (host/user/command/ppid/…), same shape as the challenge
    /// request — so a cache HIT is audited with the same context as a ceremony
    /// decrypt. The cache key is the host token plus `meta.project`; the rest
    /// is forensic only.
    meta: &'a ChallengeMeta,
}

#[derive(Deserialize)]
struct DekCacheResp {
    /// Discriminant: "cache" on a hit. Absent/other ⇒ treat as miss (state-
    /// confusion guard — a non-cache response can never be opened on this path).
    #[serde(default)]
    source: String,
    #[serde(default)]
    sealed_deks_b64u: Option<String>,
    #[serde(default)]
    miss: bool,
}

const CACHE_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn http_client(ipv4: bool) -> reqwest::Result<&'static reqwest::Client> {
    static V4: OnceLock<reqwest::Client> = OnceLock::new();
    static ANY: OnceLock<reqwest::Client> = OnceLock::new();
    let slot = if ipv4 { &V4 } else { &ANY };
    if let Some(client) = slot.get() {
        return Ok(client);
    }
    // Preserve reqwest's proxy defaults, sampled when each pool is first built.
    // Auth and timeouts belong to requests, never to these shared clients.
    let mut builder = reqwest::Client::builder();
    if ipv4 {
        builder = builder.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    }
    // Failed builds are not cached; concurrent successful builds use one winner.
    let _ = slot.set(builder.build()?);
    Ok(slot.get().expect("HTTP client initialized"))
}

/// POST to the worker with the egress IP family pinned to IPv4 (with graceful
/// fallback). Both the challenge (which writes the DEK-cache entry, ctx bound to
/// CF-Connecting-IP) and the dek-cache probe (which reads it) go through here,
/// so a dual-stack host can't flip between its IPv4 and IPv6 egress across the
/// two separate `vt` processes — that flip would change CF-Connecting-IP, hence
/// the cache ctx, and cause a permanent miss. Cloudflare always publishes A
/// records, so IPv4 connects whenever the host has any IPv4 egress; on an
/// IPv6-only host the IPv4 connect fails and we retry without the pin (both
/// requests then consistently use IPv6).
pub(crate) async fn cf_post(
    url: &str,
    auth_header: &str,
    token_id: Option<&str>,
    body: &[u8],
) -> Result<reqwest::Response> {
    cf_post_with_timeout(url, auth_header, token_id, body, 30).await
}

/// Same IPv4-pinned-with-fallback POST as [`cf_post`], but with a caller-chosen
/// timeout (seconds). The fire-and-forget agent audit push needs a short (5 s)
/// budget so it can never block the agent — the default `cf_post` 30 s ceiling
/// would let a single retried row stall up to a minute.
///
/// `token_id` (host-token auth) rides in the `VT-Token-Id` header so the Worker
/// can re-derive the HMAC key; `None` for the unauthenticated enroll request
/// (`auth_header` empty) and the agent's hostname-keyed audit push.
pub(crate) async fn cf_post_with_timeout(
    url: &str,
    auth_header: &str,
    token_id: Option<&str>,
    body: &[u8],
    secs: u64,
) -> Result<reqwest::Response> {
    async fn send_once(
        client: &reqwest::Client,
        url: &str,
        auth_header: &str,
        token_id: Option<&str>,
        body: &[u8],
        secs: u64,
    ) -> reqwest::Result<reqwest::Response> {
        let mut req = client
            .post(url)
            .timeout(Duration::from_secs(secs))
            .header("Content-Type", "application/json");
        if !auth_header.is_empty() {
            req = req.header("Authorization", auth_header);
        }
        if let Some(id) = token_id {
            req = req.header("VT-Token-Id", id);
        }
        req.body(body.to_vec()).send().await
    }

    match send_once(http_client(true)?, url, auth_header, token_id, body, secs).await {
        Ok(r) => Ok(r),
        // IPv6-only host (or no IPv4 route): retry without the family pin so both
        // requests consistently fall back to IPv6.
        Err(e) if e.is_connect() || e.is_builder() => {
            Ok(send_once(http_client(false)?, url, auth_header, token_id, body, secs).await?)
        }
        Err(e) => Err(e.into()),
    }
}

/// Turn a non-2xx ceremony response into the user-facing error. A structured
/// 401 from a dead host token names the remedy; anything else keeps the
/// historical `HTTP <status>: <body>` shape.
async fn ceremony_http_error(what: &str, resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status == 401 {
        if let Ok(refused) = serde_json::from_str::<TokenRefused>(&body) {
            return anyhow!(
                "{what}: host token {} — run `vt enroll` on this host to get a new VT_PASSKEY_TOKEN",
                match refused.error.as_str() {
                    "token_expired" => "expired (unused for more than 7 days)",
                    "token_revoked" => "revoked",
                    _ => "not recognized",
                }
            );
        }
    }
    anyhow!("{what}: HTTP {status}: {body}")
}

async fn connect_dek_ws(
    url: &str,
    timeout: Duration,
) -> Result<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>> {
    let (stream, _) = tokio::time::timeout(timeout, connect_async(url))
        .await
        .map_err(|_| anyhow!("WS connection handshake timeout"))?
        // Neither the URL's poll token nor server-controlled error data is safe to display.
        .map_err(|_| anyhow!("WS connection handshake failed"))?;
    Ok(stream)
}

/// The `/api/dek` poll socket URL for a ceremony. `poll_token` is
/// worker-controlled and interpolated into the query string, so it is
/// restricted to the b64url alphabet: a compromised worker can't inject extra
/// URL/query/fragment structure into the connect target.
fn poll_ws_url(worker_url: &str, poll_token: &str) -> Result<String> {
    if poll_token.is_empty()
        || !poll_token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("challenge: malformed poll_token");
    }
    Ok(format!(
        "{}/api/dek?poll_token={}",
        worker_url
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1),
        poll_token
    ))
}

/// Wait on the poll socket until the ceremony reaches a terminal state and
/// return the `approved` message. Rejection / expiry / timeout are errors.
async fn await_approval(ws_url: &str) -> Result<WsMsg> {
    let mut ws_stream = connect_dek_ws(ws_url, WS_CONNECT_TIMEOUT).await?;
    // Up to 6 minutes — DO TTL is 5 min.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws_stream.next())
            .await
            .map_err(|_| anyhow!("approval timeout (6 min)"))?
            .ok_or_else(|| anyhow!("connection closed before approval"))?
            .map_err(|_| anyhow!("connection closed before approval"))?;
        match msg {
            Message::Text(text) => {
                let ws: WsMsg = serde_json::from_str(&text).context("WS message parse")?;
                match ws.status.as_str() {
                    "waiting" => continue,
                    "approved" => return Ok(ws),
                    "rejected" => bail!("approval rejected by user"),
                    "expired" => bail!("approval request expired"),
                    other => bail!("unexpected WS status: {other}"),
                }
            }
            Message::Close(_) => bail!("WS closed unexpectedly"),
            _ => continue,
        }
    }
}

// ── Enrollment ─────────────────────────────────────────────────────────────

/// `vt enroll`: ask the Worker for this host's own `VT_PASSKEY_TOKEN`. The
/// request is unauthenticated (a fresh host has nothing to sign with) and
/// becomes a Passkey ceremony on the phone; the Worker shows the same pairing
/// code we print here so the approver can tell this terminal's request from a
/// stranger's. Returns the minted `vt1.…` token; the caller persists it.
pub async fn enroll(worker_url: &str, host: &str, user: &str) -> Result<Zeroizing<String>> {
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let body = serde_json::to_vec(&EnrollReq {
        host: &sanitize(host, 100),
        user: &sanitize(user, 64),
        timestamp_ms: ts_ms,
    })?;
    let url = format!("{}/api/enroll", worker_url.trim_end_matches('/'));
    let resp = cf_post(&url, "", None, &body)
        .await
        .context("POST /api/enroll")?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let hint = match status {
            429 => " (rate limited — wait a minute, or approve/expire the pending requests first)",
            503 => " (the Worker has no ENROLL_LIMITER binding; see docs/host-token.md)",
            _ => "",
        };
        bail!("enroll: HTTP {status}: {text}{hint}");
    }
    let er: EnrollResp =
        serde_json::from_slice(&resp.bytes().await.context("enroll response read")?)
            .context("enroll response parse")?;
    let ws_url = poll_ws_url(worker_url, &er.poll_token)?;
    eprintln!("vt: approve on your phone: {}", er.approve_url);
    eprintln!(
        "vt: pairing code: {}  (approve only if the page shows this code)",
        sanitize(&er.pair_code, 16)
    );
    eprintln!("vt: waiting for approval…");
    let approved = await_approval(&ws_url).await?;
    let token = approved
        .host_token
        .ok_or_else(|| anyhow!("approved message carries no host token"))?;
    WorkerAuth::parse(&token).context("enroll: Worker returned a non-host token")?;
    Ok(Zeroizing::new(token))
}

// ── Main entry point ───────────────────────────────────────────────────────

/// Run the CF approval ceremony and return one DEK per salt.
///
/// `salts` — per-record salts; pass the salts from vt:// URLs for decrypt,
/// fresh random salts for encrypt, empty for auth-only. The browser derives
/// `DEK[i] = HKDF(master_key, salt[i])` and seals `[DEK...]` back.
pub async fn get_deks(
    config: &CfConfig<'_>,
    salts: &[[u8; 16]],
    meta: ChallengeMeta,
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    // Ephemeral X25519 keypair (PublicKey / SecretKey are [u8; 32] type aliases).
    // Wrap the secret in Zeroizing so it is wiped on return (S1).
    let (pk, sk_raw) = crypto_box_keypair();
    let sk = Zeroizing::new(sk_raw);
    let pk_b64u = URL_SAFE_NO_PAD.encode(pk);

    let n_deks = salts.len();
    let salts_b64u: Vec<String> = salts.iter().map(|s| URL_SAFE_NO_PAD.encode(s)).collect();

    let challenge_url = format!("{}/api/challenge", config.worker_url);
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let req_body = serde_json::to_vec(&ChallengeReq {
        daemon_pubkey_b64u: pk_b64u.clone(),
        timestamp_ms: ts_ms,
        salts_b64u: salts_b64u.clone(),
        meta,
        uv: config.uv,
    })?;

    let auth = WorkerAuth::parse(config.worker_auth)?;
    let auth_header = auth.auth_header(&req_body);
    let resp = cf_post(
        &challenge_url,
        &auth_header,
        Some(&auth.token_id),
        &req_body,
    )
    .await
    .context("POST /api/challenge")?;

    if !resp.status().is_success() {
        return Err(ceremony_http_error("challenge", resp).await);
    }

    let body = resp.bytes().await.context("challenge response read")?;
    let ch: ChallengeResp = serde_json::from_slice(&body).context("challenge response parse")?;

    let worker_nonce: [u8; 16] = decode_b64u_exact(&ch.worker_nonce_b64u, "worker_nonce")?;
    let approve_challenge_hash = compute_approve_challenge_hash(&pk, &worker_nonce, ts_ms, salts);

    let ws_url = poll_ws_url(config.worker_url, &ch.poll_token)?;

    eprintln!("vt: approve on your phone: {}", ch.approve_url);
    eprintln!("vt: waiting for approval…");

    let ws = await_approval(&ws_url).await?;
    let sealed_b64u = ws.sealed_deks_b64u.as_deref().ok_or_else(|| {
        anyhow!("approved message missing required binding fields: sealed_deks_b64u")
    })?;
    let pwa_pk_b64u = ws
        .pwa_pk_b64u
        .as_deref()
        .ok_or_else(|| anyhow!("approved message missing required binding fields: pwa_pk_b64u"))?;
    let binding_tag_b64u = ws.binding_tag_b64u.as_deref().ok_or_else(|| {
        anyhow!("approved message missing required binding fields: binding_tag_b64u")
    })?;

    let pwa_pk: [u8; 32] = decode_b64u_exact(pwa_pk_b64u, "pwa_pk")?;
    let binding_tag: [u8; 32] = decode_b64u_exact(binding_tag_b64u, "binding_tag")?;
    let sealed_deks_bytes = URL_SAFE_NO_PAD
        .decode(sealed_b64u)
        .context("sealed_deks b64u decode")?;

    verify_binding(
        &pk,
        &sk,
        &pwa_pk,
        &approve_challenge_hash,
        &sealed_deks_bytes,
        &binding_tag,
    )?;

    // Open the SAME decoded bytes the binding tag committed to — never
    // re-decode the b64u string, so the bound and opened byte sequences are
    // identical by construction.
    open_sealed_deks(&sealed_deks_bytes, &pk, &sk, n_deks)
}

/// Fast path: try the opt-in server-side DEK cache before running a full phone
/// approval. Returns `Some(deks)` on a full cache hit (all `salts` present,
/// unexpired, armed by this host token for the same `meta.project` — see
/// docs/dek-cache.md), or `None` on any miss / disabled cache / recoverable
/// transport error (the caller then falls back to `get_deks`).
///
/// SECURITY: the cache path has NO PWA and NO binding tag, so `verify_binding`
/// does not apply (a cache hit is the worker delivering DEKs it already holds —
/// the malicious-worker substitution that binding defends against is moot
/// here). We therefore require the explicit `source == "cache"` discriminant
/// before opening the sealed box, so a normal ceremony response can never be
/// mistakenly accepted on this unbound path. Confidentiality of the response
/// still rests on the sealed_box being sealed to our fresh ephemeral pubkey
/// (only we can open it) plus TLS.
pub async fn try_cache(
    config: &CfConfig<'_>,
    salts: &[[u8; 16]],
    meta: &ChallengeMeta,
) -> Result<Option<Vec<Zeroizing<[u8; 32]>>>> {
    try_cache_with_timeout(config, salts, meta, CACHE_PROBE_TIMEOUT).await
}

async fn try_cache_with_timeout(
    config: &CfConfig<'_>,
    salts: &[[u8; 16]],
    meta: &ChallengeMeta,
    timeout: Duration,
) -> Result<Option<Vec<Zeroizing<[u8; 32]>>>> {
    if salts.is_empty() {
        return Ok(None); // auth-only / nothing to look up
    }

    let (pk, sk_raw) = crypto_box_keypair();
    // SecretKey is a bare [u8;32] (no Drop) — wrap so the ephemeral key is wiped
    // when this fn returns (S1).
    let sk = Zeroizing::new(sk_raw);
    let pk_b64u = URL_SAFE_NO_PAD.encode(pk);
    let salts_b64u: Vec<String> = salts.iter().map(|s| URL_SAFE_NO_PAD.encode(s)).collect();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let req_body = match serde_json::to_vec(&DekCacheReq {
        daemon_pubkey_b64u: pk_b64u,
        salts_b64u,
        timestamp_ms: ts_ms,
        meta,
    }) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };

    let url = format!("{}/api/dek-cache", config.worker_url);
    let Ok(auth) = WorkerAuth::parse(config.worker_auth) else {
        return Ok(None); // the ceremony path reports the malformed token
    };
    let auth_header = auth.auth_header(&req_body);
    // Same IPv4-pinned client as the challenge POST so CF-Connecting-IP (half the
    // cache ctx) is stable across the two processes. Any transport/HTTP failure →
    // fall back to the ceremony rather than abort.
    // One budget includes both address-family attempts and the entire body read.
    // Keep crypto validation outside the recoverable transport/miss path.
    let bytes = match tokio::time::timeout(timeout, async {
        let resp = cf_post(&url, &auth_header, Some(&auth.token_id), &req_body)
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.bytes().await.ok()
    })
    .await
    {
        Ok(Some(bytes)) => bytes,
        _ => return Ok(None),
    };
    let parsed: DekCacheResp = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };

    if parsed.miss || parsed.source != "cache" {
        return Ok(None);
    }
    let sealed = match parsed.sealed_deks_b64u {
        Some(s) => s,
        None => return Ok(None),
    };

    // Cache hit: open the sealed box sealed to our ephemeral pubkey. No binding
    // verification on this path (see SECURITY note above).
    let ct = URL_SAFE_NO_PAD
        .decode(&sealed)
        .context("sealed_deks b64u decode")?;
    let deks = open_sealed_deks(&ct, &pk, &sk, salts.len())?;
    Ok(Some(deks))
}

fn open_sealed_deks(
    ct: &[u8],
    pk: &PublicKey,
    sk: &SecretKey,
    n_deks: usize,
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    // sealed_box overhead = 48 bytes (ephemeral pk 32 + mac 16)
    // plaintext = max(n_deks, 1) * 32 bytes (at least 1 even for auth-only)
    let n = n_deks.max(1);
    let expected_len = n * 32 + 48;
    if ct.len() != expected_len {
        bail!(
            "sealed_box length {} != expected {}",
            ct.len(),
            expected_len
        );
    }

    let mut pt = vec![0u8; n * 32];
    crypto_box_seal_open(&mut pt, ct, pk, sk)
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
    crypto_scalarmult(&mut shared, daemon_sk, pwa_pk);
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
    mac.verify_slice(received_tag)
        .map_err(|_| anyhow!("binding: tag mismatch"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dryoc::classic::crypto_box::{crypto_box_keypair, crypto_box_seal};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// Bind `addr`, accept one connection, and hand it to `handle`. Returns the
    /// `http://` URL and the server task.
    async fn serve<F, Fut>(addr: &str, handle: F) -> (String, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(BufReader<TcpStream>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind(addr).await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle(BufReader::new(stream)).await;
        });
        (url, task)
    }

    async fn join(server: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    async fn read_request(stream: &mut BufReader<TcpStream>) -> (Vec<String>, Vec<u8>) {
        let mut headers = Vec::new();
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
            }
            headers.push(line);
        }
        let mut body = vec![0; content_length];
        stream.read_exact(&mut body).await.unwrap();
        (headers, body)
    }

    async fn write_response(stream: &mut TcpStream, status: u16, body: &[u8]) {
        let headers = format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    }

    /// Optionally send headers plus a truncated body, then hold the connection
    /// open until the client gives up; the client's timeout must close it.
    async fn stall_until_client_closes(stream: &mut BufReader<TcpStream>, partial_response: bool) {
        if partial_response {
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
                .await
                .unwrap();
        }
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    }

    async fn cache_server(
        response: impl FnOnce(serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> (String, tokio::task::JoinHandle<()>) {
        serve("127.0.0.1:0", |mut stream| async move {
            let (_, body) = read_request(&mut stream).await;
            let request = serde_json::from_slice(&body).unwrap();
            let body = serde_json::to_vec(&response(request)).unwrap();
            write_response(stream.get_mut(), 200, &body).await;
        })
        .await
    }

    fn config(url: &str) -> CfConfig<'_> {
        CfConfig {
            worker_url: url,
            worker_auth: "vt1.AAAAAAAAAAAAAAAA.iaR45SwFl4C19e0hLGVnh32aBZlyjE4i47Jp_FbuKAI",
            uv: None,
        }
    }

    async fn probe(url: &str) -> Result<Option<Vec<Zeroizing<[u8; 32]>>>> {
        try_cache(&config(url), &[[1; 16]], &ChallengeMeta::default()).await
    }

    fn ws_url(http_url: &str) -> String {
        format!(
            "{}/api/dek?poll_token=test_token",
            http_url.replacen("http", "ws", 1)
        )
    }

    #[tokio::test]
    async fn websocket_handshake_is_bounded_after_tcp_accept() {
        let (url, server) = serve("127.0.0.1:0", |mut stream| async move {
            read_request(&mut stream).await;
            // No upgrade response: cancellation must close the accepted socket.
            stall_until_client_closes(&mut stream, false).await;
        })
        .await;
        let err = connect_dek_ws(&ws_url(&url), Duration::from_millis(200))
            .await
            .unwrap_err();
        assert_eq!(format!("{err:#}"), "WS connection handshake timeout");
        join(server).await;
    }

    #[tokio::test]
    async fn websocket_handshake_failure_does_not_expose_poll_token() {
        let (url, server) = serve("127.0.0.1:0", |mut stream| async move {
            read_request(&mut stream).await;
            write_response(stream.get_mut(), 403, b"test_token").await;
        })
        .await;
        let err = connect_dek_ws(&ws_url(&url), Duration::from_secs(2))
            .await
            .unwrap_err();
        assert_eq!(format!("{err:#}"), "WS connection handshake failed");
        join(server).await;
    }

    #[tokio::test]
    async fn cache_probe_opens_successful_hit() {
        let (url, server) = cache_server(|request| {
            let pk = decode_b64u_exact::<32>(
                request["daemon_pubkey_b64u"].as_str().unwrap(),
                "test public key",
            )
            .unwrap();
            let mut sealed = vec![0; 80];
            crypto_box_seal(&mut sealed, &[0x42; 32], &pk).unwrap();
            serde_json::json!({"source": "cache", "sealed_deks_b64u": URL_SAFE_NO_PAD.encode(sealed)})
        })
        .await;
        let result = probe(&url).await.unwrap().unwrap();
        assert_eq!(result.len(), 1);
        assert!(
            *result[0] == [0x42; 32],
            "cache hit must open the expected test DEK"
        );
        join(server).await;
    }

    #[tokio::test]
    async fn cache_probe_miss_and_non_cache_responses_remain_misses() {
        for response in [
            serde_json::json!({"miss": true}),
            serde_json::json!({"source": "cache", "miss": true, "sealed_deks_b64u": "bad"}),
            serde_json::json!({"source": "approved", "sealed_deks_b64u": "bad"}),
            serde_json::json!({"source": "cache"}),
        ] {
            let (url, server) = cache_server(move |_| response).await;
            assert!(probe(&url).await.unwrap().is_none());
            join(server).await;
        }
    }

    #[test]
    fn challenge_request_carries_only_an_explicit_uv_request() {
        let request = |uv| {
            serde_json::to_value(ChallengeReq {
                daemon_pubkey_b64u: String::new(),
                timestamp_ms: 0,
                salts_b64u: Vec::new(),
                meta: ChallengeMeta::default(),
                uv,
            })
            .unwrap()
        };
        // Absent, not null: the worker reads a missing field as "no request"
        // and applies its own policy.
        assert!(request(None).get("uv").is_none());
        assert_eq!(request(Some("required"))["uv"], "required");
    }

    #[tokio::test]
    async fn cache_probe_crypto_errors_are_not_misses() {
        for sealed in ["!".to_string(), URL_SAFE_NO_PAD.encode([0; 80])] {
            let (url, server) = cache_server(
                move |_| serde_json::json!({"source": "cache", "sealed_deks_b64u": sealed}),
            )
            .await;
            assert!(probe(&url).await.is_err());
            join(server).await;
        }
    }

    /// The probe's single budget covers headers, body, and the IPv4→unpinned
    /// fallback (the `[::1]` server rejects the IPv4-pinned attempt first).
    #[tokio::test]
    async fn cache_probe_budget_covers_headers_body_and_ipv6_fallback() {
        for addr in ["127.0.0.1:0", "[::1]:0"] {
            for partial_response in [false, true] {
                let (url, server) = serve(addr, move |mut stream| async move {
                    read_request(&mut stream).await;
                    stall_until_client_closes(&mut stream, partial_response).await;
                })
                .await;
                let result = tokio::time::timeout(
                    Duration::from_secs(2),
                    try_cache_with_timeout(
                        &config(&url),
                        &[[1; 16]],
                        &ChallengeMeta::default(),
                        Duration::from_millis(200),
                    ),
                )
                .await
                .expect("probe budget must bound the whole exchange, not the 30 s request timeout")
                .unwrap();
                assert!(result.is_none());
                join(server).await;
            }
        }
    }

    #[tokio::test]
    async fn http_pool_reuses_connection_with_fresh_auth_and_timeouts() {
        let (url, server) = serve("127.0.0.1:0", |mut stream| async move {
            // Both requests must arrive on this one TCP connection.
            for auth in ["first-test-auth", "second-test-auth"] {
                let (headers, body) = read_request(&mut stream).await;
                assert!(headers
                    .iter()
                    .any(|h| h.trim() == format!("authorization: {auth}")));
                assert_eq!(body, b"{}");
                write_response(stream.get_mut(), 200, b"{}").await;
            }
        })
        .await;
        for (auth, secs) in [("first-test-auth", 30), ("second-test-auth", 5)] {
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                cf_post_with_timeout(&url, auth, None, b"{}", secs),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.bytes().await.unwrap().as_ref(), b"{}");
        }
        join(server).await;
    }

    #[tokio::test]
    async fn http_request_timeout_still_bounds_body_reads() {
        let (url, server) = serve("127.0.0.1:0", |mut stream| async move {
            read_request(&mut stream).await;
            stall_until_client_closes(&mut stream, true).await;
        })
        .await;
        let response = cf_post_with_timeout(&url, "test-auth", None, b"{}", 1)
            .await
            .unwrap();
        let err = tokio::time::timeout(Duration::from_secs(2), response.bytes())
            .await
            .expect("per-request timeout must survive the returned Response")
            .unwrap_err();
        assert!(err.is_timeout());
        join(server).await;
    }

    #[tokio::test]
    async fn http_status_errors_do_not_retry() {
        let (url, server) = serve("127.0.0.1:0", |mut stream| async move {
            read_request(&mut stream).await;
            write_response(stream.get_mut(), 401, b"{}").await;
        })
        .await;
        let response = cf_post(&url, "test-auth", None, b"{}").await.unwrap();
        assert_eq!(response.status().as_u16(), 401);
        join(server).await;
    }
    /// The CLI ceremony meta: host/user are absent on the wire (the Worker
    /// fills them from the host-token record), and tty/ppid/ssh_client are
    /// gone for good — the approval page only ever showed noise for them.
    #[test]
    fn challenge_meta_preserves_shape_and_command_newlines() {
        let meta = collect_meta("decrypt\0", "first\r\nsecond\t", "reason\n");
        assert_eq!(meta.op_kind, "decrypt");
        assert_eq!(meta.command, "first\nsecond");
        assert_eq!(meta.reason, "reason");
        assert!(meta.host.is_empty());
        assert!(meta.user.is_empty());
        let json = serde_json::to_value(meta).unwrap();
        let fields: Vec<_> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            ["command", "op_kind", "ppid_cmd", "project", "pwd", "reason"]
        );
    }

    /// `project` is the repository's common git dir for every worktree of it,
    /// and the cwd itself outside a repository. Skipped where git is absent:
    /// that is exactly the case `project_dir` must degrade silently for.
    #[test]
    fn project_dir_names_common_git_dir_or_falls_back_to_cwd() {
        let tmp = std::env::temp_dir().join(format!("vt-cf-project-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let plain = std::fs::canonicalize(&tmp).unwrap();
        let plain_s = plain.display().to_string();
        assert_eq!(project_dir(""), "");
        let git = |args: &[&str], dir: &std::path::Path| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        if !git(&["--version"], &plain) {
            return;
        }
        // Not a repository (GIT_CEILING is not set, so guard against the
        // tempdir living under one).
        let outside = project_dir(&plain_s);
        assert!(outside == plain_s || outside.ends_with(".git"));
        let repo = plain.join("repo");
        let sub = repo.join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        assert!(git(&["init", "-q"], &repo));
        let common = repo.join(".git").display().to_string();
        assert_eq!(project_dir(&repo.display().to_string()), common);
        assert_eq!(project_dir(&sub.display().to_string()), common);
        // A linked worktree reports the SAME common dir as its trunk.
        if git(
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "x",
            ],
            &repo,
        ) {
            let wt = plain.join("repo.wt");
            assert!(git(&["worktree", "add", "-q", wt.to_str().unwrap()], &repo));
            assert_eq!(project_dir(&wt.display().to_string()), common);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Agent audit rows still name the session host: non-empty host/user
    /// serialize, so the Worker keeps reading them from the body there.
    #[test]
    fn challenge_meta_serializes_host_user_when_set() {
        let meta = ChallengeMeta {
            host: "h".into(),
            user: "u".into(),
            ..ChallengeMeta::default()
        };
        let json = serde_json::to_value(meta).unwrap();
        assert_eq!(json["host"], "h");
        assert_eq!(json["user"], "u");
    }

    /// `vt1.<id>.<secret>` parses into the raw 32-byte HMAC key + id. A value
    /// that is not a host token — the Worker master pasted verbatim, as before
    /// `vt enroll` — is refused with the enroll hint, never used as a key.
    #[test]
    fn worker_auth_parses_host_token_and_rejects_bare_master() {
        let err = WorkerAuth::parse("plain-master")
            .err()
            .map(|e| e.to_string());
        assert!(
            err.as_deref().is_some_and(|e| e.contains("vt enroll")),
            "got: {err:?}"
        );

        let tok = "vt1.AAAAAAAAAAAAAAAA.iaR45SwFl4C19e0hLGVnh32aBZlyjE4i47Jp_FbuKAI";
        let parsed = WorkerAuth::parse(tok).unwrap();
        assert_eq!(parsed.token_id, "AAAAAAAAAAAAAAAA");
        assert_eq!(parsed.key.len(), 32);
        // Same body, same key → same MAC as the Worker computes with the derived
        // secret (crypto-level parity is pinned by the b64u secret above, which
        // is the Worker test suite's golden vector for this id).
        assert_eq!(
            parsed.auth_header(b"{}"),
            hmac_auth_header_raw(
                &URL_SAFE_NO_PAD
                    .decode("iaR45SwFl4C19e0hLGVnh32aBZlyjE4i47Jp_FbuKAI")
                    .unwrap(),
                b"{}"
            )
        );

        assert!(WorkerAuth::parse("vt1.short.xx").is_err());
        assert!(WorkerAuth::parse("vt1.AAAAAAAAAAAAAAAA").is_err());
        assert!(WorkerAuth::parse("vt1.AAAAAAAAAAAAAAAA.notb64u!").is_err());
    }

    /// Requests carry the token id only on the host-token path, and the
    /// unauthenticated enroll POST sends no Authorization header at all.
    #[tokio::test]
    async fn http_post_sends_token_id_header_only_when_given() {
        let (url, server) = serve("127.0.0.1:0", |mut stream| async move {
            let (headers, _) = read_request(&mut stream).await;
            assert!(headers
                .iter()
                .any(|h| h.trim() == "vt-token-id: AAAAAAAAAAAAAAAA"));
            assert!(headers.iter().any(|h| h.trim() == "authorization: a"));
            write_response(stream.get_mut(), 200, b"{}").await;
            let (headers, _) = read_request(&mut stream).await;
            assert!(!headers
                .iter()
                .any(|h| h.to_ascii_lowercase().starts_with("vt-token-id")));
            assert!(!headers
                .iter()
                .any(|h| h.to_ascii_lowercase().starts_with("authorization")));
            write_response(stream.get_mut(), 200, b"{}").await;
        })
        .await;
        let r = cf_post(&url, "a", Some("AAAAAAAAAAAAAAAA"), b"{}")
            .await
            .unwrap();
        r.bytes().await.unwrap();
        let r = cf_post(&url, "", None, b"{}").await.unwrap();
        r.bytes().await.unwrap();
        join(server).await;
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
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

    /// Cross-impl wire-compat: a sealed box produced by the WORKER's
    /// tweetnacl + blakejs `crypto_box_seal` (cf-worker/src/cache_crypto.ts)
    /// MUST open with the Rust client's dryoc `crypto_box_seal_open` — this is
    /// exactly the cache-hit delivery path (worker seals cached DEKs to the
    /// daemon pubkey; cf.rs opens). Vector generated by that JS code over a
    /// fixed secret key (32×0x11) and message bytes 0..32. If this fails, the
    /// worker's sealed-box construction has drifted from libsodium and cache
    /// hits will silently fail to decrypt.
    #[test]
    fn worker_sealed_box_opens_with_dryoc() {
        let sk: [u8; 32] =
            decode_b64u_exact("ERERERERERERERERERERERERERERERERERERERERERE", "sk").unwrap();
        let pk: [u8; 32] =
            decode_b64u_exact("e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM", "pk").unwrap();
        let expected: Vec<u8> = (0u8..32).collect();
        let sealed = "JEYfUWAkbFlSTgjZD-GXcSHkANGFWCT637UiLWtBRUu-uQjaKW_GFnZplKkhLMm3h0-ch65fczHafJozQnVbdv4F-eyFxUbJuJoIzb9Anvw";

        let ct = URL_SAFE_NO_PAD.decode(sealed).unwrap();
        let deks =
            open_sealed_deks(&ct, &pk, &sk, 1).expect("worker-sealed box must open with dryoc");
        assert_eq!(deks.len(), 1);
        assert_eq!(
            &deks[0][..],
            &expected[..],
            "decrypted DEK mismatch — wire incompatibility"
        );
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
        assert!(
            err.to_string().contains("tag mismatch"),
            "unexpected: {err}"
        );
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
        assert!(
            err.to_string().contains("tag mismatch"),
            "unexpected: {err}"
        );
    }
}
