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
//   7. Open the sealed box (docs/sealed-box-v1.md) → n DEKs (32 bytes each).
//   8. Return DEKs to caller; ephemeral secret key is wiped on drop.
//
// master_key never leaves the user's phone. The daemon never holds it.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::StreamExt;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use x25519_dalek::{PublicKey, StaticSecret};
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
    /// The token's 32-byte secret: the HMAC key for every daemon request and,
    /// via `--audit-key`, the agent's audit push.
    pub key: Zeroizing<[u8; 32]>,
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
            key: Zeroizing::new(secret),
            token_id: id.to_owned(),
        })
    }

    fn auth_header(&self, body: &[u8]) -> String {
        hmac_auth_header(&*self.key, body)
    }
}

/// The `VT-HMAC <b64u>` Authorization header for `body` under the host
/// token's 32-byte secret (daemon requests and the agent audit push alike).
pub(crate) fn hmac_auth_header(key: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(body);
    format!(
        "VT-HMAC {}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
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
/// dropped from the wire entirely (docs/approval-transparency.md §1b).
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
    /// One suggested display name per entry of `salts_b64u`, same order, `""`
    /// when unknown (the env var name or file basename `inject` read the
    /// record from). A suggestion only: the Worker shows it as 自报 and stores
    /// nothing until the approver adopts it (docs/dek-cache.md).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

/// A record-name suggestion within the Worker's cap: control chars stripped,
/// at most 40 UTF-16 units (what the Worker's `.length` check counts), so a
/// long basename is shortened here instead of failing the whole ceremony.
pub fn record_name(s: &str) -> String {
    let clean = sanitize_for_display_uncapped(s);
    if clean.encode_utf16().count() <= RECORD_NAME_MAX {
        return clean;
    }
    let mut out: String = clean.chars().take(RECORD_NAME_MAX - 1).collect();
    while out.encode_utf16().count() > RECORD_NAME_MAX - 1 {
        out.pop();
    }
    out.push('…');
    out
}

const RECORD_NAME_MAX: usize = 40;

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
        names: Vec::new(),
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

fn http_client() -> reqwest::Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    // Preserve reqwest's proxy defaults, sampled when the pool is first built.
    // Auth and timeouts belong to requests, never to this shared client.
    // Failed builds are not cached; concurrent successful builds use one winner.
    let _ = CLIENT.set(reqwest::Client::builder().build()?);
    Ok(CLIENT.get().expect("HTTP client initialized"))
}

/// POST to the worker on the shared client with a 30 s request timeout.
pub(crate) async fn cf_post(
    url: &str,
    auth_header: &str,
    token_id: Option<&str>,
    body: &[u8],
) -> Result<reqwest::Response> {
    cf_post_with_timeout(url, auth_header, token_id, body, 30).await
}

/// Same POST as [`cf_post`], but with a caller-chosen timeout (seconds). The fire-and-forget agent audit push needs a short (5 s)
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
    let mut req = http_client()?
        .post(url)
        .timeout(Duration::from_secs(secs))
        .header("Content-Type", "application/json");
    if !auth_header.is_empty() {
        req = req.header("Authorization", auth_header);
    }
    if let Some(id) = token_id {
        req = req.header("VT-Token-Id", id);
    }
    Ok(req.body(body.to_vec()).send().await?)
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
            503 => " (the Worker has no LIMITER binding; see docs/host-token.md)",
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
    // Ephemeral X25519 keypair; StaticSecret zeroizes on drop (S1).
    let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let pk = PublicKey::from(&sk);
    let pk_b64u = URL_SAFE_NO_PAD.encode(pk.as_bytes());

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
    let approve_challenge_hash =
        compute_approve_challenge_hash(pk.as_bytes(), &worker_nonce, ts_ms, salts);

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

    // Ephemeral X25519 keypair; StaticSecret zeroizes on drop (S1).
    let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let pk = PublicKey::from(&sk);
    let pk_b64u = URL_SAFE_NO_PAD.encode(pk.as_bytes());
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
    // Any transport/HTTP failure → fall back to the ceremony rather than abort.
    // One budget covers connect, headers, and the entire body read.
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

/// X25519 shared secret, refusing the all-zero result of a low-order peer.
fn x25519_shared(sk: &StaticSecret, peer: &PublicKey) -> Result<x25519_dalek::SharedSecret> {
    let shared = sk.diffie_hellman(peer);
    if !shared.was_contributory() {
        bail!("x25519: all-zero shared secret (low-order point)");
    }
    Ok(shared)
}

/// Sealed box v1 AES-256-GCM key: HKDF-SHA256(ss, salt = epk ‖ rpk,
/// info = "vt-sealed-box-v1"). `header` is that epk ‖ rpk, also the AAD.
fn sealed_box_key(shared: &x25519_dalek::SharedSecret, header: &[u8; 64]) -> Result<Aes256Gcm> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(header), shared.as_bytes())
        .expand(b"vt-sealed-box-v1", &mut *key)
        .map_err(|_| anyhow!("sealed_box: HKDF expand failed"))?;
    // Path-qualified: `KeyInit::new_from_slice` in scope would shadow `Mac`'s.
    Ok(<Aes256Gcm as aes_gcm::KeyInit>::new((&*key).into()))
}

// One ephemeral key per message, so the key is used once and the nonce is a
// constant (docs/sealed-box-v1.md, Nonce).
const SEALED_BOX_NONCE: [u8; 12] = [0u8; 12];

fn open_sealed_deks(
    ct: &[u8],
    pk: &PublicKey,
    sk: &StaticSecret,
    n_deks: usize,
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    // sealed_box overhead = 48 bytes (ephemeral pk 32 + GCM tag 16)
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

    let epk = PublicKey::from(<[u8; 32]>::try_from(&ct[..32])?);
    let mut header = [0u8; 64];
    header[..32].copy_from_slice(epk.as_bytes());
    header[32..].copy_from_slice(pk.as_bytes());
    // Any failure — a pre-v1 libsodium box included — is this one error.
    let pt = x25519_shared(sk, &epk)
        .and_then(|shared| sealed_box_key(&shared, &header))
        .and_then(|cipher| {
            cipher
                .decrypt(
                    Nonce::from_slice(&SEALED_BOX_NONCE),
                    Payload {
                        msg: &ct[32..],
                        aad: &header,
                    },
                )
                .map_err(|_| anyhow!("aead"))
        })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("sealed_box open failed — possible MITM or wrong key"))?;

    // Auth-only: n_deks == 0, we just needed the approval — return no DEKs.
    let mut deks: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(n_deks);
    for i in 0..n_deks {
        let mut dek = Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&pt[i * 32..(i + 1) * 32]);
        deks.push(dek);
    }
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
    daemon_pk: &PublicKey,
    daemon_sk: &StaticSecret,
    pwa_pk: &[u8; 32],
    approve_challenge_hash: &[u8; 32],
    sealed_deks: &[u8],
    received_tag: &[u8; 32],
) -> Result<()> {
    let shared = x25519_shared(daemon_sk, &PublicKey::from(*pwa_pk))
        .map_err(|_| anyhow!("binding: all-zero shared secret (low-order point)"))?;

    let mut binding_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(b"vt-sealed-deks-bind-v1", &mut *binding_key)
        .map_err(|_| anyhow!("binding: HKDF expand failed"))?;

    let mut transcript = Vec::with_capacity(10 + 32 + 32 + 32 + sealed_deks.len());
    transcript.extend_from_slice(b"vt-bind-v1");
    transcript.extend_from_slice(approve_challenge_hash);
    transcript.extend_from_slice(daemon_pk.as_bytes());
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
            let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let sealed = seal_with(&eph, &[0x42; 32], &PublicKey::from(pk));
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

    /// The probe's single budget covers headers and body on either address family.
    #[tokio::test]
    async fn cache_probe_budget_covers_headers_and_body() {
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

    /// Record-name suggestions ride in `meta.names`, one per salt, and stay
    /// within the Worker's 40-unit cap; an empty list is absent from the wire.
    #[test]
    fn challenge_meta_names_are_capped_and_optional() {
        let mut meta = collect_meta("decrypt", "", "");
        assert!(serde_json::to_value(&meta).unwrap().get("names").is_none());
        meta.names = vec![
            record_name("GH_\x07TOKEN"),
            String::new(),
            record_name(&"é".repeat(50)),
        ];
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["names"][0], "GH_TOKEN");
        assert_eq!(json["names"][1], "");
        let long = json["names"][2].as_str().unwrap();
        assert_eq!(long.encode_utf16().count(), 40);
        assert!(long.ends_with('…'));
        assert_eq!(record_name(&"😀".repeat(20)).encode_utf16().count(), 40);
        assert_eq!(record_name(&"😀".repeat(21)).encode_utf16().count(), 39);
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
        // Same body, same key → same MAC as the Worker computes with the derived
        // secret (crypto-level parity is pinned by the b64u secret above, which
        // is the Worker test suite's golden vector for this id).
        assert_eq!(
            parsed.auth_header(b"{}"),
            hmac_auth_header(
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

    fn keypair() -> (PublicKey, StaticSecret) {
        let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        (PublicKey::from(&sk), sk)
    }

    fn pk_of(sk_bytes: [u8; 32]) -> (PublicKey, StaticSecret) {
        let sk = StaticSecret::from(sk_bytes);
        (PublicKey::from(&sk), sk)
    }

    /// Mirror of the PWA's / Worker's seal (docs/sealed-box-v1.md) with the
    /// ephemeral key supplied, so a vector is reproducible.
    fn seal_with(esk: &StaticSecret, m: &[u8], rpk: &PublicKey) -> Vec<u8> {
        let epk = PublicKey::from(esk);
        let mut header = [0u8; 64];
        header[..32].copy_from_slice(epk.as_bytes());
        header[32..].copy_from_slice(rpk.as_bytes());
        let cipher = sealed_box_key(&x25519_shared(esk, rpk).unwrap(), &header).unwrap();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&SEALED_BOX_NONCE),
                Payload {
                    msg: m,
                    aad: &header,
                },
            )
            .unwrap();
        [epk.as_bytes().as_slice(), &ct].concat()
    }

    // Mirror of the PWA's binding construction. Returns binding_tag.
    fn pwa_build_tag(
        daemon_pk: &PublicKey,
        pwa_sk: &StaticSecret,
        pwa_pk: &[u8; 32],
        approve_challenge_hash: &[u8; 32],
        sealed_deks: &[u8],
    ) -> [u8; 32] {
        let shared = pwa_sk.diffie_hellman(daemon_pk);
        let mut binding_key = [0u8; 32];
        Hkdf::<Sha256>::new(None, shared.as_bytes())
            .expand(b"vt-sealed-deks-bind-v1", &mut binding_key)
            .unwrap();
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"vt-bind-v1");
        transcript.extend_from_slice(approve_challenge_hash);
        transcript.extend_from_slice(daemon_pk.as_bytes());
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

    // docs/sealed-box-v1.md "Test vectors": recipient scalar 32 × 0x11.
    const RSK: [u8; 32] = [0x11; 32];
    const RPK_B64U: &str = "e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM";
    // Ephemeral 32 × 0x22 sealing bytes 0..32 to RPK (cross-checked against an
    // independent X25519/HKDF/AES-GCM implementation).
    const BOX_B64U: &str = "D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyAXd0g_gjeoLbDGIQ2LVzEYHI8va2j8W808kbRSATfGUrDZFYbWuED_lkx7WVYQ6RQ";
    // Ephemeral 32 × 0x33 sealing 32 × 0xaa ‖ 32 × 0xbb to RPK.
    const BOX2_B64U: &str = "ew1H2TQn-DERYHgcfHM_2J-IlwrvSQ2KoO4ZpMuKGxSXlmdFkev5R4nHJPIRmjXxGQdFQ-EGDFB48wLpysDwX7HUNqLVWN3JvVscbJ5oum4eKqAPi7jAR3ZV-37Y2_jNfk6rXmjkpUum2vvzfSn-TQ";
    // The previous release's libsodium crypto_box_seal of bytes 0..32 to RPK.
    const LIBSODIUM_BOX_B64U: &str = "JEYfUWAkbFlSTgjZD-GXcSHkANGFWCT637UiLWtBRUu-uQjaKW_GFnZplKkhLMm3h0-ch65fczHafJozQnVbdv4F-eyFxUbJuJoIzb9Anvw";

    fn recipient() -> (PublicKey, StaticSecret) {
        let (pk, sk) = pk_of(RSK);
        assert_eq!(URL_SAFE_NO_PAD.encode(pk.as_bytes()), RPK_B64U);
        (pk, sk)
    }

    /// The deterministic vectors: seal with the fixed ephemeral key reproduces
    /// the committed box byte for byte, and open returns the message.
    #[test]
    fn sealed_box_v1_deterministic_vectors() {
        let (pk, sk) = recipient();
        let m: Vec<u8> = (0u8..32).collect();
        let sealed = seal_with(&StaticSecret::from([0x22; 32]), &m, &pk);
        assert_eq!(URL_SAFE_NO_PAD.encode(&sealed), BOX_B64U);
        let deks = open_sealed_deks(&sealed, &pk, &sk, 1).unwrap();
        assert_eq!(&deks[0][..], &m[..]);

        let m2 = [[0xaa; 32], [0xbb; 32]].concat();
        let sealed2 = seal_with(&StaticSecret::from([0x33; 32]), &m2, &pk);
        assert_eq!(URL_SAFE_NO_PAD.encode(&sealed2), BOX2_B64U);
        let deks = open_sealed_deks(&sealed2, &pk, &sk, 2).unwrap();
        assert_eq!(*deks[0], [0xaa; 32]);
        assert_eq!(*deks[1], [0xbb; 32]);
    }

    /// Cross-impl wire-compat: a box produced by the WORKER's WebCrypto `seal`
    /// (cf-worker/src/cache_crypto.ts, random ephemeral key) over bytes 0..32
    /// to RPK MUST open here — this is exactly the cache-hit delivery path
    /// (worker re-seals cached DEKs to the daemon pubkey; cf.rs opens). The
    /// reverse direction (this file's `seal_with` → the Worker's `openToCache`)
    /// is pinned in cf-worker/test/cache_crypto.test.ts.
    #[test]
    fn worker_sealed_box_opens_here() {
        let (pk, sk) = recipient();
        let sealed = "VSToDyDrhNwFgC2BgvGG5WWrdbkrB5q5ox66M4uozkLMu34oprFNdzgIaiLdaqKwzlJL_mvtuPgo5xrq11a_nlo8O3WRK8Q3q9e5aGzAcBs";
        let ct = URL_SAFE_NO_PAD.decode(sealed).unwrap();
        let deks = open_sealed_deks(&ct, &pk, &sk, 1).expect("worker-sealed box must open");
        let expected: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            &deks[0][..],
            &expected[..],
            "decrypted DEK mismatch — wire incompatibility"
        );
    }

    /// Rejected input: the libsodium box of the previous release (right
    /// length, right recipient), tamper anywhere, the wrong recipient, and a
    /// low-order ephemeral point all fail as the one opaque error.
    #[test]
    fn sealed_box_v1_rejects_libsodium_tamper_and_wrong_key() {
        let (pk, sk) = recipient();
        let deny = |ct: &[u8]| {
            let err = open_sealed_deks(ct, &pk, &sk, 1).unwrap_err().to_string();
            assert!(err.contains("open failed"), "unexpected: {err}");
        };
        deny(&URL_SAFE_NO_PAD.decode(LIBSODIUM_BOX_B64U).unwrap());
        let sealed = URL_SAFE_NO_PAD.decode(BOX_B64U).unwrap();
        for i in [0, 31, 32, 79] {
            let mut t = sealed.clone();
            t[i] ^= 0x01;
            deny(&t);
        }
        let mut low_order = sealed.clone();
        low_order[..32].fill(0);
        deny(&low_order);
        let (other_pk, other_sk) = pk_of([0x12; 32]);
        assert!(open_sealed_deks(&sealed, &other_pk, &other_sk, 1).is_err());
        // Length is checked first and separately, as before.
        let err = open_sealed_deks(&sealed[..79], &pk, &sk, 1).unwrap_err();
        assert!(err.to_string().contains("length"), "unexpected: {err}");
    }

    #[test]
    fn verify_binding_happy_path() {
        let (daemon_pk, daemon_sk) = keypair();
        let (pwa_pk, pwa_sk) = keypair();
        let pwa_pk = pwa_pk.to_bytes();
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
        let (daemon_pk, daemon_sk) = keypair();
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
        let (daemon_pk, daemon_sk) = keypair();
        let (pwa_pk, pwa_sk) = keypair();
        let pwa_pk = pwa_pk.to_bytes();
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
        let (daemon_pk, daemon_sk) = keypair();
        let (pwa_pk, pwa_sk) = keypair();
        let pwa_pk = pwa_pk.to_bytes();
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
