//! Cross-platform SSH-over-`vt://` commands.
//!
//! The Ed25519 private key is stored as an ordinary `SecretType::RAW` v2 record
//! whose plaintext is `BASE64_URL_SAFE_NO_PAD(seed[32])` — reusing the existing
//! encrypt/decrypt ceremony with zero core/worker changes. `keygen` creates the
//! identity here; `connect` (the git SSH driver) lands in a follow-up.
//!
//! See `docs/ssh-vt-design.md` for the full design and security boundary.

use anyhow::{bail, Context, Result};

use crate::client::VTClient;
use crate::core::{EncryptItem, SecretType};

/// Default location of the encrypted key record, relative to `$HOME`.
const DEFAULT_REL_PATH: &str = ".config/vt/git-ssh";

/// `vt ssh keygen`: generate an Ed25519 keypair in memory, store the seed as a
/// RAW `vt://` record (ciphertext on disk), and print/write the OpenSSH public
/// key. The plaintext seed never touches disk.
pub async fn keygen(
    vt_client: VTClient,
    label: Option<String>,
    comment: Option<String>,
    key_file: Option<String>,
) -> Result<()> {
    #[cfg(unix)]
    {
        keygen_unix(vt_client, label, comment, key_file).await
    }
    #[cfg(not(unix))]
    {
        let _ = (vt_client, label, comment, key_file);
        bail!("vt ssh keygen requires Unix")
    }
}

#[cfg(unix)]
async fn keygen_unix(
    vt_client: VTClient,
    label: Option<String>,
    comment: Option<String>,
    key_file: Option<String>,
) -> Result<()> {
    use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use ssh_key::public::{Ed25519PublicKey, KeyData, PublicKey};
    use zeroize::{Zeroize, Zeroizing};

    // 1. Generate the keypair in memory.
    let signing = SigningKey::generate(&mut OsRng);
    let mut seed = signing.to_bytes(); // [u8; 32], the Ed25519 seed
    let pub_bytes = signing.verifying_key().to_bytes();

    // 2. base64url(seed) -> encrypt as RAW -> vt://0...  (seed wiped immediately)
    let seed_b64 = Zeroizing::new(BASE64_URL_SAFE_NO_PAD.encode(seed));
    seed.zeroize();
    drop(signing);
    let res = vt_client
        .encrypt(&[EncryptItem {
            plaintext: seed_b64.to_string(),
            t: SecretType::RAW,
        }])
        .await?;
    if !res[0].err_message.is_empty() {
        bail!("failed to encrypt ssh key: {}", res[0].err_message);
    }
    let vt_url = res[0].result.clone();

    // 3. OpenSSH public-key line (encoding only — no secret material).
    let comment_str = comment.or(label).unwrap_or_default();
    let pk = PublicKey::new(KeyData::Ed25519(Ed25519PublicKey(pub_bytes)), comment_str);
    let pub_line = pk.to_openssh().context("encode openssh public key")?;

    // 4. Resolve paths and write files (ciphertext vt:// + cleartext pubkey only).
    let key_path = resolve_key_path(key_file)?;
    let pub_path = pubkey_path(&key_path);
    if let Some(parent) = key_path.parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_0700(parent)?;
        }
    }
    write_new_file(&key_path, vt_url.as_bytes(), 0o600)
        .with_context(|| format!("write {}", key_path.display()))?;
    write_new_file(&pub_path, format!("{pub_line}\n").as_bytes(), 0o644)
        .with_context(|| format!("write {}", pub_path.display()))?;

    // 5. Echo result + usage guidance.
    println!("{pub_line}");
    println!();
    println!("public key   -> {} (add this to GitHub)", pub_path.display());
    println!("vt:// record -> {} (mode 0600, ciphertext)", key_path.display());
    println!("vt url       : {vt_url}");
    println!();
    println!("On each host that runs `git push`:");
    println!("  git config core.sshCommand \"vt ssh connect\"");
    println!(
        "  # copy {} to the host (it is ciphertext), or set VT_GIT_SSH_PRIVATE_KEY=<vt:// record>",
        key_path.display()
    );
    println!("  #   (and VT_GIT_SSH_PUB=<openssh public key line> when not copying the .pub)");
    Ok(())
}

#[cfg(unix)]
fn default_key_path() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().context("cannot resolve home directory")?;
    Ok(home.join(DEFAULT_REL_PATH))
}

/// Resolve the *output* key-file path for `keygen`: explicit `--key-file` flag >
/// default. The raw-content env vars (`VT_GIT_SSH_PRIVATE_KEY` /
/// `VT_GIT_SSH_PUB`) are read sources for `connect`, never write destinations.
#[cfg(unix)]
fn resolve_key_path(flag: Option<String>) -> Result<std::path::PathBuf> {
    if let Some(p) = flag {
        return Ok(std::path::PathBuf::from(p));
    }
    default_key_path()
}

/// Load the OPTIONAL ciphertext `vt://` record for `connect`. The raw
/// `VT_GIT_SSH_PRIVATE_KEY` env value (if non-empty) takes precedence;
/// otherwise read the default key file (`~/.config/vt/git-ssh`).
///
/// Returns `Ok(None)` when neither source exists (`ErrorKind::NotFound` on the
/// default file) — the normal case on a macOS Keychain-backed host that signs
/// via `sign@vt`. Any OTHER IO error (e.g. permission denied) stays fatal.
/// A present-but-non-`vt://` record is a configuration error and fails here, so
/// the contract ("a record is a `vt://` URL") is enforced at load, not at use.
#[cfg(unix)]
async fn load_private_record_opt() -> Result<Option<String>> {
    let record = if let Ok(v) = std::env::var("VT_GIT_SSH_PRIVATE_KEY") {
        let v = v.trim();
        if v.is_empty() {
            load_default_key_file().await?
        } else {
            Some(v.to_string())
        }
    } else {
        load_default_key_file().await?
    };
    if let Some(ref u) = record {
        if !u.starts_with("vt://") {
            bail!("VT_GIT_SSH_PRIVATE_KEY / default key file does not contain a vt:// record");
        }
    }
    Ok(record)
}

/// Read the default ciphertext key file (`~/.config/vt/git-ssh`), `Ok(None)` if
/// absent. Other IO errors stay fatal.
#[cfg(unix)]
async fn load_default_key_file() -> Result<Option<String>> {
    let key_path = default_key_path()?;
    match tokio::fs::read_to_string(&key_path).await {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("read {}", key_path.display()))),
    }
}

/// `<key>` -> `<key>.pub`.
#[cfg(unix)]
fn pubkey_path(key: &std::path::Path) -> std::path::PathBuf {
    let mut s = key.as_os_str().to_os_string();
    s.push(".pub");
    std::path::PathBuf::from(s)
}

#[cfg(unix)]
fn create_dir_0700(dir: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    Ok(())
}

/// Create-new write with `O_NOFOLLOW` + explicit mode (no umask reliance, no
/// symlink redirection, no clobber). Mirrors the safe-write pattern in `inject`.
#[cfg(unix)]
fn write_new_file(path: &std::path::Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow::anyhow!(
                    "{} already exists; remove it or pass --key-file <path>",
                    path.display()
                )
            } else {
                anyhow::Error::new(e)
            }
        })?;
    f.write_all(contents)?;
    Ok(())
}

// ── vt ssh connect (git SSH driver) ──────────────────────────────────────────

/// `vt ssh connect`: a `GIT_SSH_COMMAND` driver. Loads the cleartext public key
/// + the ciphertext `vt://` record from the key file, starts an ephemeral
/// in-process SSH-agent that answers `REQUEST_IDENTITIES` from the public key
/// (no tap) and signs `SIGN_REQUEST` by decrypting the seed on demand via the
/// existing ceremony, then execs the system `ssh` pointed at that agent.
pub async fn connect(vt_client: VTClient, args: Vec<String>) -> Result<()> {
    #[cfg(unix)]
    {
        connect_unix(vt_client, args).await
    }
    #[cfg(not(unix))]
    {
        let _ = (vt_client, args);
        bail!("vt ssh connect requires Unix")
    }
}

#[cfg(unix)]
async fn connect_unix(vt_client: VTClient, args: Vec<String>) -> Result<()> {
    // 1. Resolve which identity/identities to advertise. An explicit pubkey
    //    (VT_GIT_SSH_PUB / ~/.config/vt/git-ssh.pub) takes precedence and may
    //    carry a vt:// record for the decrypt-then-sign fallback; otherwise, with
    //    VT_AUTH set, discover ALL keys from the upstream vt agent (each signs via
    //    `sign@vt`). See `resolve_identities` for the full precedence + errors.
    let identities = resolve_identities(&vt_client).await?;

    // 2. Best-effort audit context from our own argv (we are git's child).
    //    op_kind stays "decrypt" (decrypt's existing meta); the human-meaningful
    //    label rides the `command` field shown on the approval page / audit.
    let host = parse_ssh_host(&args).unwrap_or_default();
    let op = if args.iter().any(|a| a.contains("git-receive-pack")) {
        "push"
    } else if args.iter().any(|a| a.contains("git-upload-pack")) {
        "fetch"
    } else {
        "ssh"
    };
    let command = if host.is_empty() {
        format!("ssh-sign: {op}")
    } else {
        format!("ssh-sign: {op} -> {host}")
    };

    // 3. Ephemeral signer socket in a private 0700 dir.
    let dir = make_temp_dir_0700()?;
    let sock_path = dir.join("agent.sock");
    let inner = std::sync::Arc::new(SignerInner {
        client: vt_client,
        identities,
        host,
        command,
    });
    let listener = tokio::net::UnixListener::bind(&sock_path)
        .with_context(|| format!("bind {}", sock_path.display()))?;
    chmod_0600(&sock_path)?;

    // 4. Run the agent + child ssh concurrently. The child must talk to OUR
    //    ephemeral signer socket so the `sign@vt` context (host/command) is
    //    injected. We pin it two ways:
    //      - `-o IdentityAgent=<sock>` on the command line — HIGHEST precedence,
    //        so it beats any `IdentityAgent` in the user's ~/.ssh/config (e.g.
    //        `IdentityAgent ~/.ssh/vt.sock`, the natural vt setup, which would
    //        otherwise hijack the child straight to the real agent and bypass
    //        the shim → context-less standard sign).
    //      - `SSH_AUTH_SOCK` via Command::env as belt-and-suspenders (lowest
    //        precedence; loses to a config IdentityAgent, hence the `-o`).
    //    The PARENT env keeps the original (possibly forwarded) agent so the
    //    signer's own decrypt/sign@vt resolves it. NEVER env::set_var (would make
    //    the signer connect to itself — D14 / round-3 B1).
    //    Our `-o` precedes git's args and ssh takes the FIRST IdentityAgent
    //    value, so it wins regardless of what git appends.
    let factory = SignerFactory { inner };

    // Run the agent + child ssh concurrently; capture the outcome so the
    // socket/dir are cleaned up exactly once regardless of which arm wins.
    let outcome: Result<std::process::ExitStatus> = async {
        let mut child = tokio::process::Command::new("ssh")
            .arg("-o")
            .arg(format!("IdentityAgent={}", sock_path.display()))
            .args(&args)
            .env("SSH_AUTH_SOCK", &sock_path)
            .spawn()
            .context("spawn system ssh (is it installed?)")?;
        let listen_fut = ssh_agent_lib::agent::listen(listener, factory);
        tokio::pin!(listen_fut);
        tokio::select! {
            r = child.wait() => r.context("wait for ssh"),
            e = &mut listen_fut => bail!("ephemeral ssh-agent exited unexpectedly: {e:?}"),
        }
    }
    .await;

    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_dir(&dir);

    // 5. Propagate ssh's exit code.
    let status = outcome?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Load the OPTIONAL OpenSSH public-key line for `connect`: the raw
/// `VT_GIT_SSH_PUB` env value takes precedence; otherwise read the sibling
/// `.pub` of the default key file (`~/.config/vt/git-ssh.pub`).
///
/// Returns `Ok(None)` when neither source exists (so `resolve_identities` can
/// fall through to agent discovery). Any other IO error (e.g. permission
/// denied) stays fatal. Mirrors `load_private_record_opt`.
#[cfg(unix)]
async fn load_pubkey_line_opt() -> Result<Option<String>> {
    if let Ok(p) = std::env::var("VT_GIT_SSH_PUB") {
        if !p.trim().is_empty() {
            return Ok(Some(p));
        }
    }
    let pub_path = pubkey_path(&default_key_path()?);
    match tokio::fs::read_to_string(&pub_path).await {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("read {} (or set VT_GIT_SSH_PUB)", pub_path.display()))),
    }
}

/// Resolve the identity/identities `connect` advertises to system `ssh`.
///
/// Precedence:
/// 1. **Explicit pubkey** (`VT_GIT_SSH_PUB` env, else `~/.config/vt/git-ssh.pub`):
///    one identity, optionally carrying a `vt://` record for decrypt-then-sign.
/// 2. **Agent discovery** — only when `VT_AUTH` is set (`sign@vt` needs it):
///    list ALL keys the upstream vt agent holds and advertise every one
///    (`vt_url: None`). Signing routes through `sign@vt` per key.
/// 3. Otherwise an actionable error.
#[cfg(unix)]
async fn resolve_identities(client: &VTClient) -> Result<Vec<SignerIdentity>> {
    use ssh_key::public::PublicKey;

    // 1. Explicit pubkey — reproducible pin, highest precedence.
    if let Some(pub_line) = load_pubkey_line_opt().await? {
        let pubkey =
            PublicKey::from_openssh(pub_line.trim()).context("parse OpenSSH public key")?;
        let vt_url = load_private_record_opt().await?;
        return Ok(vec![make_signer_identity(
            pubkey.key_data().clone(),
            pubkey.comment().to_string(),
            vt_url,
        )?]);
    }

    // No explicit pubkey. A record without a pubkey is unusable here — warn so
    // it's not silently ignored before we fall through to discovery.
    if std::env::var("VT_GIT_SSH_PRIVATE_KEY")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        tracing::warn!(
            "VT_GIT_SSH_PRIVATE_KEY is set but no public key was found; set \
             VT_GIT_SSH_PUB to use the private key record — falling back to agent discovery"
        );
    }

    // 2. Agent discovery — gated on VT_AUTH (sign@vt needs the derived key;
    //    discovery from a foreign $SSH_AUTH_SOCK agent would only fail at sign
    //    time). list_agent_identities is BLOCKING → spawn_blocking.
    if client.has_auth_token() {
        let client = client.clone();
        let ids = tokio::task::spawn_blocking(move || client.list_agent_identities())
            .await
            .context("agent identity discovery task panicked")??;
        if !ids.is_empty() {
            return ids
                .into_iter()
                .map(|id| make_signer_identity(id.pubkey, id.comment, None))
                .collect();
        }
    }

    // 3. Nothing to advertise.
    bail!(
        "no SSH identity for `vt ssh connect`: set VT_GIT_SSH_PUB (or write \
         ~/.config/vt/git-ssh.pub), or start `vt ssh agent` with a key loaded and \
         VT_AUTH set so connect can discover it. If $SSH_AUTH_SOCK points at a \
         non-vt agent, unset it."
    )
}

/// Build a `SignerIdentity`, wire-encoding `pubkey` so the agent decodes +
/// fingerprints it identically to its stored keys (no format drift). Shared by
/// both `resolve_identities` branches (explicit pubkey + agent discovery).
#[cfg(unix)]
fn make_signer_identity(
    pubkey: ssh_key::public::KeyData,
    comment: String,
    vt_url: Option<String>,
) -> Result<SignerIdentity> {
    use ssh_agent_lib::ssh_encoding::Encode;
    let mut pubkey_bytes = Vec::new();
    pubkey
        .encode(&mut pubkey_bytes)
        .context("encode public key")?;
    Ok(SignerIdentity {
        pubkey,
        pubkey_bytes,
        comment,
        vt_url,
        key: tokio::sync::OnceCell::new(),
    })
}

#[cfg(unix)]
fn make_temp_dir_0700() -> Result<std::path::PathBuf> {
    use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
    use rand::RngCore;
    use std::os::unix::fs::DirBuilderExt;
    let mut buf = [0u8; 9];
    rand::thread_rng().fill_bytes(&mut buf);
    let name = format!("vt-ssh-{}-{}", std::process::id(), BASE64_URL_SAFE_NO_PAD.encode(buf));
    let dir = std::env::temp_dir().join(name);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(false)
        .create(&dir)
        .with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

#[cfg(unix)]
fn chmod_0600(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}

/// Best-effort: pull the `[user@]host` token out of ssh's argv for the audit
/// label. Not security-relevant; a miss just yields an empty host.
#[cfg(unix)]
fn parse_ssh_host(args: &[String]) -> Option<String> {
    // Short options that consume the following token as their value.
    const VAL_OPTS: &[&str] = &[
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
        "-Q", "-R", "-S", "-W", "-w",
    ];
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            // `-p 2222` (separate value) vs `-p2222` (attached): only skip the
            // next token when the flag is exactly a value-taking short option.
            if VAL_OPTS.contains(&a.as_str()) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        return Some(a.clone());
    }
    None
}

/// One advertisable identity. `connect` advertises either a single explicitly
/// configured key (env/file, may carry a `vt_url` record for the decrypt-then-
/// sign fallback) or ALL keys discovered from the upstream agent (each with
/// `vt_url: None`, since discovery has no record — those sign via `sign@vt` or
/// hard-fail per G3).
#[cfg(unix)]
struct SignerIdentity {
    pubkey: ssh_key::public::KeyData,
    /// SSH wire-encoded `pubkey`, sent in `sign@vt` to identify the agent key.
    pubkey_bytes: Vec<u8>,
    comment: String,
    /// Ciphertext `vt://` record for the decrypt-then-sign fallback. `None` on a
    /// Keychain-backed host (signs via `sign@vt`) and on every discovered key;
    /// the fallback then hard-fails (G3).
    vt_url: Option<String>,
    /// Decrypted seed (fallback path only), initialized once per process.
    key: tokio::sync::OnceCell<zeroize::Zeroizing<[u8; 32]>>,
}

#[cfg(unix)]
struct SignerInner {
    client: VTClient,
    /// Identities advertised to the system `ssh`. One when an explicit pubkey is
    /// configured; one-or-more when discovered from the upstream agent.
    identities: Vec<SignerIdentity>,
    host: String,
    command: String,
}

#[cfg(unix)]
struct SignerFactory {
    inner: std::sync::Arc<SignerInner>,
}

#[cfg(unix)]
struct SignerSession {
    inner: std::sync::Arc<SignerInner>,
}

#[cfg(unix)]
impl ssh_agent_lib::agent::Agent<tokio::net::UnixListener> for SignerFactory {
    fn new_session(
        &mut self,
        _socket: &tokio::net::UnixStream,
    ) -> impl ssh_agent_lib::agent::Session {
        SignerSession {
            inner: std::sync::Arc::clone(&self.inner),
        }
    }
}

#[cfg(unix)]
fn sign_err(msg: impl Into<String>) -> ssh_agent_lib::error::AgentError {
    ssh_agent_lib::error::AgentError::other(std::io::Error::other(msg.into()))
}

/// Pure routing decision for `SignerSession::sign`, extracted so the fallback
/// policy (guardrail G3) is unit-testable without a live agent socket.
#[cfg(unix)]
#[derive(Debug)]
enum SignRoute {
    /// `sign@vt` succeeded — use this `(algorithm, signature)`.
    Use(String, Vec<u8>),
    /// Fall back to local decrypt-then-sign (a `vt://` record is available).
    Fallback,
    /// Hard fail with this message — NO fallback.
    Fail(String),
}

/// Decide what `sign()` does given the `sign_vt` outcome and whether a `vt://`
/// record exists for the fallback path. G3: only `Ok(None)` (agent absent / key
/// not held / recoverable) may fall back, and only if a record exists; an `Err`
/// (AuthRejected / BadRequest) NEVER falls back, even when a record exists.
#[cfg(unix)]
fn decide_sign_route(outcome: Result<Option<(String, Vec<u8>)>>, has_vt_url: bool) -> SignRoute {
    match outcome {
        Ok(Some((alg, sig))) => SignRoute::Use(alg, sig),
        Ok(None) if has_vt_url => SignRoute::Fallback,
        Ok(None) => SignRoute::Fail(
            "no vt agent holds this key and no vt:// record is configured \
             (set VT_GIT_SSH_PRIVATE_KEY or place the record at ~/.config/vt/git-ssh, \
             or ensure the vt agent at $SSH_AUTH_SOCK / ~/.ssh/vt.sock holds this key)"
                .to_string(),
        ),
        Err(e) => SignRoute::Fail(e.to_string()),
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl ssh_agent_lib::agent::Session for SignerSession {
    async fn request_identities(
        &mut self,
    ) -> Result<Vec<ssh_agent_lib::proto::Identity>, ssh_agent_lib::error::AgentError> {
        Ok(self
            .inner
            .identities
            .iter()
            .map(|id| ssh_agent_lib::proto::Identity {
                pubkey: id.pubkey.clone(),
                comment: id.comment.clone(),
            })
            .collect())
    }

    async fn sign(
        &mut self,
        request: ssh_agent_lib::proto::SignRequest,
    ) -> Result<ssh_key::Signature, ssh_agent_lib::error::AgentError> {
        use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
        use ed25519_dalek::{Signer, SigningKey};
        use ssh_agent_lib::error::AgentError;
        use ssh_key::{Algorithm, Signature};
        use zeroize::Zeroizing;

        // Resolve the advertised identity by INDEX (never hold a `find()`
        // reference across the awaits below — that would make this future
        // non-`Send` and `agent::listen` would reject it). Clone the small
        // fields we need before the first await.
        let idx = self
            .inner
            .identities
            .iter()
            .position(|id| id.pubkey == request.pubkey)
            .ok_or(AgentError::Failure)?;
        // Extract what we need from the matched identity BEFORE any await; the
        // borrow is dropped here so it can't make this future non-`Send`. The
        // `key` OnceCell is re-indexed after the await (OnceCell is Send+Sync).
        let (pubkey_bytes, vt_url_opt) = {
            let id = &self.inner.identities[idx];
            (id.pubkey_bytes.clone(), id.vt_url.clone())
        };

        // 1. Agent-internal sign with vt context (e.g. macOS Keychain key): the
        //    private key never leaves the agent. The fallback policy (G3) is in
        //    the pure `decide_sign_route` so it can be unit-tested.
        let outcome = self
            .inner
            .client
            .sign_vt(
                &self.inner.host,
                &self.inner.command,
                &pubkey_bytes,
                &request.data,
                request.flags,
            )
            .await;
        let vt_url = match decide_sign_route(outcome, vt_url_opt.is_some()) {
            SignRoute::Use(alg, sig) => {
                let algorithm = Algorithm::new(&alg).map_err(AgentError::other)?;
                return Signature::new(algorithm, sig).map_err(AgentError::other);
            }
            SignRoute::Fail(msg) => return Err(sign_err(msg)),
            // Fallback implies `vt_url.is_some()`, so this unwrap always yields Some.
            SignRoute::Fallback => {
                vt_url_opt.expect("Fallback route requires a vt:// record")
            }
        };

        // 2. Fallback path: decrypt-then-sign locally with the vt:// record.
        // Decrypt the seed once (get_or_try_init: errors are NOT cached, so a
        // rejected Touch ID / passkey can be retried on a later request).
        // `&OnceCell` borrowed across the await is fine (OnceCell: Send+Sync).
        let seed = self
            .inner
            .identities[idx]
            .key
            .get_or_try_init(|| async {
                let inner = &self.inner;
                let res = inner
                    .client
                    .decrypt(&inner.host, &inner.command, std::slice::from_ref(&vt_url))
                    .await
                    .map_err(|e| sign_err(e.to_string()))?;
                if res.is_empty() || !res[0].err_message.is_empty() {
                    let msg = res.first().map(|r| r.err_message.clone()).unwrap_or_default();
                    return Err(sign_err(format!("decrypt ssh key failed: {msg}")));
                }
                let bytes = BASE64_URL_SAFE_NO_PAD
                    .decode(res[0].result.trim())
                    .map_err(|e| sign_err(format!("ssh seed base64: {e}")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| sign_err("ssh seed must be 32 bytes"))?;
                Ok::<_, AgentError>(Zeroizing::new(arr))
            })
            .await?;

        let signing = SigningKey::from_bytes(seed);
        let sig = signing.sign(&request.data);
        Signature::new(Algorithm::Ed25519, sig.to_bytes().to_vec()).map_err(AgentError::other)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // §9.3: the seed round-trips through base64url and reconstructs the same key.
    // Guards NEW-B1 (an alphabet/padding mismatch would corrupt the key silently).
    #[test]
    fn seed_base64url_roundtrip_preserves_key() {
        let sk = SigningKey::generate(&mut OsRng);
        let seed = sk.to_bytes();
        let pub1 = sk.verifying_key().to_bytes();

        let enc = BASE64_URL_SAFE_NO_PAD.encode(seed);
        assert_eq!(enc.len(), 43, "32-byte seed must encode to 43 url-safe no-pad chars");

        let dec = BASE64_URL_SAFE_NO_PAD.decode(&enc).unwrap();
        let seed2: [u8; 32] = dec.try_into().expect("decoded seed must be 32 bytes");
        let sk2 = SigningKey::from_bytes(&seed2);
        assert_eq!(
            sk2.verifying_key().to_bytes(),
            pub1,
            "recovered key must match the original"
        );
    }

    // The pinned encoder must never emit standard-base64 chars (+ / =).
    #[test]
    fn encoder_is_url_safe_no_pad() {
        let url = BASE64_URL_SAFE_NO_PAD.encode([0xffu8; 32]);
        assert!(!url.contains('+') && !url.contains('/') && !url.contains('='));
    }

    // A malformed/short record must be rejected by the 32-byte length check.
    #[test]
    fn short_record_rejected() {
        let dec = BASE64_URL_SAFE_NO_PAD.decode("AAAA").unwrap(); // 3 bytes
        let r: Result<[u8; 32], _> = dec.try_into();
        assert!(r.is_err());
    }

    // ── sign@vt routing (guardrail G3) ───────────────────────────────────────

    #[test]
    fn sign_route_uses_agent_signature() {
        match super::decide_sign_route(Ok(Some(("ssh-ed25519".into(), vec![1, 2, 3]))), true) {
            super::SignRoute::Use(alg, sig) => {
                assert_eq!(alg, "ssh-ed25519");
                assert_eq!(sig, vec![1, 2, 3]);
            }
            other => panic!("expected Use, got {other:?}"),
        }
    }

    #[test]
    fn sign_route_falls_back_when_none_and_record_present() {
        assert!(matches!(
            super::decide_sign_route(Ok(None), true),
            super::SignRoute::Fallback
        ));
    }

    #[test]
    fn sign_route_hard_fails_when_none_and_no_record() {
        match super::decide_sign_route(Ok(None), false) {
            super::SignRoute::Fail(m) => assert!(m.contains("no vt agent")),
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    // G3 core: a sign@vt error (AuthRejected / BadRequest) must NEVER fall back,
    // even when a vt:// record is available — otherwise a declined Touch ID
    // would silently re-prompt via the decrypt path.
    #[test]
    fn sign_route_err_never_falls_back_even_with_record() {
        let err = Err(anyhow::anyhow!("vt: authentication rejected"));
        match super::decide_sign_route(err, true) {
            super::SignRoute::Fail(m) => assert!(m.contains("authentication rejected")),
            other => panic!("expected Fail (no fallback), got {other:?}"),
        }
    }

    // The pubkey connect encodes (Encode) must decode (Decode) on the agent to a
    // KeyData with the SAME SHA256 fingerprint — the contract `sign@vt` lookup
    // relies on (no format drift between the cross-platform client and the agent).
    #[test]
    fn pubkey_wire_roundtrip_preserves_fingerprint() {
        use ssh_agent_lib::ssh_encoding::{Decode, Encode};
        use ssh_key::public::{Ed25519PublicKey, KeyData, PublicKey};
        use ssh_key::{Fingerprint, HashAlg};

        let sk = SigningKey::generate(&mut OsRng);
        let kd = KeyData::Ed25519(Ed25519PublicKey(sk.verifying_key().to_bytes()));

        let mut wire = Vec::new();
        kd.encode(&mut wire).unwrap();
        let decoded = KeyData::decode(&mut wire.as_slice()).unwrap();

        let fp_orig = Fingerprint::new(HashAlg::Sha256, &kd).to_string();
        let fp_decoded = Fingerprint::new(HashAlg::Sha256, &decoded).to_string();
        assert_eq!(fp_orig, fp_decoded);

        // …and equals the fingerprint of the advertised OpenSSH public key.
        let pk = PublicKey::new(kd, "");
        assert_eq!(pk.fingerprint(HashAlg::Sha256).to_string(), fp_decoded);
    }
}
