//! FIDO2 (YubiKey) fallback authentication.
//!
//! Sits between Touch ID and password in `security::authenticate`. Credentials
//! are non-resident (stored server-side in the macOS keychain as an encrypted
//! JSON blob) and touch-only (uv=discouraged, no PIN). Enrollment is gated by
//! Touch ID so an attacker with only keychain write access can't
//! substitute their own pubkey. Each credential tracks a monotonic sign
//! counter; a regression fails auth closed (clone indicator).

use anyhow::{anyhow, bail, Context, Result};
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key::{PublicKey, PublicKeyType};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{get_fidokey_devices, verifier, Cfg, FidoKeyHidFactory};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Assertion;

use crate::core::crypto::AesGcmCrypto;
use super::security::{derive_passcode_ciphers, load_mac_cipher};
use super::store::KeychainStore;

pub const RP_ID: &str = "com.timqi.vt";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PubkeyAlg {
    Ecdsa256,
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidoCredential {
    pub credential_id: Vec<u8>,
    pub pubkey_der: Vec<u8>,
    pub pubkey_alg: PubkeyAlg,
    pub sign_counter: u32,
    pub label: String,
    pub created_at_unix: u64,
}

impl FidoCredential {
    /// Short hex id for display (first 8 bytes of credential_id).
    pub fn short_id(&self) -> String {
        self.credential_id
            .iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

/// Decode the FIDO2 credentials blob from a loaded store. Empty when the
/// `encrypted_fido2` field is absent.
fn decode_credentials(
    store: &KeychainStore,
    cipher: &AesGcmCrypto,
) -> Result<Vec<FidoCredential>> {
    let Some(encrypted) = store.encrypted_fido2_bytes()? else {
        return Ok(Vec::new());
    };
    let plain = cipher.decrypt(&encrypted)?;
    let creds: Vec<FidoCredential> = serde_json::from_slice(&plain)?;
    Ok(creds)
}

fn encode_credentials_into(
    store: &mut KeychainStore,
    cipher: &AesGcmCrypto,
    creds: &[FidoCredential],
) -> Result<()> {
    let json = serde_json::to_vec(creds)?;
    let encrypted = cipher.encrypt(&json)?;
    store.set_encrypted_fido2(&encrypted);
    Ok(())
}

pub fn load_credentials() -> Result<Vec<FidoCredential>> {
    let Ok(store) = KeychainStore::load() else {
        // Vault not initialized → no credentials. Matches the previous
        // "missing keychain item ⇒ empty list" semantics.
        return Ok(Vec::new());
    };
    if store.encrypted_fido2.is_none() {
        return Ok(Vec::new());
    }
    let (_, passphrase_cipher) = derive_passcode_ciphers(&store)?;
    let (mac_cipher, _mac_key) = load_mac_cipher(&store, &passphrase_cipher)?;
    decode_credentials(&store, &mac_cipher)
}

/// User-triggered credential save (register/remove). Holds the cross-process
/// file lock across the read-modify-write so it can't race a concurrent
/// `vt ssh add` writing a different field.
fn save_credentials_locked(creds: &[FidoCredential]) -> Result<()> {
    KeychainStore::modify(|store| {
        let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
        let (mac_cipher, _mac_key) = load_mac_cipher(store, &passphrase_cipher)?;
        encode_credentials_into(store, &mac_cipher, creds)
    })
}

/// Best-effort sign-counter persistence, called from the FIDO2 hot path
/// inside the SSH `sign()` handler. Uses `try_modify` (non-blocking lock):
/// if another vt process is currently inside its own write, we drop the
/// counter update and warn rather than blocking the SSH session.
fn save_credentials_best_effort(creds: &[FidoCredential]) -> Result<bool> {
    KeychainStore::try_modify(|store| {
        let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
        let (mac_cipher, _mac_key) = load_mac_cipher(store, &passphrase_cipher)?;
        encode_credentials_into(store, &mac_cipher, creds)
    })
}

pub fn device_present() -> bool {
    !get_fidokey_devices().is_empty()
}

fn alg_from_pk(pk: &PublicKey) -> Result<PubkeyAlg> {
    match pk.key_type {
        PublicKeyType::Ecdsa256 => Ok(PubkeyAlg::Ecdsa256),
        PublicKeyType::Ed25519 => Ok(PubkeyAlg::Ed25519),
        PublicKeyType::Unknown => bail!("unsupported FIDO2 public key type"),
    }
}

fn pk_type_from_alg(alg: &PubkeyAlg) -> PublicKeyType {
    match alg {
        PubkeyAlg::Ecdsa256 => PublicKeyType::Ecdsa256,
        PubkeyAlg::Ed25519 => PublicKeyType::Ed25519,
    }
}

/// Register a new FIDO2 credential on a plugged-in authenticator.
///
/// Touch-only (no PIN). The caller is responsible for gating this behind a
/// Touch ID prompt — `register()` does not enforce that itself.
pub fn register(label: String) -> Result<FidoCredential> {
    if !device_present() {
        bail!("no FIDO2 authenticator detected (is the YubiKey plugged in?)");
    }

    let mut existing = load_credentials().context("failed to load existing FIDO2 credentials")?;

    let device = FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| anyhow!("failed to open FIDO2 device: {}", e))?;

    let challenge = verifier::create_challenge();
    let user = PublicKeyCredentialUserEntity {
        id: rand_user_id().to_vec(),
        name: std::env::var("USER").unwrap_or_else(|_| "vt".into()),
        display_name: "vt".into(),
    };
    let args = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
        .without_pin_and_uv()
        .user_entity(&user)
        .build();

    eprintln!("Touch the YubiKey to register…");
    let _dialog = TouchDialog::show("Register a new YubiKey credential");
    let att = device
        .make_credential_with_args(&args)
        .map_err(|e| anyhow!("FIDO2 registration failed: {}", e))?;
    drop(_dialog);

    let pk = att.credential_publickey.clone();
    let alg = alg_from_pk(&pk).context("FIDO2 returned unsupported key type")?;
    let cred = FidoCredential {
        credential_id: att.credential_descriptor.id.clone(),
        pubkey_der: pk.der,
        pubkey_alg: alg,
        sign_counter: att.sign_count,
        label,
        created_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };

    if existing
        .iter()
        .any(|c| c.credential_id == cred.credential_id)
    {
        bail!("this credential is already registered");
    }
    existing.push(cred.clone());
    save_credentials_locked(&existing)?;
    Ok(cred)
}

/// Outcome of a FIDO2 authentication attempt.
///
/// `Skip` means FIDO2 was not a viable path (no device, no credentials, device
/// error, bad assertion) — the caller should fall through to the next factor.
/// `Rejected` means the user explicitly clicked Reject in the dialog, or a
/// sign-counter regression was detected — the caller should abort the entire
/// auth chain, not fall back to password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FidoOutcome {
    Success,
    Rejected,
    Skip,
}

/// Attempt FIDO2 assertion using any registered credential. Shows a macOS
/// alert with a Reject button alongside the YubiKey blink; clicking Reject
/// returns `Rejected` immediately. The YubiKey I/O call is blocking and not
/// cancelable, so the worker thread is detached on Reject and will unwind
/// naturally when the authenticator's internal touch timeout (~30s) fires.
pub fn authenticate(reason: &str) -> FidoOutcome {
    if !device_present() {
        tracing::debug!("FIDO2: no authenticator connected");
        return FidoOutcome::Skip;
    }

    let mut creds = match load_credentials() {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => {
            tracing::debug!("FIDO2: no credentials registered");
            return FidoOutcome::Skip;
        }
        Err(e) => {
            tracing::warn!("FIDO2: failed to load credentials: {}", e);
            return FidoOutcome::Skip;
        }
    };

    eprintln!("Touch the YubiKey: {}", reason);
    let dialog = TouchDialog::show(reason);

    let challenge = verifier::create_challenge();
    let credential_ids: Vec<Vec<u8>> = creds.iter().map(|c| c.credential_id.clone()).collect();
    let challenge_for_thread = challenge.to_vec();

    let (ftx, frx) = mpsc::channel::<Result<Assertion, String>>();
    std::thread::spawn(move || {
        let _ = ftx.send(run_assertion(&challenge_for_thread, &credential_ids));
    });

    let assertion = loop {
        match frx.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(a)) => break a,
            Ok(Err(e)) => {
                tracing::warn!("FIDO2: {}", e);
                return FidoOutcome::Skip;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if matches!(dialog.check_action(), DialogAction::Rejected) {
                    tracing::info!("FIDO2: user clicked Reject — aborting auth chain");
                    return FidoOutcome::Rejected;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return FidoOutcome::Skip,
        }
    };
    // Success: drop the dialog now so the alert closes before we do keychain I/O.
    drop(dialog);

    let Some(idx) = creds
        .iter()
        .position(|c| c.credential_id == assertion.credential_id)
    else {
        tracing::warn!("FIDO2: assertion returned unknown credential_id");
        return FidoOutcome::Skip;
    };

    let pk = PublicKey::with_der(
        &creds[idx].pubkey_der,
        pk_type_from_alg(&creds[idx].pubkey_alg),
    );
    if !verifier::verify_assertion(RP_ID, &pk, &challenge, &assertion) {
        tracing::error!("FIDO2: signature verification failed");
        return FidoOutcome::Skip;
    }

    // Monotonic counter check. Some authenticators always return 0 (no counter);
    // only skip enforcement until this credential has produced a non-zero
    // counter. A regression means the authenticator may be cloned — abort the
    // chain, never fall back silently.
    if creds[idx].sign_counter != 0 && assertion.sign_count <= creds[idx].sign_counter {
        tracing::error!(
            "FIDO2: sign counter regression (stored={}, got={}) — possible clone; failing closed",
            creds[idx].sign_counter,
            assertion.sign_count
        );
        return FidoOutcome::Rejected;
    }
    if assertion.sign_count > creds[idx].sign_counter {
        creds[idx].sign_counter = assertion.sign_count;
        // Best-effort: never block the SSH sign() path on a contended file
        // lock. Losing one counter bump means at worst a regression-detection
        // false positive on the next auth, which would log loudly and abort.
        match save_credentials_best_effort(&creds) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    "FIDO2: keychain store busy — skipped persisting sign counter"
                );
            }
            Err(e) => tracing::warn!("FIDO2: failed to persist sign counter: {}", e),
        }
    }

    FidoOutcome::Success
}

fn run_assertion(challenge: &[u8], credential_ids: &[Vec<u8>]) -> Result<Assertion, String> {
    let device =
        FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| format!("open FIDO2 device: {}", e))?;
    let mut builder = GetAssertionArgsBuilder::new(RP_ID, challenge).without_pin_and_uv();
    for id in credential_ids {
        builder = builder.add_credential_id(id);
    }
    let assertions = device
        .get_assertion_with_args(&builder.build())
        .map_err(|e| format!("assertion failed: {}", e))?;
    assertions
        .into_iter()
        .next()
        .ok_or_else(|| "no assertions returned".into())
}

pub fn list() -> Result<Vec<FidoCredential>> {
    load_credentials()
}

/// Remove credentials whose `short_id()` starts with `prefix`. Returns the
/// number removed.
pub fn remove(prefix: &str) -> Result<usize> {
    let creds = load_credentials()?;
    let (keep, drop): (Vec<_>, Vec<_>) = creds
        .into_iter()
        .partition(|c| !c.short_id().starts_with(prefix));
    if drop.is_empty() {
        bail!("no FIDO2 credential matches '{}'", prefix);
    }
    save_credentials_locked(&keep)?;
    Ok(drop.len())
}

pub fn remove_all() -> Result<usize> {
    let creds = load_credentials()?;
    let n = creds.len();
    save_credentials_locked(&[])?;
    Ok(n)
}

fn rand_user_id() -> [u8; 16] {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DialogAction {
    Pending,
    Rejected,
    Other, // gave up (60s timeout) / killed by us / other close
}

/// Standard macOS alert (`display alert`) with a Reject button. Runs as a
/// background `osascript` process. On drop the process is killed so the alert
/// is dismissed on any return path. The osascript stdout is drained in a
/// reader thread; `check_action()` polls the result non-blockingly.
struct TouchDialog {
    child: Option<Child>,
    result_rx: mpsc::Receiver<String>,
}

impl TouchDialog {
    fn show(reason: &str) -> Self {
        let safe_reason = reason.replace('\\', "\\\\").replace('"', "\\\"");
        // The alert is owned by osascript itself (no `tell application "System
        // Events"`) so killing the child actually dismisses it. Delegating to
        // System Events would leak the alert because it'd be owned by a
        // different process.
        let script = format!(
            r#"display alert "vt" message "🔑 Touch YubiKey — {}" buttons {{"Reject"}} as critical giving up after 60"#,
            safe_reason
        );
        let mut child = Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok();

        let (tx, rx) = mpsc::channel();
        if let Some(c) = child.as_mut() {
            if let Some(mut stdout) = c.stdout.take() {
                std::thread::spawn(move || {
                    let mut buf = String::new();
                    let _ = stdout.read_to_string(&mut buf);
                    let _ = tx.send(buf);
                });
            }
        }

        Self {
            child,
            result_rx: rx,
        }
    }

    fn check_action(&self) -> DialogAction {
        match self.result_rx.try_recv() {
            Ok(s) if s.contains("button returned:Reject") => DialogAction::Rejected,
            Ok(_) => DialogAction::Other,
            Err(mpsc::TryRecvError::Empty) => DialogAction::Pending,
            Err(mpsc::TryRecvError::Disconnected) => DialogAction::Other,
        }
    }
}

impl Drop for TouchDialog {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
