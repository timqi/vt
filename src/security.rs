use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub fn set_keychain(name: &str, _value: &[u8]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use security_framework::passwords::set_generic_password;
        let service = "rusty.vault.".to_string() + name;
        set_generic_password(&service, &"prod".to_string(), &_value)?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        anyhow::bail!("keychain is only supported on macOS");
    }
    #[cfg(target_os = "macos")]
    Ok(())
}

pub fn get_keychain(name: &str) -> Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        use security_framework::passwords::get_generic_password;
        let service = "rusty.vault.".to_string() + name;
        get_generic_password(&service, &"prod".to_string())
            .map_err(|e| anyhow::anyhow!("Failed to get keychain {}: {}", name, e))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        anyhow::bail!("keychain is only supported on macOS");
    }
}

#[allow(dead_code)]
pub fn delete_keychain(name: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use security_framework::passwords::delete_generic_password;
        let service = "rusty.vault.".to_string() + name;
        delete_generic_password(&service, &"prod".to_string())
            .map_err(|e| anyhow::anyhow!("Failed to delete keychain {}: {}", name, e))?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        anyhow::bail!("keychain is only supported on macOS");
    }
    #[cfg(target_os = "macos")]
    Ok(())
}

/// Which method satisfied the auth request. Useful for callers that want to
/// treat factor strength differently (e.g. the SSH agent cache doesn't cache
/// FIDO2 since touch-only is weaker than Touch ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Biometric,
    Fido2,
    Password,
}

/// Why authentication could not even be attempted right now. Distinct from
/// `Rejected`, which means the user actively declined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// Screen is locked, user not on console, or login window has not finished.
    /// Touch ID dialog cannot display, so no fallback is offered either —
    /// physical-presence model: locked machine ⇒ no auth.
    NotInteractive,
    /// `CGSessionCopyCurrentDictionary` returned NULL (e.g. LaunchDaemon
    /// context with no GUI session at all).
    NoGuiSession,
}

/// Result of an authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// User successfully authenticated via the indicated method.
    Success(AuthMethod),
    /// User actively declined (terminal — no fallback).
    Rejected,
    /// System cannot prompt right now (locked, no GUI, etc.).
    Unavailable(UnavailableReason),
}

impl AuthOutcome {
    pub fn is_success(self) -> bool {
        matches!(self, AuthOutcome::Success(_))
    }
}

/// What kind of macOS notification we're throttling. Keyed by kind only —
/// reason strings are user-controllable (e.g. via remote `auth@vt`) and would
/// let an attacker bypass dedup by rotating reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotifyKind {
    TouchIdRejected,
    Locked,
}

/// Classification of `CGSessionCopyCurrentDictionary`'s state. Pure type,
/// no FFI — produced by `classify_session` and consumable in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// User on console, login complete, screen unlocked → Touch ID can prompt.
    Interactive,
    /// Locked, off-console, or login pending → Touch ID dialog can't display.
    NotInteractive,
    /// `CGSessionCopyCurrentDictionary` returned NULL.
    NoSession,
}

/// Three CGSession dict booleans we care about. `None` = key absent (treated
/// as "no info" — defaults to unblocking that particular check).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionFlags {
    pub is_locked: Option<bool>,
    pub is_on_console: Option<bool>,
    pub is_login_done: Option<bool>,
}

/// Pure classifier. `None` flags = NULL dict from CGSession.
pub fn classify_session(flags: Option<SessionFlags>) -> SessionState {
    let Some(f) = flags else {
        return SessionState::NoSession;
    };
    if f.is_locked == Some(true)
        || f.is_on_console == Some(false)
        || f.is_login_done == Some(false)
    {
        return SessionState::NotInteractive;
    }
    SessionState::Interactive
}

/// Pure: 1s-TTL cache check over an injectable lookup. Production wrapper
/// is `screen_state_cached`; tests call this directly with mocks.
fn lock_cache_check<F: FnOnce() -> SessionState>(
    cache: &mut Option<(Instant, SessionState)>,
    lookup: F,
    now: Instant,
    ttl: Duration,
) -> SessionState {
    if let Some((at, state)) = *cache {
        if now.duration_since(at) < ttl {
            return state;
        }
    }
    let state = lookup();
    *cache = Some((now, state));
    state
}

/// Pure: dedup gate over an injectable map + clock. Production wrapper is
/// `notify_throttle_should_fire`; tests call this directly.
fn throttle_check(
    map: &mut HashMap<NotifyKind, Instant>,
    kind: NotifyKind,
    now: Instant,
    window: Duration,
) -> bool {
    let allowed = match map.get(&kind) {
        Some(at) => now.duration_since(*at) >= window,
        None => true,
    };
    if allowed {
        map.insert(kind, now);
    }
    allowed
}

/// Production lock-state lookup (uncached). Cheap; called at most once per
/// second via `screen_state_cached` plus once per `evaluate_policy(false)`
/// re-check.
#[cfg(target_os = "macos")]
fn screen_state_now() -> SessionState {
    classify_session(cgsession::fetch_flags())
}

#[cfg(not(target_os = "macos"))]
fn screen_state_now() -> SessionState {
    SessionState::NoSession
}

#[cfg(target_os = "macos")]
fn screen_state_cached() -> SessionState {
    static CACHE: OnceLock<Mutex<Option<(Instant, SessionState)>>> = OnceLock::new();
    let mu = CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = mu.lock().unwrap();
    lock_cache_check(
        &mut guard,
        screen_state_now,
        Instant::now(),
        Duration::from_secs(1),
    )
}

#[cfg(target_os = "macos")]
fn notify_throttle_should_fire(kind: NotifyKind) -> bool {
    static THROTTLE: OnceLock<Mutex<HashMap<NotifyKind, Instant>>> = OnceLock::new();
    let mu = THROTTLE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = mu.lock().unwrap();
    throttle_check(
        &mut guard,
        kind,
        Instant::now(),
        Duration::from_secs(30),
    )
}

#[cfg(target_os = "macos")]
mod cgsession {
    use super::SessionFlags;
    use objc2_core_foundation::{CFBoolean, CFDictionary, CFRetained, CFString, CFType};
    use std::ffi::c_void;
    use std::ptr::NonNull;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> *mut CFDictionary;
    }

    /// Returns `None` if the dict is NULL (no GUI session). Otherwise reads
    /// the three flags we care about; missing/wrong-type keys yield `None`
    /// for that specific flag (treated as "no info" by `classify_session`).
    pub(super) fn fetch_flags() -> Option<SessionFlags> {
        // SAFETY: CGSessionCopyCurrentDictionary is a *Copy* CF function — it
        // returns either NULL or a +1 retained dict. CFRetained::from_raw
        // takes ownership and releases on drop.
        let dict: CFRetained<CFDictionary> = unsafe {
            let raw = CGSessionCopyCurrentDictionary();
            CFRetained::from_raw(NonNull::new(raw)?)
        };
        Some(SessionFlags {
            is_locked: read_bool(&dict, "CGSSessionScreenIsLocked"),
            is_on_console: read_bool(&dict, "kCGSSessionOnConsoleKey"),
            is_login_done: read_bool(&dict, "kCGSSessionLoginDoneKey"),
        })
    }

    /// Look up `key` in the dict; return `Some(bool)` only if it exists AND
    /// is a `CFBoolean`. Other types or absence yield `None`.
    fn read_bool(dict: &CFDictionary, key: &str) -> Option<bool> {
        let key_cf = CFString::from_str(key);
        let mut value_ptr: *const c_void = std::ptr::null();
        // SAFETY: key_cf is a valid CFString; value_ptr is a stack slot.
        let found = unsafe {
            dict.value_if_present(
                CFRetained::as_ptr(&key_cf).as_ptr() as *const c_void,
                &mut value_ptr,
            )
        };
        if !found || value_ptr.is_null() {
            return None;
        }
        // SAFETY: value_ptr points to a CF object owned by `dict`, valid
        // for the lifetime of this borrow. Reinterpret as &CFType so we can
        // dispatch through the type-checked downcast helper.
        let cf_type: &CFType = unsafe { &*(value_ptr as *const CFType) };
        // downcast_ref does the CFGetTypeID == CFBoolean::type_id() check.
        let bool_ref: &CFBoolean = cf_type.downcast_ref::<CFBoolean>()?;
        Some(bool_ref.value())
    }
}

#[cfg(target_os = "macos")]
fn notify_macos(title: &str, body: &str) {
    let safe: String = body
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .take(150)
        .collect();
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        safe, title
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status();
}

#[cfg(target_os = "macos")]
fn notify_touch_id_rejected(reason: &str) {
    if !notify_throttle_should_fire(NotifyKind::TouchIdRejected) {
        tracing::debug!("Touch ID rejection notification suppressed (throttled)");
        return;
    }
    notify_macos("vt", &format!("Touch ID rejected: {}", reason));
}

#[cfg(target_os = "macos")]
fn notify_locked_rejected(reason: &str) {
    if !notify_throttle_should_fire(NotifyKind::Locked) {
        tracing::debug!("Locked rejection notification suppressed (throttled)");
        return;
    }
    notify_macos(
        "vt: cannot authenticate",
        &format!("screen locked or session inactive — {}", reason),
    );
}

/// Classification of an `evaluatePolicy` outcome. Lifts `LAError` codes into
/// the categories the auth chain reasons about. Pure mapper +
/// `EvalOutcome::Success` is the typed return of `la::evaluate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalOutcome {
    /// Policy evaluation succeeded.
    Success,
    /// User actively declined (UserCancel, AuthenticationFailed, AppCancel,
    /// UserFallback, InvalidContext). Terminal — no fallback per commit
    /// `1d9d5d1`.
    Rejected,
    /// Biometry was attempted but is locked/unavailable/not-enrolled, or the
    /// device has no passcode. Caller should try the next factor in the chain
    /// (FIDO2 → password). This is the new fallback path the objc2 refactor
    /// unlocks — previously these were indistinguishable from Rejected.
    TryFallback,
    /// System couldn't display dialog (NotInteractive, SystemCancel, etc.).
    /// Caller should return `Unavailable`.
    NotInteractive,
}

/// Pure mapper from a raw `LAError` code → `EvalOutcome`. Unit-testable; no
/// FFI or system state. The `i32` matches the underlying ObjC `NSInteger`
/// representation we read off `NSError`.
#[cfg(target_os = "macos")]
pub fn classify_la_error(code: i32) -> EvalOutcome {
    use objc2_local_authentication::{
        kLAErrorAppCancel, kLAErrorAuthenticationFailed, kLAErrorBiometryDisconnected,
        kLAErrorBiometryLockout, kLAErrorBiometryNotAvailable, kLAErrorBiometryNotEnrolled,
        kLAErrorBiometryNotPaired, kLAErrorInvalidContext, kLAErrorNotInteractive,
        kLAErrorPasscodeNotSet, kLAErrorSystemCancel, kLAErrorUserCancel, kLAErrorUserFallback,
    };
    match code {
        // Terminal — user actively declined or app aborted.
        c if c == kLAErrorUserCancel
            || c == kLAErrorAuthenticationFailed
            || c == kLAErrorAppCancel
            || c == kLAErrorUserFallback
            || c == kLAErrorInvalidContext =>
        {
            EvalOutcome::Rejected
        }
        // Biometry path is dead — caller should try the next factor.
        // Includes BiometryNotPaired / BiometryDisconnected: hardware-availability
        // failures, semantically equivalent to BiometryNotAvailable.
        c if c == kLAErrorBiometryLockout
            || c == kLAErrorBiometryNotAvailable
            || c == kLAErrorBiometryNotEnrolled
            || c == kLAErrorPasscodeNotSet
            || c == kLAErrorBiometryNotPaired
            || c == kLAErrorBiometryDisconnected =>
        {
            EvalOutcome::TryFallback
        }
        // System interrupted us; return Unavailable upstream.
        c if c == kLAErrorSystemCancel || c == kLAErrorNotInteractive => {
            EvalOutcome::NotInteractive
        }
        // Unknown codes: be conservative and treat as Rejected (don't open
        // a fallback path on uncharted territory).
        _ => EvalOutcome::Rejected,
    }
}

/// Thin wrapper around `LAContext` via `objc2`. Exposes only the operations
/// the auth chain needs. Async `evaluatePolicy` is synchronized via a
/// bounded mpsc channel — the reply block runs on a private framework
/// queue, so blocking the caller does not deadlock against it.
#[cfg(target_os = "macos")]
mod la {
    use super::{classify_la_error, EvalOutcome};
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::mpsc;

    /// Which LA policy to evaluate. Maps to Apple's `LAPolicy` constants.
    #[derive(Debug, Clone, Copy)]
    pub(super) enum Policy {
        /// `LAPolicyDeviceOwnerAuthenticationWithBiometrics` — Touch ID only.
        WithBiometrics,
        /// `LAPolicyDeviceOwnerAuthentication` — biometrics or system passcode.
        DeviceOwner,
    }

    impl Policy {
        fn raw(self) -> LAPolicy {
            match self {
                Policy::WithBiometrics => LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                Policy::DeviceOwner => LAPolicy::DeviceOwnerAuthentication,
            }
        }
    }

    pub(super) fn can_evaluate(policy: Policy) -> bool {
        let ctx = unsafe { LAContext::new() };
        unsafe { ctx.canEvaluatePolicy_error(policy.raw()).is_ok() }
    }

    pub(super) fn evaluate(policy: Policy, reason: &str) -> EvalOutcome {
        let ctx = unsafe { LAContext::new() };
        let reason_ns = NSString::from_str(reason);
        let (tx, rx) = mpsc::sync_channel::<(bool, i32)>(1);
        let block = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let ok = success.as_bool();
            let code = if ok {
                0
            } else {
                // SAFETY: NSError pointer is non-null on failure; framework
                // owns the object for the duration of the reply block, which
                // outlives this read.
                unsafe { error.as_ref() }
                    .map(|e| e.code() as i32)
                    .unwrap_or(0)
            };
            // recv() may have hung up if the caller dropped early; ignore.
            let _ = tx.send((ok, code));
        });
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(policy.raw(), &reason_ns, &block);
        }
        let (ok, code) = match rx.recv() {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("LAContext reply channel closed unexpectedly");
                return EvalOutcome::Rejected;
            }
        };
        if ok {
            return EvalOutcome::Success;
        }
        let outcome = classify_la_error(code);
        if matches!(outcome, EvalOutcome::TryFallback) {
            tracing::info!(
                la_error_code = code,
                "biometry unavailable for evaluatePolicy; falling back to FIDO2/password"
            );
        }
        outcome
    }
}

/// Authentication chain.
///
/// **Pre-check**: if `CGSessionCopyCurrentDictionary` says the screen is
/// locked / off-console / login pending → `Unavailable(NotInteractive)`.
/// If the dict is NULL → `Unavailable(NoGuiSession)`. No FIDO2 fallback in
/// either case (physical-presence model).
///
/// **Touch ID** (when `canEvaluatePolicy` for biometrics succeeds): success
/// → `Biometric`. `EvalOutcome::Rejected` is terminal (per commit `1d9d5d1`)
/// after a session re-check disambiguates "user rejected" from "screen
/// locked mid-prompt". `EvalOutcome::TryFallback` (Lockout / NotAvailable /
/// NotEnrolled / PasscodeNotSet) **falls through to FIDO2 → password** —
/// new behavior unlocked by the objc2 refactor; previously these errors
/// were indistinguishable from a user rejection.
///
/// **FIDO2 → Password chain**: `FidoOutcome::Rejected` aborts; `Skip` falls
/// to system password (`DeviceOwnerAuthentication` policy).
#[cfg(target_os = "macos")]
pub fn authenticate(reason: &str) -> AuthOutcome {
    use crate::fido2::FidoOutcome;

    // Pre-check: screen lock state. Cached for 1s to bound CPU under spammy
    // callers (locked-screen + tight-loop client = naturally O(1)).
    match screen_state_cached() {
        SessionState::NotInteractive => {
            notify_locked_rejected(reason);
            return AuthOutcome::Unavailable(UnavailableReason::NotInteractive);
        }
        SessionState::NoSession => {
            return AuthOutcome::Unavailable(UnavailableReason::NoGuiSession);
        }
        SessionState::Interactive => {}
    }

    if la::can_evaluate(la::Policy::WithBiometrics) {
        match la::evaluate(la::Policy::WithBiometrics, reason) {
            EvalOutcome::Success => return AuthOutcome::Success(AuthMethod::Biometric),
            EvalOutcome::Rejected => {
                // Disambiguate: the screen could have locked between the cached
                // pre-check and now. Re-query uncached so a transient lock is
                // not misreported as a user rejection.
                match screen_state_now() {
                    SessionState::NotInteractive => {
                        notify_locked_rejected(reason);
                        return AuthOutcome::Unavailable(UnavailableReason::NotInteractive);
                    }
                    SessionState::NoSession => {
                        return AuthOutcome::Unavailable(UnavailableReason::NoGuiSession);
                    }
                    SessionState::Interactive => {}
                }
                notify_touch_id_rejected(reason);
                return AuthOutcome::Rejected;
            }
            EvalOutcome::NotInteractive => {
                return AuthOutcome::Unavailable(UnavailableReason::NotInteractive);
            }
            EvalOutcome::TryFallback => {
                // Biometry locked/unavailable: drop into FIDO2 → password.
            }
        }
    }

    // Re-check session state before entering the fallback chain. We may have
    // arrived here via two paths:
    //   1. `can_evaluate(WithBiometrics) == false` upfront (no LAContext call).
    //   2. `evaluate` returned `TryFallback` (Lockout / NotAvailable / etc.).
    // In either case, the screen could have locked since the cached pre-check
    // (1s TTL window). Don't prompt FIDO2 / password on a locked machine —
    // physical-presence model says no auth on a locked screen, even with a
    // YubiKey plugged in.
    match screen_state_now() {
        SessionState::NotInteractive => {
            notify_locked_rejected(reason);
            return AuthOutcome::Unavailable(UnavailableReason::NotInteractive);
        }
        SessionState::NoSession => {
            return AuthOutcome::Unavailable(UnavailableReason::NoGuiSession);
        }
        SessionState::Interactive => {}
    }

    match crate::fido2::authenticate(reason) {
        FidoOutcome::Success => return AuthOutcome::Success(AuthMethod::Fido2),
        FidoOutcome::Rejected => return AuthOutcome::Rejected,
        FidoOutcome::Skip => {}
    }

    match la::evaluate(la::Policy::DeviceOwner, reason) {
        EvalOutcome::Success => AuthOutcome::Success(AuthMethod::Password),
        EvalOutcome::NotInteractive => {
            AuthOutcome::Unavailable(UnavailableReason::NotInteractive)
        }
        EvalOutcome::Rejected | EvalOutcome::TryFallback => AuthOutcome::Rejected,
    }
}

#[cfg(not(target_os = "macos"))]
pub fn authenticate(_reason: &str) -> AuthOutcome {
    tracing::warn!("local authentication is not supported on this platform");
    AuthOutcome::Unavailable(UnavailableReason::NoGuiSession)
}

#[cfg(target_os = "macos")]
pub fn touch_id_authentication(reason: &str) -> bool {
    la::can_evaluate(la::Policy::WithBiometrics)
        && matches!(
            la::evaluate(la::Policy::WithBiometrics, reason),
            EvalOutcome::Success
        )
}

#[cfg(not(target_os = "macos"))]
pub fn touch_id_authentication(_reason: &str) -> bool {
    tracing::warn!("Touch ID authentication is not supported on this platform");
    false
}

pub fn local_authentication(reason: &str) -> bool {
    authenticate(reason).is_success()
}

pub fn derive_passphrase_secret(passcode: &[u8; 32], bin_path: Option<&str>) -> Result<[u8; 32]> {
    let passcode = BASE64_URL_SAFE_NO_PAD.encode(&passcode);
    let bin_path = bin_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| env::current_exe().unwrap().to_string_lossy().to_string());
    let derived_str = format!("{}:{}:{}", passcode, env::var("USER")?, bin_path,);
    let hash = Sha256::digest(&Sha256::digest(derived_str.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    Ok(key)
}

/// Build the initial KeychainStore (passcode + auth_token + encrypted
/// passphrase) and write it as a single keychain item. Used by `vt init`,
/// `vt secret import`, and `vt secret rotate-passcode` — all three either
/// create the store fresh (init/import) or replace it wholesale (rotate),
/// so this single call is the only write.
#[cfg(target_os = "macos")]
pub fn create_and_save_passcode_passphrase(
    real_passphrase: &[u8; 32],
    bin_path: Option<&str>,
) -> Result<()> {
    use crate::store::KeychainStore;

    let origin_auth_token = AesGcmCrypto::generate_key();
    let hash = Sha256::digest(&Sha256::digest(origin_auth_token));
    let mut auth_token = [0u8; 32];
    auth_token.copy_from_slice(&hash[..32]);

    let passcode = AesGcmCrypto::generate_key();
    let mut passcode_and_auth_token = Vec::with_capacity(passcode.len() + auth_token.len());
    passcode_and_auth_token.extend_from_slice(&passcode);
    passcode_and_auth_token.extend_from_slice(&auth_token);

    let passphrase_secret = derive_passphrase_secret(&passcode, bin_path)?;
    let aes = AesGcmCrypto::new(&passphrase_secret)?;
    let encrypted_passphrase = aes.encrypt(real_passphrase)?;

    // Preserve any pre-existing SSH keys / FIDO2 credentials on rotate.
    // The rotated passcode does not change `real_passphrase` (the master key
    // for SSH/FIDO2 ciphertexts), so those blobs remain decryptable.
    let mut store = KeychainStore::new(&passcode_and_auth_token, &encrypted_passphrase);
    if let Ok(existing) = KeychainStore::load() {
        store.encrypted_ssh_keys = existing.encrypted_ssh_keys;
        store.encrypted_fido2 = existing.encrypted_fido2;
    }
    store.save()?;
    tracing::info!("keychain store saved!");

    tracing::info!(
        "export VT_AUTH={};",
        BASE64_URL_SAFE_NO_PAD.encode(origin_auth_token)
    );
    Ok(())
}

/// Decrypt the master passphrase from the store and build the mac_cipher.
/// The passphrase cipher is supplied separately so callers can hold it
/// long-term (serve) without keeping the decrypted master key in memory.
#[cfg(target_os = "macos")]
pub fn load_mac_cipher(
    store: &crate::store::KeychainStore,
    passphrase_cipher: &AesGcmCrypto,
) -> Result<AesGcmCrypto> {
    let encrypted_passphrase = store.encrypted_passphrase_bytes()?;
    let decrypted_passphrase = passphrase_cipher.decrypt(&encrypted_passphrase)?;
    AesGcmCrypto::new(decrypted_passphrase.as_slice().try_into()?)
}

/// Derive `(auth_cipher, passphrase_cipher)` from the passcode bytes inside
/// an already-loaded store. Pure CPU work; does not touch the keychain.
#[cfg(target_os = "macos")]
pub fn derive_passcode_ciphers(
    store: &crate::store::KeychainStore,
) -> Result<(AesGcmCrypto, AesGcmCrypto)> {
    let passcode = store.passcode_and_auth_token_bytes()?;
    ensure!(
        passcode.len() == 64,
        "Passcode length is {}, expected 64",
        passcode.len()
    );
    let passcode_arr: [u8; 32] = passcode[..32].try_into()?;
    let auth_token: [u8; 32] = passcode[32..].try_into()?;

    let passphrase_secret = derive_passphrase_secret(&passcode_arr, None)?;
    let passphrase_cipher = AesGcmCrypto::new(&passphrase_secret)?;
    let auth_cipher = AesGcmCrypto::new(&auth_token)?;

    Ok((auth_cipher, passphrase_cipher))
}


pub fn decode_auth_cipher_from_b64(b64_token: &str) -> Result<[u8; 32]> {
    let token_bytes = BASE64_URL_SAFE_NO_PAD.decode(b64_token)?;
    let hash = Sha256::digest(&Sha256::digest(token_bytes));
    let mut token = [0u8; 32];
    token.copy_from_slice(&hash[..32]);
    Ok(token)
}

pub struct AesGcmCrypto {
    cipher: Aes256Gcm,
}

impl AesGcmCrypto {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        ensure!(key.len() == 32, "Invalid key length, expected 32 bytes");
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;
        Ok(Self { cipher })
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt data. The result contains nonce (first 12 bytes) and ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption error: {e}"))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data. Input should contain nonce (first 12 bytes) and ciphertext.
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        ensure!(encrypted_data.len() >= 12, "Data too short, missing nonce");
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption error: {e}"))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[test]
    fn test_base64_encode() {
        let text = b"to be encoded".to_vec();
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(&text), "dG8gYmUgZW5jb2RlZA");
    }

    #[traced_test]
    #[test]
    #[ignore]
    fn test_create_and_save_passcode_passphrase() {
        let real_passphrase = AesGcmCrypto::generate_key();
        let result = create_and_save_passcode_passphrase(&real_passphrase, None);
        assert!(result.is_ok())
    }

    #[test]
    fn test_generation() {
        let key1 = AesGcmCrypto::generate_key();
        let key2 = AesGcmCrypto::generate_key();
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2);

        // test nonce generation
        let nonce1 = AesGcmCrypto::generate_nonce();
        let nonce2 = AesGcmCrypto::generate_nonce();
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_encrypt_decrypt_basic() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Hello, World!";

        let encrypted = crypto.encrypt(plaintext).unwrap();
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = vec![0xAB; 1024 * 1024];
        let encrypted = crypto.encrypt(&plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Original message";
        let mut encrypted = crypto.encrypt(plaintext).unwrap();

        encrypted[15] ^= 0xFF;

        let result = crypto.decrypt(&encrypted);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Decryption error"));
    }

    #[test]
    fn test_multiple_encryptions_different_results() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Same message";
        let encrypted1 = crypto.encrypt(plaintext).unwrap();
        let encrypted2 = crypto.encrypt(plaintext).unwrap();
        assert_ne!(encrypted1, encrypted2);

        let decrypted1 = crypto.decrypt(&encrypted1).unwrap();
        let decrypted2 = crypto.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_unicode_text() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = "Hello, 世界! 🌍".as_bytes();
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(decrypted_str, "Hello, 世界! 🌍");
    }

    #[test]
    #[ignore]
    fn test_encrypt_body() {
        let body = r#"{"items":[]}"#.to_string();
        let store = crate::store::KeychainStore::load().expect("load keychain store");
        let (cipher, _) = derive_passcode_ciphers(&store).expect("derive auth cipher");
        let encrypted = cipher.encrypt(body.as_bytes()).expect("encrypt body");
        let decrypted = cipher.decrypt(&encrypted).expect("decrypt body");
        assert_eq!(decrypted, body.as_bytes());
    }

    #[test]
    #[ignore]
    fn test_biometric_authentication() {
        assert!(local_authentication(&"test biometric authentication"));
    }

    // ---- classify_session ------------------------------------------------

    #[test]
    fn classify_no_dict_is_no_session() {
        assert_eq!(classify_session(None), SessionState::NoSession);
    }

    #[test]
    fn classify_locked_is_not_interactive() {
        let f = SessionFlags {
            is_locked: Some(true),
            is_on_console: Some(true),
            is_login_done: Some(true),
        };
        assert_eq!(classify_session(Some(f)), SessionState::NotInteractive);
    }

    #[test]
    fn classify_off_console_is_not_interactive() {
        let f = SessionFlags {
            is_locked: Some(false),
            is_on_console: Some(false),
            is_login_done: Some(true),
        };
        assert_eq!(classify_session(Some(f)), SessionState::NotInteractive);
    }

    #[test]
    fn classify_login_pending_is_not_interactive() {
        let f = SessionFlags {
            is_locked: Some(false),
            is_on_console: Some(true),
            is_login_done: Some(false),
        };
        assert_eq!(classify_session(Some(f)), SessionState::NotInteractive);
    }

    #[test]
    fn classify_all_clear_is_interactive() {
        let f = SessionFlags {
            is_locked: Some(false),
            is_on_console: Some(true),
            is_login_done: Some(true),
        };
        assert_eq!(classify_session(Some(f)), SessionState::Interactive);
    }

    #[test]
    fn classify_missing_keys_default_interactive() {
        // None for every flag = "no info" → not blocking. Defaults to Interactive
        // so an Apple key rename doesn't fail-close.
        assert_eq!(
            classify_session(Some(SessionFlags::default())),
            SessionState::Interactive
        );
    }

    #[test]
    fn classify_missing_locked_only_is_interactive() {
        let f = SessionFlags {
            is_locked: None,
            is_on_console: Some(true),
            is_login_done: Some(true),
        };
        assert_eq!(classify_session(Some(f)), SessionState::Interactive);
    }

    // ---- lock_cache_check ------------------------------------------------

    #[test]
    fn lock_cache_first_call_calls_lookup() {
        let mut cache = None;
        let mut calls = 0;
        let now = Instant::now();
        let state = lock_cache_check(
            &mut cache,
            || {
                calls += 1;
                SessionState::Interactive
            },
            now,
            Duration::from_secs(1),
        );
        assert_eq!(state, SessionState::Interactive);
        assert_eq!(calls, 1);
        assert!(cache.is_some());
    }

    #[test]
    fn lock_cache_within_ttl_uses_cached() {
        let mut cache = None;
        let now = Instant::now();
        lock_cache_check(
            &mut cache,
            || SessionState::NotInteractive,
            now,
            Duration::from_secs(1),
        );
        let mut calls = 0;
        let state = lock_cache_check(
            &mut cache,
            || {
                calls += 1;
                SessionState::Interactive
            },
            now + Duration::from_millis(500),
            Duration::from_secs(1),
        );
        assert_eq!(state, SessionState::NotInteractive);
        assert_eq!(calls, 0, "lookup must not be called within TTL");
    }

    #[test]
    fn lock_cache_after_ttl_refreshes() {
        let mut cache = None;
        let now = Instant::now();
        lock_cache_check(
            &mut cache,
            || SessionState::NotInteractive,
            now,
            Duration::from_secs(1),
        );
        let state = lock_cache_check(
            &mut cache,
            || SessionState::Interactive,
            now + Duration::from_secs(2),
            Duration::from_secs(1),
        );
        assert_eq!(state, SessionState::Interactive);
    }

    // ---- throttle_check --------------------------------------------------

    #[test]
    fn throttle_first_call_fires() {
        let mut map = HashMap::new();
        let now = Instant::now();
        assert!(throttle_check(
            &mut map,
            NotifyKind::Locked,
            now,
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn throttle_dedups_within_window() {
        let mut map = HashMap::new();
        let now = Instant::now();
        assert!(throttle_check(
            &mut map,
            NotifyKind::Locked,
            now,
            Duration::from_secs(30)
        ));
        assert!(!throttle_check(
            &mut map,
            NotifyKind::Locked,
            now + Duration::from_secs(15),
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn throttle_re_fires_after_window() {
        let mut map = HashMap::new();
        let now = Instant::now();
        throttle_check(
            &mut map,
            NotifyKind::Locked,
            now,
            Duration::from_secs(30),
        );
        // After the window, a new fire is allowed.
        assert!(throttle_check(
            &mut map,
            NotifyKind::Locked,
            now + Duration::from_secs(31),
            Duration::from_secs(30)
        ));
        // The successful re-fire must reset the stored timestamp; another
        // immediate call should be suppressed again.
        assert!(!throttle_check(
            &mut map,
            NotifyKind::Locked,
            now + Duration::from_secs(32),
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn throttle_separate_kinds_independent() {
        let mut map = HashMap::new();
        let now = Instant::now();
        assert!(throttle_check(
            &mut map,
            NotifyKind::Locked,
            now,
            Duration::from_secs(30)
        ));
        // Different kind, same instant — should still fire.
        assert!(throttle_check(
            &mut map,
            NotifyKind::TouchIdRejected,
            now,
            Duration::from_secs(30)
        ));
    }

    // ---- AuthOutcome -----------------------------------------------------

    #[test]
    fn auth_outcome_is_success() {
        assert!(AuthOutcome::Success(AuthMethod::Biometric).is_success());
        assert!(AuthOutcome::Success(AuthMethod::Fido2).is_success());
        assert!(AuthOutcome::Success(AuthMethod::Password).is_success());
        assert!(!AuthOutcome::Rejected.is_success());
        assert!(!AuthOutcome::Unavailable(UnavailableReason::NotInteractive).is_success());
        assert!(!AuthOutcome::Unavailable(UnavailableReason::NoGuiSession).is_success());
    }

    // ---- classify_la_error -----------------------------------------------

    #[test]
    fn classify_la_user_cancel_is_rejected() {
        // -2: user pressed Cancel in the Touch ID dialog.
        assert_eq!(classify_la_error(-2), EvalOutcome::Rejected);
    }

    #[test]
    fn classify_la_authentication_failed_is_rejected() {
        // -1: 3 wrong fingerprints in a row, before lockout fires.
        assert_eq!(classify_la_error(-1), EvalOutcome::Rejected);
    }

    #[test]
    fn classify_la_user_fallback_is_rejected() {
        // -3: user tapped "Use Password" — with WithBiometrics policy this
        // surfaces as rejection rather than success on a different factor.
        assert_eq!(classify_la_error(-3), EvalOutcome::Rejected);
    }

    #[test]
    fn classify_la_app_cancel_is_rejected() {
        // -9: process invalidate()'d the context.
        assert_eq!(classify_la_error(-9), EvalOutcome::Rejected);
    }

    #[test]
    fn classify_la_invalid_context_is_rejected() {
        // -10: programmer error using a stale context.
        assert_eq!(classify_la_error(-10), EvalOutcome::Rejected);
    }

    #[test]
    fn classify_la_biometry_lockout_is_try_fallback() {
        // -8: 3 failures triggered system lockout. THIS is the case the
        // objc2 refactor unlocks — previously indistinguishable from
        // AuthenticationFailed and treated as terminal Rejected.
        assert_eq!(classify_la_error(-8), EvalOutcome::TryFallback);
    }

    #[test]
    fn classify_la_biometry_not_available_is_try_fallback() {
        // -6: hardware not present.
        assert_eq!(classify_la_error(-6), EvalOutcome::TryFallback);
    }

    #[test]
    fn classify_la_biometry_not_enrolled_is_try_fallback() {
        // -7: hardware present, no fingers enrolled.
        assert_eq!(classify_la_error(-7), EvalOutcome::TryFallback);
    }

    #[test]
    fn classify_la_passcode_not_set_is_try_fallback() {
        // -5: no system passcode → biometric path can't run.
        assert_eq!(classify_la_error(-5), EvalOutcome::TryFallback);
    }

    #[test]
    fn classify_la_system_cancel_is_not_interactive() {
        // -4: framework canceled (e.g. another app stole focus).
        assert_eq!(classify_la_error(-4), EvalOutcome::NotInteractive);
    }

    #[test]
    fn classify_la_not_interactive_is_not_interactive() {
        // -1004: defense in depth — PR1 lock pre-check normally catches this,
        // but if the screen locks during the prompt we land here.
        assert_eq!(classify_la_error(-1004), EvalOutcome::NotInteractive);
    }

    #[test]
    fn classify_la_biometry_not_paired_is_try_fallback() {
        // -12: hardware paired state lost. Same family as NotAvailable —
        // biometry can't run, but other factors (FIDO2/password) might.
        assert_eq!(classify_la_error(-12), EvalOutcome::TryFallback);
    }

    #[test]
    fn classify_la_biometry_disconnected_is_try_fallback() {
        // -13: sensor temporarily disconnected (e.g. external Touch ID device).
        // Treat as TryFallback so the user can still auth via FIDO2 / password.
        assert_eq!(classify_la_error(-13), EvalOutcome::TryFallback);
    }

    #[test]
    fn classify_la_unknown_codes_are_rejected() {
        // Be conservative on uncharted codes — don't silently open a fallback
        // path on something we haven't reasoned about. -11 (WatchNotAvailable)
        // and -14 (InvalidDimensions) fall here; if a future Apple OS adds
        // new codes, behavior is fail-closed until they're classified.
        assert_eq!(classify_la_error(-11), EvalOutcome::Rejected);
        assert_eq!(classify_la_error(-14), EvalOutcome::Rejected);
        assert_eq!(classify_la_error(-9999), EvalOutcome::Rejected);
        assert_eq!(classify_la_error(0), EvalOutcome::Rejected);
        assert_eq!(classify_la_error(42), EvalOutcome::Rejected);
    }
}
