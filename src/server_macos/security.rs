use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::core::crypto::{derive_passphrase_secret, AesGcmCrypto};
use crate::core::session::{
    classify_session, lock_cache_check, throttle_check, AuthMethod, AuthOutcome, NotifyKind,
    SessionState, UnavailableReason,
};

pub fn set_keychain(name: &str, value: &[u8]) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    let service = "rusty.vault.".to_string() + name;
    set_generic_password(&service, &"prod".to_string(), value)?;
    Ok(())
}

pub fn get_keychain(name: &str) -> Result<Vec<u8>> {
    use security_framework::passwords::get_generic_password;
    let service = "rusty.vault.".to_string() + name;
    get_generic_password(&service, &"prod".to_string())
        .map_err(|e| anyhow::anyhow!("Failed to get keychain {}: {}", name, e))
}

/// Production lock-state lookup (uncached). Cheap; called at most once per
/// second via `screen_state_cached` plus once per `evaluate_policy(false)`
/// re-check.
fn screen_state_now() -> SessionState {
    classify_session(cgsession::fetch_flags())
}

/// True when the GUI session can present an auth dialog right now (on
/// console, login done, screen unlocked). Used by the SSH agent's cache
/// watcher to flush standing grants when the screen locks. Uncached — the
/// watcher polls on a multi-second tick, so no TTL cache is needed.
pub fn session_interactive_now() -> bool {
    matches!(screen_state_now(), SessionState::Interactive)
}

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

mod cgsession {
    use crate::core::session::SessionFlags;
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

fn notify_macos(title: &str, body: &str) {
    // Sanitize BOTH fields identically before interpolating into AppleScript.
    // All current callers pass static titles, but sanitizing the title too
    // removes a latent injection if a future caller ever passes dynamic text.
    let sanitize = |s: &str, max: usize| -> String {
        s.chars()
            .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
            .take(max)
            .collect()
    };
    let safe = sanitize(body, 150);
    let safe_title = sanitize(title, 100);
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        safe, safe_title
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status();
}

/// The `reason` we get is the full Touch ID prompt body — now multi-line
/// (`decrypt 5 secrets on WHO\nop: inject\nfile: …\n…`). Notifications only
/// have room for a couple of lines, and the user just saw the whole prompt
/// before rejecting, so the header alone is what's useful here.
fn first_line(s: &str) -> &str {
    s.split('\n').next().unwrap_or(s)
}

fn notify_touch_id_rejected(reason: &str) {
    if !notify_throttle_should_fire(NotifyKind::TouchIdRejected) {
        tracing::debug!("Touch ID rejection notification suppressed (throttled)");
        return;
    }
    notify_macos("vt", &format!("Touch ID rejected: {}", first_line(reason)));
}

fn notify_locked_rejected(reason: &str) {
    if !notify_throttle_should_fire(NotifyKind::Locked) {
        tracing::debug!("Locked rejection notification suppressed (throttled)");
        return;
    }
    notify_macos(
        "vt: cannot authenticate",
        &format!("screen locked or session inactive — {}", first_line(reason)),
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
pub fn authenticate(reason: &str) -> AuthOutcome {
    use super::fido2::FidoOutcome;

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

    match super::fido2::authenticate(reason) {
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

pub fn touch_id_authentication(reason: &str) -> bool {
    la::can_evaluate(la::Policy::WithBiometrics)
        && matches!(
            la::evaluate(la::Policy::WithBiometrics, reason),
            EvalOutcome::Success
        )
}

pub fn local_authentication(reason: &str) -> bool {
    authenticate(reason).is_success()
}

/// Build the initial KeychainStore (passcode + auth_token + encrypted
/// passphrase) and write it as a single keychain item. Used by `vt init`,
/// `vt secret import`, and `vt secret rotate-passcode` — all three either
/// create the store fresh (init/import) or replace it wholesale (rotate),
/// so this single call is the only write.
pub fn create_and_save_passcode_passphrase(
    real_passphrase: &[u8; 32],
    bin_path: Option<&str>,
) -> Result<()> {
    use super::store::KeychainStore;

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
///
/// Returns both the cipher (for legacy AES-GCM ops) and the raw 32-byte master
/// key (needed as HKDF IKM for v2 envelope DEK derivation). The raw key is
/// returned in a `Zeroizing` wrapper so it is wiped from memory on drop;
/// callers should drop it as soon as derivation is complete.
pub fn load_mac_cipher(
    store: &super::store::KeychainStore,
    passphrase_cipher: &AesGcmCrypto,
) -> Result<(AesGcmCrypto, Zeroizing<[u8; 32]>)> {
    let encrypted_passphrase = store.encrypted_passphrase_bytes()?;
    let decrypted_passphrase =
        Zeroizing::new(passphrase_cipher.decrypt(&encrypted_passphrase)?);
    let mut key = Zeroizing::new([0u8; 32]);
    let slice: &[u8; 32] = decrypted_passphrase.as_slice().try_into()?;
    key.copy_from_slice(slice);
    let cipher = AesGcmCrypto::new(&key)?;
    Ok((cipher, key))
}

/// Derive `(auth_cipher, passphrase_cipher)` from the passcode bytes inside
/// an already-loaded store. Pure CPU work; does not touch the keychain.
pub fn derive_passcode_ciphers(
    store: &super::store::KeychainStore,
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


#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    #[ignore]
    fn test_create_and_save_passcode_passphrase() {
        let real_passphrase = AesGcmCrypto::generate_key();
        let result = create_and_save_passcode_passphrase(&real_passphrase, None);
        assert!(result.is_ok())
    }

    #[test]
    #[ignore]
    fn test_encrypt_body() {
        let body = r#"{"items":[]}"#.to_string();
        let store = super::super::store::KeychainStore::load().expect("load keychain store");
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
