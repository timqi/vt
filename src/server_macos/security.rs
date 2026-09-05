use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::core::crypto::{derive_passphrase_secret, derive_passphrase_secret_v2, AesGcmCrypto};
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
pub(crate) fn screen_state_now() -> SessionState {
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
    throttle_check(&mut guard, kind, Instant::now(), Duration::from_secs(30))
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

/// When the running binary lives inside an `.app` bundle
/// (`…/Contents/MacOS/<exe>`), return the path of the bundled `VTApp` shell
/// binary, which doubles as the `UNUserNotificationCenter` helper
/// (docs/app-bundle.md §3). The notification then carries VT's own bundle
/// identity/icon instead of Script Editor's. The shell is named `VTApp`
/// because the default APFS volume is case-insensitive — `VT` would collide
/// with the `vt` CLI beside it.
fn bundle_notify_helper() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let macos_dir = exe.parent()?;
    if macos_dir.file_name()? != "MacOS" {
        return None;
    }
    let contents = macos_dir.parent()?;
    if contents.file_name()? != "Contents"
        || contents.parent()?.extension().is_none_or(|e| e != "app")
    {
        return None;
    }
    let helper = macos_dir.join("VTApp");
    (helper.is_file() && helper != exe).then_some(helper)
}

fn notify_macos(title: &str, body: &str) {
    // Sanitize BOTH fields identically before they leave the agent — the
    // same filter guards the AppleScript interpolation of the fallback and
    // the argv of the helper (control chars could still garble the native
    // notification UI). All current callers pass static titles, but
    // sanitizing the title too removes a latent injection if a future
    // caller ever passes dynamic text.
    let sanitize = |s: &str, max: usize| -> String {
        s.chars()
            .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
            .take(max)
            .collect()
    };
    let safe = sanitize(body, 150);
    let safe_title = sanitize(title, 100);

    // Fire-and-forget on a reaper thread: notifying must never add latency
    // to (or fail) the operation that triggered it, and the helper's
    // first-use permission dialog has unbounded latency. The thread waits on
    // the child so no zombie is left; the ≥30 s per-kind throttle bounds
    // thread churn.
    std::thread::spawn(move || {
        if let Some(helper) = bundle_notify_helper() {
            // Argv only — no shell, no AppleScript interpolation.
            let ok = std::process::Command::new(&helper)
                .args(["notify", "--title", &safe_title, "--body", &safe])
                .status()
                .is_ok_and(|s| s.success());
            if ok {
                return;
            }
            tracing::debug!("bundled notify helper failed, falling back to osascript");
        }
        let script = format!(
            r#"display notification "{}" with title "{}""#,
            safe, safe_title
        );
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .status();
    });
}

/// The `reason` we get is the full Touch ID prompt body — now multi-line
/// (`decrypt 5 secrets on WHO\nop: inject\nfile: …\n…`). Notifications only
/// have room for a couple of lines, and the user just saw the whole prompt
/// before rejecting, so the header alone is what's useful here.
fn first_line(s: &str) -> &str {
    s.split('\n').next().unwrap_or(s)
}

/// Cache-hit transparency notification (docs/app-bundle.md §3). Called by
/// the agent only AFTER `permit.commit()` returned — never while a permit
/// (and thus the security read gate) is live — and is itself fire-and-forget
/// via `notify_macos`'s reaper thread. Throttled per kind so a burst
/// (multi-sign `git push`) notifies once per 30 s window.
pub(super) fn notify_cache_hit(
    operation: &str,
    scope_display: &str,
    remaining: Option<std::time::Duration>,
) {
    if !notify_throttle_should_fire(NotifyKind::CacheHit) {
        tracing::debug!("cache-hit notification suppressed (throttled)");
        return;
    }
    let left = match remaining {
        Some(d) => {
            let secs = d.as_secs();
            format!(" · {}m{:02}s left", secs / 60, secs % 60)
        }
        None => String::new(),
    };
    let body = format!("{operation} · {scope_display}{left}");
    notify_macos("VT: cached grant used (no Touch ID)", &body);
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
        EvalOutcome::NotInteractive => AuthOutcome::Unavailable(UnavailableReason::NotInteractive),
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
pub fn create_and_save_passcode_passphrase(real_passphrase: &[u8; 32]) -> Result<()> {
    use super::store::KeychainStore;

    let origin_auth_token = AesGcmCrypto::generate_key();
    let hash = Sha256::digest(&Sha256::digest(origin_auth_token));
    let mut auth_token = [0u8; 32];
    auth_token.copy_from_slice(&hash[..32]);

    let passcode = AesGcmCrypto::generate_key();
    let mut passcode_and_auth_token = Vec::with_capacity(passcode.len() + auth_token.len());
    passcode_and_auth_token.extend_from_slice(&passcode);
    passcode_and_auth_token.extend_from_slice(&auth_token);

    // New stores are always wrap v2 (KeychainStore::new sets wrap_v).
    let passphrase_secret = derive_passphrase_secret_v2(&passcode)?;
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
fn load_mac_key(
    store: &super::store::KeychainStore,
    passphrase_cipher: &AesGcmCrypto,
) -> Result<Zeroizing<[u8; 32]>> {
    let encrypted_passphrase = store.encrypted_passphrase_bytes()?;
    let decrypted_passphrase = Zeroizing::new(passphrase_cipher.decrypt(&encrypted_passphrase)?);
    let mut key = Zeroizing::new([0u8; 32]);
    let slice: &[u8; 32] = decrypted_passphrase.as_slice().try_into()?;
    key.copy_from_slice(slice);
    Ok(key)
}

/// Preflight the encrypted master key without constructing a long-lived cipher
/// or retaining raw key material across a human authorization prompt.
pub(crate) fn validate_mac_key_material(
    store: &super::store::KeychainStore,
    passphrase_cipher: &AesGcmCrypto,
) -> Result<()> {
    drop(load_mac_key(store, passphrase_cipher)?);
    Ok(())
}

pub fn load_mac_cipher(
    store: &super::store::KeychainStore,
    passphrase_cipher: &AesGcmCrypto,
) -> Result<(AesGcmCrypto, Zeroizing<[u8; 32]>)> {
    let key = load_mac_key(store, passphrase_cipher)?;
    let cipher = AesGcmCrypto::new(&key)?;
    Ok((cipher, key))
}

/// Derive `(auth_cipher, passphrase_cipher)` from the passcode bytes inside
/// an already-loaded store, selecting the wrap derivation by `store.wrap_v`.
/// Pure CPU work; does not touch the keychain.
pub fn derive_passcode_ciphers(
    store: &super::store::KeychainStore,
) -> Result<(AesGcmCrypto, AesGcmCrypto)> {
    let (passcode_arr, auth_token) = split_passcode(store)?;
    let passphrase_secret = wrap_secret_for(store.wrap_v, &passcode_arr, None)?;
    let passphrase_cipher = AesGcmCrypto::new(&passphrase_secret)?;
    let auth_cipher = AesGcmCrypto::new(&auth_token)?;

    Ok((auth_cipher, passphrase_cipher))
}

fn split_passcode(store: &super::store::KeychainStore) -> Result<([u8; 32], [u8; 32])> {
    let passcode = store.passcode_and_auth_token_bytes()?;
    ensure!(
        passcode.len() == 64,
        "Passcode length is {}, expected 64",
        passcode.len()
    );
    Ok((passcode[..32].try_into()?, passcode[32..].try_into()?))
}

/// Wrap-key derivation for a given `wrap_v`. `bin_path` only applies to v1
/// (`None` → `current_exe()`); unknown versions error out so a store written
/// by a newer vt fails loudly instead of mis-deriving.
fn wrap_secret_for(wrap_v: u32, passcode: &[u8; 32], bin_path: Option<&str>) -> Result<[u8; 32]> {
    use super::store::{WRAP_V1, WRAP_V2};
    match wrap_v {
        WRAP_V1 => derive_passphrase_secret(passcode, bin_path),
        WRAP_V2 => derive_passphrase_secret_v2(passcode),
        other => anyhow::bail!(
            "rusty.vault.store has wrap version {other}, this binary supports up to {WRAP_V2} — upgrade vt"
        ),
    }
}

/// Rewrap `encrypted_passphrase` in place to `target_wrap` (v2 label, or v1
/// bound to THIS binary's path for `--to-v1`). Pure over the store value —
/// callers wrap it in `KeychainStore::modify` for the cross-process flock.
/// Tries, in order: the store's recorded wrap, then (for v1 stores) the
/// explicit `old_bin_path` string — the old binary need not exist, only its
/// path enters the derivation. Preserves `passcode_and_auth_token` (VT_AUTH),
/// `encrypted_ssh_keys`, and `encrypted_fido2` untouched.
pub(super) fn rewrap_passphrase(
    store: &mut super::store::KeychainStore,
    old_bin_path: Option<&str>,
    target_wrap: u32,
) -> Result<()> {
    use super::store::WRAP_V1;
    let (passcode_arr, _) = split_passcode(store)?;
    let encrypted = store.encrypted_passphrase_bytes()?;

    let mut candidates: Vec<(u32, Option<String>)> = vec![(store.wrap_v, None)];
    if store.wrap_v == WRAP_V1 {
        if let Some(p) = old_bin_path {
            candidates.push((WRAP_V1, Some(p.to_string())));
        }
    }

    let mut passphrase: Option<Zeroizing<Vec<u8>>> = None;
    for (wrap_v, path) in &candidates {
        let secret = wrap_secret_for(*wrap_v, &passcode_arr, path.as_deref())?;
        if let Ok(plain) = AesGcmCrypto::new(&secret)?.decrypt(&encrypted) {
            passphrase = Some(Zeroizing::new(plain));
            break;
        }
    }
    let passphrase = passphrase.ok_or_else(|| {
        anyhow::anyhow!(
            "could not unwrap the master passphrase with the store's recorded wrap \
             (v{}){} — pass --old-bin-path <absolute path of the binary that wrote the store>",
            store.wrap_v,
            if old_bin_path.is_some() {
                " or the given --old-bin-path"
            } else {
                ""
            }
        )
    })?;

    let new_secret = wrap_secret_for(target_wrap, &passcode_arr, None)?;
    let rewrapped = AesGcmCrypto::new(&new_secret)?.encrypt(&passphrase)?;
    store.set_encrypted_passphrase(&rewrapped, target_wrap);
    Ok(())
}

/// Transparent wrap v1→v2 upgrade, run at agent startup (docs/app-bundle.md
/// §2). Under the store flock: re-checks `wrap_v == 1`, rewraps only
/// `encrypted_passphrase`, never touches passcode/auth_token/SSH/FIDO2
/// blobs. Returns Ok(false) if the store is absent or already v2; unwrap
/// failure (binary already moved before upgrading) is left to
/// `vt secret rebind` and reported as an error for the caller to log.
pub fn upgrade_wrap_v2_if_needed() -> Result<bool> {
    use super::store::{KeychainStore, WRAP_V1, WRAP_V2};
    if !matches!(KeychainStore::load(), Ok(s) if s.wrap_v == WRAP_V1) {
        return Ok(false);
    }
    let mut upgraded = false;
    KeychainStore::modify(|store| {
        // Re-check under the lock: another process may have upgraded first.
        if store.wrap_v != WRAP_V1 {
            return Ok(());
        }
        rewrap_passphrase(store, None, WRAP_V2)?;
        upgraded = true;
        Ok(())
    })?;
    Ok(upgraded)
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
        let result = create_and_save_passcode_passphrase(&real_passphrase);
        assert!(result.is_ok())
    }

    /// Pure rewrap round-trip over an in-memory store: v1 (explicit old
    /// path) -> v2 -> v1, asserting the master passphrase survives and the
    /// non-passphrase fields are byte-for-byte untouched. No keychain access.
    #[test]
    fn test_rewrap_round_trip_preserves_store() {
        use super::super::store::{KeychainStore, WRAP_V1, WRAP_V2};
        use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

        let passcode = AesGcmCrypto::generate_key();
        let auth_token = AesGcmCrypto::generate_key();
        let mut passcode_and_auth_token = Vec::new();
        passcode_and_auth_token.extend_from_slice(&passcode);
        passcode_and_auth_token.extend_from_slice(&auth_token);

        let master = AesGcmCrypto::generate_key();
        let old_path = "/old/install/location/vt";
        let v1_secret = derive_passphrase_secret(&passcode, Some(old_path)).unwrap();
        let v1_wrapped = AesGcmCrypto::new(&v1_secret)
            .unwrap()
            .encrypt(&master)
            .unwrap();

        let mut store = KeychainStore::new(&passcode_and_auth_token, &v1_wrapped);
        store.set_encrypted_passphrase(&v1_wrapped, WRAP_V1);
        store.set_encrypted_ssh_keys(b"ssh-blob");
        store.set_encrypted_fido2(b"fido2-blob");
        let tokens_before = store.passcode_and_auth_token.clone();

        // v1 (old path) -> v2: recorded-wrap candidate fails (current_exe !=
        // old_path), the explicit old path candidate succeeds.
        rewrap_passphrase(&mut store, Some(old_path), WRAP_V2).unwrap();
        assert_eq!(store.wrap_v, WRAP_V2);
        let v2_secret = derive_passphrase_secret_v2(&passcode).unwrap();
        let unwrapped = AesGcmCrypto::new(&v2_secret)
            .unwrap()
            .decrypt(&store.encrypted_passphrase_bytes().unwrap())
            .unwrap();
        assert_eq!(unwrapped, master);

        // v2 -> v1 (current_exe binding), the --to-v1 escape hatch.
        rewrap_passphrase(&mut store, None, WRAP_V1).unwrap();
        assert_eq!(store.wrap_v, WRAP_V1);
        let v1_now = derive_passphrase_secret(&passcode, None).unwrap();
        let unwrapped = AesGcmCrypto::new(&v1_now)
            .unwrap()
            .decrypt(&store.encrypted_passphrase_bytes().unwrap())
            .unwrap();
        assert_eq!(unwrapped, master);

        // Everything except the passphrase wrap is untouched.
        assert_eq!(store.passcode_and_auth_token, tokens_before);
        assert_eq!(
            store.encrypted_ssh_keys.as_deref(),
            Some(BASE64_URL_SAFE_NO_PAD.encode(b"ssh-blob").as_str())
        );
        assert_eq!(
            store.encrypted_fido2.as_deref(),
            Some(BASE64_URL_SAFE_NO_PAD.encode(b"fido2-blob").as_str())
        );
    }

    /// A wrap version this binary does not know must fail loudly, and a
    /// failed unwrap must name the remedy without leaking key material.
    #[test]
    fn test_rewrap_unknown_and_wrong_path_errors() {
        use super::super::store::{KeychainStore, WRAP_V1, WRAP_V2};

        let passcode = AesGcmCrypto::generate_key();
        let mut tokens = Vec::new();
        tokens.extend_from_slice(&passcode);
        tokens.extend_from_slice(&AesGcmCrypto::generate_key());

        let master = AesGcmCrypto::generate_key();
        let v1_secret = derive_passphrase_secret(&passcode, Some("/gone/vt")).unwrap();
        let wrapped = AesGcmCrypto::new(&v1_secret)
            .unwrap()
            .encrypt(&master)
            .unwrap();
        let mut store = KeychainStore::new(&tokens, &wrapped);
        store.set_encrypted_passphrase(&wrapped, WRAP_V1);

        // No candidate matches: recorded wrap derives from current_exe, and
        // the supplied old path is wrong.
        let err = rewrap_passphrase(&mut store, Some("/also/wrong/vt"), WRAP_V2).unwrap_err();
        assert!(err.to_string().contains("--old-bin-path"), "{err}");
        assert_eq!(
            store.wrap_v, WRAP_V1,
            "failed rewrap must not mutate the store"
        );

        store.wrap_v = 99;
        let err = rewrap_passphrase(&mut store, None, WRAP_V2).unwrap_err();
        assert!(err.to_string().contains("wrap version 99"), "{err}");
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
