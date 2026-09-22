use anyhow::{ensure, Result};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::core::crypto::{derive_passphrase_secret_v2, AesGcmCrypto};
use crate::core::session::{
    classify_session, lock_cache_check, throttle_check, AuthMethod, AuthOutcome, NotifyKind,
    SessionState, UnavailableReason,
};

pub fn set_keychain(name: &str, value: &[u8]) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    let service = "rusty.vault.".to_string() + name;
    set_generic_password(&service, "prod", value)?;
    Ok(())
}

pub fn get_keychain(name: &str) -> Result<Vec<u8>> {
    use security_framework::passwords::get_generic_password;
    let service = "rusty.vault.".to_string() + name;
    get_generic_password(&service, "prod")
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
    /// for that specific flag (`classify_session` denies on a missing
    /// console/login flag; the lock key is absent while unlocked).
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
            // Apple spells this one `kCGSession…`, not `kCGSSession…`.
            is_login_done: read_bool(&dict, "kCGSessionLoginDoneKey"),
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
/// (docs/app-bundle.md#notifications). The notification then carries VT's own bundle
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

/// Bundled `VTApp notify` is the only transport: a bare `vt` outside the
/// bundle logs and drops the notification (no osascript, no second path).
fn notify_macos(title: &str, body: &str) {
    let Some(helper) = bundle_notify_helper() else {
        tracing::debug!("no bundled notify helper; notification dropped");
        return;
    };
    // Control chars could garble the native notification UI; both fields
    // are filtered so a future dynamic title gets the same treatment.
    let sanitize = |s: &str, max: usize| -> String {
        s.chars().filter(|c| !c.is_control()).take(max).collect()
    };
    let safe = sanitize(body, 150);
    let safe_title = sanitize(title, 100);

    // Fire-and-forget on a reaper thread: notifying must never add latency
    // to (or fail) the operation that triggered it, and the helper's
    // first-use permission dialog has unbounded latency. The thread waits on
    // the child so no zombie is left; the ≥30 s per-kind throttle bounds
    // thread churn.
    std::thread::spawn(move || {
        // Argv only — no shell.
        let ok = std::process::Command::new(&helper)
            .args(["notify", "--title", &safe_title, "--body", &safe])
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            tracing::debug!("bundled notify helper failed");
        }
    });
}

/// The `reason` we get is the full Touch ID prompt body — now multi-line
/// (`decrypt 5 secrets on WHO\nop: inject\nfile: …\n…`). Notifications only
/// have room for a couple of lines, and the user just saw the whole prompt
/// before rejecting, so the header alone is what's useful here.
fn first_line(s: &str) -> &str {
    s.split('\n').next().unwrap_or(s)
}

/// Cache-hit transparency notification (docs/app-bundle.md#notifications). Called by
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
    /// UserFallback, InvalidContext). Terminal — never falls back to the
    /// password.
    Rejected,
    /// Biometry was attempted but is locked/unavailable/not-enrolled, or the
    /// device has no passcode. Caller should fall back to the system password.
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
                "biometry unavailable for evaluatePolicy; falling back to password"
            );
        }
        outcome
    }
}

/// Authentication chain.
///
/// **Pre-check**: if `CGSessionCopyCurrentDictionary` says the screen is
/// locked / off-console / login pending → `Unavailable(NotInteractive)`.
/// If the dict is NULL → `Unavailable(NoGuiSession)`. No password fallback in
/// either case (physical-presence model).
///
/// **Touch ID** (when `canEvaluatePolicy` for biometrics succeeds): success
/// → `Biometric`. `EvalOutcome::Rejected` is terminal after a session
/// re-check disambiguates "user rejected" from "screen locked mid-prompt".
/// `EvalOutcome::TryFallback` (Lockout / NotAvailable / NotEnrolled /
/// PasscodeNotSet) **falls through to the system password**
/// (`DeviceOwnerAuthentication` policy).
pub fn authenticate(reason: &str) -> AuthOutcome {
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
                // Biometry locked/unavailable: drop into the password fallback.
            }
        }
    }

    // Re-check session state before the password fallback. We may have
    // arrived here via two paths:
    //   1. `can_evaluate(WithBiometrics) == false` upfront (no LAContext call).
    //   2. `evaluate` returned `TryFallback` (Lockout / NotAvailable / etc.).
    // In either case, the screen could have locked since the cached pre-check
    // (1s TTL window). Don't prompt for the password on a locked machine —
    // physical-presence model says no auth on a locked screen.
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

    match la::evaluate(la::Policy::DeviceOwner, reason) {
        EvalOutcome::Success => AuthOutcome::Success(AuthMethod::Password),
        EvalOutcome::NotInteractive => AuthOutcome::Unavailable(UnavailableReason::NotInteractive),
        EvalOutcome::Rejected | EvalOutcome::TryFallback => AuthOutcome::Rejected,
    }
}

pub fn local_authentication(reason: &str) -> bool {
    authenticate(reason).is_success()
}

/// Build the initial KeychainStore (passcode blob + encrypted passphrase)
/// and write it as a single keychain item. Used by `vt init`,
/// `vt secret import`, and `vt secret rotate-passcode` — all three either
/// create the store fresh (init/import) or replace it wholesale (rotate),
/// so this single call is the only write.
pub fn create_and_save_passcode_passphrase(real_passphrase: &[u8; 32]) -> Result<()> {
    use super::store::KeychainStore;

    // 64 bytes: the passcode, then 32 random bytes nothing reads. The second
    // half was the retired VT_AUTH token; keeping the width means stores
    // written before and after the removal are byte-compatible.
    let passcode = AesGcmCrypto::generate_key();
    let mut passcode_and_auth_token = Vec::with_capacity(64);
    passcode_and_auth_token.extend_from_slice(&passcode);
    passcode_and_auth_token.extend_from_slice(&AesGcmCrypto::generate_key());

    // New stores are always wrap v2 (KeychainStore::new sets wrap_v).
    let passphrase_secret = derive_passphrase_secret_v2(&passcode)?;
    let aes = AesGcmCrypto::new(&passphrase_secret)?;
    let encrypted_passphrase = aes.encrypt(real_passphrase)?;

    // Carry the SSH-key blob over only when the master it is sealed under is
    // the one being written (rotate-passcode). `secret import` of a different
    // master would otherwise leave a blob no path can open or clear.
    let mut store = KeychainStore::new(&passcode_and_auth_token, &encrypted_passphrase);
    if let Ok(existing) = KeychainStore::load() {
        let same_master = derive_passcode_cipher(&existing)
            .and_then(|c| load_mac_key(&existing, &c))
            .map(|k| k.as_slice() == real_passphrase)
            .unwrap_or(false);
        if same_master {
            store.encrypted_ssh_keys = existing.encrypted_ssh_keys;
        }
    }
    store.save()?;
    tracing::info!("keychain store saved!");
    Ok(())
}

/// Decrypt the raw 32-byte master key from the store: the HKDF IKM for v2
/// envelope DEK derivation. The passphrase cipher is supplied separately so
/// callers can hold it long-term (serve) without keeping the decrypted
/// master key in memory; the key comes back `Zeroizing` and callers drop it
/// as soon as derivation is complete.
pub(super) fn load_mac_key(
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

/// The master key as the AES-GCM cipher over the SSH-keys blob.
pub fn load_mac_cipher(
    store: &super::store::KeychainStore,
    passphrase_cipher: &AesGcmCrypto,
) -> Result<AesGcmCrypto> {
    let key = load_mac_key(store, passphrase_cipher)?;
    AesGcmCrypto::new(&key)
}

/// Derive the passphrase cipher from the passcode bytes inside an
/// already-loaded store. Only wrap v2 is readable: a v1 (path-bound) or
/// unknown marker fails closed here, before any unwrap, with the operator
/// remedy. Pure CPU work; does not touch the keychain.
pub fn derive_passcode_cipher(store: &super::store::KeychainStore) -> Result<AesGcmCrypto> {
    use super::store::WRAP_V2;
    ensure!(
        store.wrap_v == WRAP_V2,
        "rusty.vault.store has wrap version {}, this release reads only wrap v{WRAP_V2} — \
         run `vt secret rebind` on the previous vt release first (docs/app-bundle.md#master-key-wrap-v2)",
        store.wrap_v
    );
    let passcode_arr = split_passcode(store)?;
    let passphrase_secret = derive_passphrase_secret_v2(&passcode_arr)?;
    AesGcmCrypto::new(&passphrase_secret)
}

/// The passcode is the first half of the 64-byte blob; the length check stays
/// so a truncated or foreign store fails here rather than in the unwrap.
fn split_passcode(store: &super::store::KeychainStore) -> Result<[u8; 32]> {
    let passcode = store.passcode_and_auth_token_bytes()?;
    ensure!(
        passcode.len() == 64,
        "Passcode length is {}, expected 64",
        passcode.len()
    );
    Ok(passcode[..32].try_into()?)
}

#[cfg(test)]
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

    /// In-memory v2 store wrapping `master` under its own passcode. No
    /// keychain access.
    fn v2_store(master: &[u8; 32]) -> super::super::store::KeychainStore {
        use super::super::store::KeychainStore;
        let passcode = AesGcmCrypto::generate_key();
        let mut tokens = Vec::new();
        tokens.extend_from_slice(&passcode);
        tokens.extend_from_slice(&AesGcmCrypto::generate_key());
        let secret = derive_passphrase_secret_v2(&passcode).unwrap();
        let wrapped = AesGcmCrypto::new(&secret).unwrap().encrypt(master).unwrap();
        KeychainStore::new(&tokens, &wrapped)
    }

    /// Rejected input: the retired path-bound wrap v1 (explicit marker or
    /// the marker-less form older stores parse as 0) and an unknown version
    /// fail closed before any unwrap, naming the remedy, and the store is
    /// not mutated.
    #[test]
    fn test_non_v2_wrap_is_rejected() {
        let master = AesGcmCrypto::generate_key();
        for wrap_v in [1u32, 0, 99] {
            let mut store = v2_store(&master);
            store.wrap_v = wrap_v;
            let err = derive_passcode_cipher(&store).err().expect("rejected");
            assert!(
                err.to_string().contains(&format!("wrap version {wrap_v}")),
                "{err}"
            );
            assert!(err.to_string().contains("previous vt release"), "{err}");
        }
    }

    #[test]
    #[ignore]
    fn test_biometric_authentication() {
        assert!(local_authentication("test biometric authentication"));
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
        // -8: 3 failures triggered system lockout — must not be treated as
        // a terminal Rejected.
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
        // biometry can't run, but the password fallback might.
        assert_eq!(classify_la_error(-12), EvalOutcome::TryFallback);
    }

    #[test]
    fn classify_la_biometry_disconnected_is_try_fallback() {
        // -13: sensor temporarily disconnected (e.g. external Touch ID device).
        // Treat as TryFallback so the user can still auth via password.
        assert_eq!(classify_la_error(-13), EvalOutcome::TryFallback);
    }

    // ---- Secure Enclave wrap-v3 spike ------------------------------------
    //
    // Keychain-less SE key: `kSecAttrIsPermanent = false`, the SE-wrapped
    // private key (`kSecAttrTokenOID`, ~570 bytes, device-bound) is ours to
    // store, and `SecKeyCreateWithData` with that attribute rebuilds the
    // handle. No data-protection keychain, so no restricted entitlement:
    // ad-hoc and self-signed binaries carrying `keychain-access-groups` are
    // SIGKILLed by AMFI (-424/-413), and a permanent SE key fails -34018.
    //
    // Findings (macOS, Apple Silicon, 2026-09-22; docs/secure-enclave.md):
    //   Q1 blob round-trips; the ACL (biometryCurrentSet | privateKeyUsage)
    //      travels inside the blob.
    //   Q2 one evaluated LAContext bound via `kSecUseAuthenticationContext`
    //      unwraps repeatedly (~5 ms) with no further prompt, for as long as
    //      the process holds it (40 s+ observed, no expiry). `invalidate()`
    //      and even dropping the context do NOT close a warm handle: ctkd
    //      keeps the last context used on the token authorized until another
    //      context performs a token op; then the invalidated one fails. A
    //      never-evaluated context always prompts. Grant revocation must
    //      therefore drop ctx + handle and treat `invalidate()` as advisory.
    //   Q3 a rebuilt (new ad-hoc cdhash) binary reloads the blob.
    //
    //   cargo test spike_se -- --ignored --nocapture                 # Q1 + Q2
    //   VT_SPIKE=keep  cargo test spike_se -- --ignored --nocapture  # leave blob
    //   touch src/main.rs && VT_SPIKE=reuse cargo test spike_se -- --ignored --nocapture  # Q3
    mod spike_se {
        use core_foundation::base::{CFType, TCFType, ToVoid};
        use core_foundation::data::CFData;
        use core_foundation::dictionary::CFMutableDictionary;
        use core_foundation::error::{CFError, CFErrorRef};
        use core_foundation::string::CFString;
        use objc2::rc::Retained;
        use objc2_foundation::NSString;
        use objc2_local_authentication::{LAContext, LAPolicy};
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
        use security_framework_sys::item::{
            kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType,
            kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
            kSecUseAuthenticationContext,
        };
        use security_framework_sys::key::SecKeyCreateWithData;
        use std::time::Instant;

        const STATE: &str = "/tmp/vt-spike-se.bin";
        const ALG: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
        /// `kSecAttrTokenOID`: not in security-framework-sys.
        const TOKEN_OID: &str = "toid";
        // security-framework-sys access_control flags (not re-exported).
        const BIOMETRY_CURRENT_SET: usize = 1 << 3;
        const PRIVATE_KEY_USAGE: usize = 1 << 30;

        fn generate() -> SecKey {
            let ac = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                BIOMETRY_CURRENT_SET | PRIVATE_KEY_USAGE,
            )
            .expect("access control");
            let mut opts = GenerateKeyOptions::default();
            // No `set_location` => kSecAttrIsPermanent false: nothing is
            // written to any keychain.
            opts.set_key_type(KeyType::ec())
                .set_size_in_bits(256)
                .set_token(Token::SecureEnclave)
                .set_access_control(ac);
            SecKey::new(&opts).unwrap_or_else(|e| panic!("Q1 FAIL: SE key generation: {e:?}"))
        }

        /// The SE-wrapped private key (what CryptoKit calls
        /// `dataRepresentation`): opaque, device-bound, useless off-SE.
        fn export_blob(key: &SecKey) -> Vec<u8> {
            let attrs = key.attributes();
            let v = attrs
                .find(CFString::from_static_string(TOKEN_OID).to_void())
                .expect("Q1 FAIL: no kSecAttrTokenOID on SE key");
            unsafe { CFData::wrap_under_get_rule(v.cast()) }.to_vec()
        }

        /// Rebuild the private-key handle. The blob travels as
        /// `kSecAttrTokenOID`; passing it as the key data instead makes the
        /// token mint a *new* key (verified). `ctx` binds
        /// `kSecUseAuthenticationContext`.
        fn import_blob(blob: &[u8], ctx: Option<&Retained<LAContext>>) -> Result<SecKey, String> {
            let mut attrs = CFMutableDictionary::<CFType, CFType>::new();
            unsafe {
                let s = |r| CFString::wrap_under_get_rule(r).as_CFType();
                attrs.set(
                    CFString::from_static_string(TOKEN_OID).as_CFType(),
                    CFData::from_buffer(blob).as_CFType(),
                );
                attrs.set(s(kSecAttrKeyType), s(kSecAttrKeyTypeECSECPrimeRandom));
                attrs.set(s(kSecAttrKeyClass), s(kSecAttrKeyClassPrivate));
                attrs.set(s(kSecAttrTokenID), s(kSecAttrTokenIDSecureEnclave));
                if let Some(ctx) = ctx {
                    let raw = Retained::as_ptr(ctx) as *const std::os::raw::c_void;
                    attrs.set(
                        s(kSecUseAuthenticationContext),
                        CFType::wrap_under_get_rule(raw),
                    );
                }
                let mut err: CFErrorRef = std::ptr::null_mut();
                let k = SecKeyCreateWithData(
                    CFData::from_buffer(&[]).as_concrete_TypeRef(),
                    attrs.to_immutable().as_concrete_TypeRef(),
                    &mut err,
                );
                if k.is_null() {
                    return Err(format!("{:?}", CFError::wrap_under_create_rule(err)));
                }
                Ok(SecKey::wrap_under_create_rule(k))
            }
        }

        fn evaluated_ctx() -> Retained<LAContext> {
            let ctx = unsafe { LAContext::new() };
            let (tx, rx) = std::sync::mpsc::sync_channel::<bool>(1);
            let block = block2::RcBlock::new(
                move |ok: objc2::runtime::Bool, _e: *mut objc2_foundation::NSError| {
                    let _ = tx.send(ok.as_bool());
                },
            );
            unsafe {
                ctx.evaluatePolicy_localizedReason_reply(
                    LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                    &NSString::from_str("vt SE spike: unwrap master"),
                    &block,
                );
            }
            assert!(rx.recv().unwrap(), "Touch ID rejected");
            ctx
        }

        fn timed_decrypt(key: &SecKey, ct: &[u8], what: &str) -> Result<Vec<u8>, String> {
            let t = Instant::now();
            let r = key.decrypt_data(ALG, ct).map_err(|e| format!("{e:?}"));
            eprintln!(
                "{what}: {:?} in {:?}",
                r.as_ref().map(|_| "ok"),
                t.elapsed()
            );
            r
        }

        #[test]
        #[ignore]
        fn spike_se_wrap_v3() {
            let mode = std::env::var("VT_SPIKE").unwrap_or_default();

            let (blob, master, ct) = if mode == "reuse" {
                let state = std::fs::read(STATE).expect("run with VT_SPIKE=keep first");
                let (master, rest) = state.split_at(32);
                let (ct, blob) = rest.split_at(65 + 32 + 16); // ECIES: epk + pt + tag
                (blob.to_vec(), master.to_vec(), ct.to_vec())
            } else {
                let k = generate();
                let blob = export_blob(&k);
                eprintln!("Q1: SE key generated, blob {} bytes", blob.len());
                let master: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let ct = k
                    .public_key()
                    .expect("public key")
                    .encrypt_data(ALG, &master)
                    .expect("ECIES encrypt");
                eprintln!("wrapped: {} -> {} bytes", master.len(), ct.len());
                (blob, master, ct)
            };

            // Q1: reload without a context — the system prompts on its own.
            let k0 = import_blob(&blob, None).expect("Q1 FAIL: SecKeyCreateWithData");
            let pt = timed_decrypt(&k0, &ct, "unwrap via reloaded blob, no ctx (system prompt)")
                .expect("Q1 FAIL: decrypt via reloaded blob");
            assert_eq!(pt, master);
            eprintln!("Q1 OK: blob round-trips through SecKeyCreateWithData");
            drop(k0);

            // Q2a: one evaluated context, three unwraps, one prompt.
            let ctx = evaluated_ctx();
            let key = import_blob(&blob, Some(&ctx)).expect("import with ctx");
            for i in 1..=3 {
                let pt = timed_decrypt(&key, &ct, &format!("unwrap #{i} (same ctx)"))
                    .expect("Q2 FAIL: decrypt with evaluated ctx");
                assert_eq!(pt, master);
            }
            eprintln!("Q2a: 3 unwraps done — count the prompts you saw (expect 1)");

            // Q2b: does `invalidate()` close the grant? Fresh ciphertext per
            // probe so no cached ECDH result can masquerade as authorization.
            let pubk = key.public_key().expect("pub");
            let probe = |label: &str| {
                let fresh_ct = pubk.encrypt_data(ALG, &master).unwrap();
                let held = key.decrypt_data(ALG, &fresh_ct).is_ok();
                let fresh = import_blob(&blob, Some(&ctx))
                    .ok()
                    .and_then(|k| k.decrypt_data(ALG, &fresh_ct).ok())
                    .is_some();
                eprintln!("Q2b {label}: held handle ok={held}, fresh import ok={fresh}");
            };
            probe("before invalidate");
            unsafe { ctx.invalidate() };
            probe("right after invalidate");
            std::thread::sleep(std::time::Duration::from_secs(3));
            probe("3s after invalidate");

            // Q2c: a never-evaluated context must prompt (no SEP-side grace
            // window); its token op evicts `ctx` from ctkd's warm slot.
            let fresh = unsafe { LAContext::new() };
            let k = import_blob(&blob, Some(&fresh)).expect("import with fresh ctx");
            let r = timed_decrypt(&k, &ct, "unwrap with NEW unevaluated ctx (expect prompt)");
            eprintln!("Q2c: {:?}", r.as_ref().map(|_| "ok"));
            probe("after another ctx did a token op");

            if mode == "keep" {
                let mut state = master.clone();
                state.extend_from_slice(&ct);
                state.extend_from_slice(&blob);
                std::fs::write(STATE, state).unwrap();
                eprintln!("kept {STATE}; rebuild, then VT_SPIKE=reuse");
            } else if mode == "reuse" {
                eprintln!("Q3 OK: rebuilt binary reloaded the blob");
            }
        }
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
