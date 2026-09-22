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
    use objc2::rc::Retained;
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

    /// Evaluate `policy` on a fresh context and hand the context back with
    /// the outcome: on success it is the evaluated context wrap v3 binds to
    /// the Secure Enclave key.
    pub(super) fn evaluate(policy: Policy, reason: &str) -> (EvalOutcome, Retained<LAContext>) {
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
                return (EvalOutcome::Rejected, ctx);
            }
        };
        if ok {
            return (EvalOutcome::Success, ctx);
        }
        let outcome = classify_la_error(code);
        if matches!(outcome, EvalOutcome::TryFallback) {
            tracing::info!(
                la_error_code = code,
                "biometry unavailable for evaluatePolicy; falling back to password"
            );
        }
        (outcome, ctx)
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
    authenticate_ctx(reason).0
}

/// [`authenticate`] plus, on `Success(Biometric)`, the evaluated context the
/// Secure Enclave key can be bound to. A password success carries no context:
/// the wrap v3 key's `biometryCurrentSet` policy cannot be met by it.
pub fn authenticate_ctx(reason: &str) -> (AuthOutcome, Option<super::se::BiometricContext>) {
    // Pre-check: screen lock state. Cached for 1s to bound CPU under spammy
    // callers (locked-screen + tight-loop client = naturally O(1)).
    match screen_state_cached() {
        SessionState::NotInteractive => {
            notify_locked_rejected(reason);
            return (
                AuthOutcome::Unavailable(UnavailableReason::NotInteractive),
                None,
            );
        }
        SessionState::NoSession => {
            return (
                AuthOutcome::Unavailable(UnavailableReason::NoGuiSession),
                None,
            );
        }
        SessionState::Interactive => {}
    }

    if la::can_evaluate(la::Policy::WithBiometrics) {
        let (outcome, ctx) = la::evaluate(la::Policy::WithBiometrics, reason);
        match outcome {
            EvalOutcome::Success => {
                return (
                    AuthOutcome::Success(AuthMethod::Biometric),
                    Some(super::se::BiometricContext::from_evaluated(ctx)),
                )
            }
            EvalOutcome::Rejected => {
                // Disambiguate: the screen could have locked between the cached
                // pre-check and now. Re-query uncached so a transient lock is
                // not misreported as a user rejection.
                match screen_state_now() {
                    SessionState::NotInteractive => {
                        notify_locked_rejected(reason);
                        return (
                            AuthOutcome::Unavailable(UnavailableReason::NotInteractive),
                            None,
                        );
                    }
                    SessionState::NoSession => {
                        return (
                            AuthOutcome::Unavailable(UnavailableReason::NoGuiSession),
                            None,
                        );
                    }
                    SessionState::Interactive => {}
                }
                notify_touch_id_rejected(reason);
                return (AuthOutcome::Rejected, None);
            }
            EvalOutcome::NotInteractive => {
                return (
                    AuthOutcome::Unavailable(UnavailableReason::NotInteractive),
                    None,
                );
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
            return (
                AuthOutcome::Unavailable(UnavailableReason::NotInteractive),
                None,
            );
        }
        SessionState::NoSession => {
            return (
                AuthOutcome::Unavailable(UnavailableReason::NoGuiSession),
                None,
            );
        }
        SessionState::Interactive => {}
    }

    let outcome = match la::evaluate(la::Policy::DeviceOwner, reason).0 {
        EvalOutcome::Success => AuthOutcome::Success(AuthMethod::Password),
        EvalOutcome::NotInteractive => AuthOutcome::Unavailable(UnavailableReason::NotInteractive),
        EvalOutcome::Rejected | EvalOutcome::TryFallback => AuthOutcome::Rejected,
    };
    (outcome, None)
}

pub fn local_authentication(reason: &str) -> bool {
    authenticate(reason).is_success()
}

/// Wrap `master` under a freshly generated Secure Enclave key and return
/// the v3 store to save. `vt init` / `vt secret import` save it as is;
/// `rotate-passcode` carries the SSH keys over first. Fails closed with
/// `se.unavailable` where there is no Secure Enclave.
pub fn new_store_v3(master: &[u8; 32]) -> Result<super::store::KeychainStore> {
    let (blob, wrapped) = super::se::generate_and_wrap(master)?;
    Ok(super::store::KeychainStore::new_v3(&blob, &wrapped))
}

/// Accept only wrap versions this release can unwrap. A v1 (path-bound) or
/// unknown marker fails here, before any unwrap, with the operator remedy.
pub fn check_wrap(store: &super::store::KeychainStore) -> Result<()> {
    use super::store::{WRAP_V2, WRAP_V3};
    ensure!(
        store.wrap_v == WRAP_V2 || store.wrap_v == WRAP_V3,
        "rusty.vault.store has wrap version {}, this release reads wrap v{WRAP_V2} (migration \
         source) and v{WRAP_V3} — run `vt secret rebind` on the previous vt release first \
         (docs/app-bundle.md#master-key-wrap-v3)",
        store.wrap_v
    );
    Ok(())
}

/// One human authorization that can unwrap a store's master: wrap v2 derives
/// the passcode cipher after the ordinary prompt; wrap v3 binds the evaluated
/// biometric context to the Secure Enclave key. CLI paths hold one of these
/// per command; the agent holds its sessions in `SeSessions`.
pub enum MasterAccess {
    Passcode(Box<AesGcmCrypto>),
    Enclave(super::se::SeSession),
}

impl MasterAccess {
    pub fn open(store: &super::store::KeychainStore, reason: &str) -> Result<Self> {
        check_wrap(store)?;
        if store.wrap_v == super::store::WRAP_V2 {
            ensure!(
                authenticate(reason).is_success(),
                "Local authentication failed for {reason}"
            );
            return Ok(Self::Passcode(Box::new(derive_passcode_cipher(store)?)));
        }
        let (blob, _) = store.se_material_bytes()?;
        let (outcome, ctx) = authenticate_ctx(reason);
        ensure!(
            outcome.is_success(),
            "Local authentication failed for {reason}"
        );
        let ctx = ctx.ok_or_else(|| {
            anyhow::anyhow!(
                "se.biometry_required: wrap v3 unwraps only after Touch ID; the password \
                 fallback cannot satisfy the Secure Enclave key"
            )
        })?;
        Ok(Self::Enclave(super::se::SeSession::open(&blob, ctx)?))
    }

    /// The raw 32-byte master: the HKDF IKM for every DEK and the SSH-blob
    /// cipher key. Callers derive and drop it in the same scope.
    pub fn master(&self, store: &super::store::KeychainStore) -> Result<Zeroizing<[u8; 32]>> {
        match self {
            Self::Passcode(cipher) => unwrap_master_v2(store, cipher),
            Self::Enclave(session) => {
                let (_, wrapped) = store.se_material_bytes()?;
                Ok(session.unwrap_master(&wrapped)?)
            }
        }
    }
}

/// Decrypt the raw master from a wrap v2 store through its passcode cipher.
pub(super) fn unwrap_master_v2(
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

/// Preflight the stored master before consulting grants or prompting, without
/// retaining raw key material across a human prompt: v2 unwraps and drops
/// (deterministic, no prompt); v3 can only check the material's shape.
pub(crate) fn validate_master_material(store: &super::store::KeychainStore) -> Result<()> {
    check_wrap(store)?;
    if store.wrap_v == super::store::WRAP_V2 {
        drop(unwrap_master_v2(store, &derive_passcode_cipher(store)?)?);
        return Ok(());
    }
    let (blob, wrapped) = store.se_material_bytes()?;
    Ok(super::se::check_material(&blob, &wrapped)?)
}

/// Derive the wrap v2 passphrase cipher from the passcode bytes inside an
/// already-loaded store. Pure CPU work; does not touch the keychain.
pub fn derive_passcode_cipher(store: &super::store::KeychainStore) -> Result<AesGcmCrypto> {
    ensure!(
        store.wrap_v == super::store::WRAP_V2,
        "wrap v{} store has no passcode cipher",
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
pub(super) mod tests {
    use super::*;

    /// In-memory v2 store wrapping `master` under its own passcode. No
    /// keychain access.
    pub(in crate::server_macos) fn v2_store(
        master: &[u8; 32],
    ) -> super::super::store::KeychainStore {
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
    /// fail closed before any unwrap, naming the remedy.
    #[test]
    fn test_unknown_wrap_is_rejected_before_unwrap() {
        let master = AesGcmCrypto::generate_key();
        for wrap_v in [1u32, 0, 99] {
            let mut store = v2_store(&master);
            store.wrap_v = wrap_v;
            let err = check_wrap(&store).expect_err("rejected");
            assert!(
                err.to_string().contains(&format!("wrap version {wrap_v}")),
                "{err}"
            );
            assert!(err.to_string().contains("previous vt release"), "{err}");
            assert!(validate_master_material(&store).is_err());
        }
    }

    /// The migration source still unwraps without a prompt; a v3 store
    /// passes the shape preflight and has no passcode cipher.
    #[test]
    fn test_v2_unwraps_and_v3_preflights_by_shape() {
        use super::super::store::KeychainStore;
        let master = AesGcmCrypto::generate_key();
        let store = v2_store(&master);
        check_wrap(&store).unwrap();
        validate_master_material(&store).unwrap();
        let got = MasterAccess::Passcode(Box::new(derive_passcode_cipher(&store).unwrap()))
            .master(&store)
            .unwrap();
        assert_eq!(got.as_slice(), &master);

        let v3 = KeychainStore::new_v3(&[1u8; 570], &[2u8; super::super::se::WRAPPED_MASTER_LEN]);
        check_wrap(&v3).unwrap();
        validate_master_material(&v3).unwrap();
        assert!(derive_passcode_cipher(&v3).is_err());
        let short = KeychainStore::new_v3(&[1u8; 570], &[2u8; 32]);
        assert!(validate_master_material(&short).is_err());
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
