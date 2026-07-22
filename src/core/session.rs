//! Pure session-state classifiers and notification throttle helpers.
//!
//! These types model "is the user actively present at an interactive
//! session" in a platform-neutral way. The macOS implementation in
//! `crate::server_macos::security` adapts `CGSessionCopyCurrentDictionary` into a
//! [`SessionFlags`] and feeds it through [`classify_session`]. Other
//! platforms can produce their own [`SessionFlags`] from whatever evidence
//! they have available.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Which method satisfied the auth request. All three are physical-presence
/// factors and treated as equivalent for authorization caching (see
/// `AuthMethod::is_cacheable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Biometric,
    Fido2,
    Password,
}

impl AuthMethod {
    /// True if a successful auth via this method may grant a TTL-bounded
    /// cache entry. All three methods qualify in the VT model: Touch ID
    /// biometric, FIDO2 YubiKey touch, and the macOS account password each
    /// require explicit physical or credentialed action per attempt.
    pub fn is_cacheable(self) -> bool {
        matches!(self, AuthMethod::Biometric | AuthMethod::Fido2 | AuthMethod::Password)
    }
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
    /// A grant reuse satisfied sign/decrypt without a Touch ID prompt
    /// (docs/app-bundle.md §3) — transparency for otherwise-silent reuse.
    CacheHit,
}

/// Classification of session state. Pure type, no FFI — produced by
/// [`classify_session`] and consumable in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// User is on console, login complete, screen unlocked → auth dialog
    /// can prompt.
    Interactive,
    /// Locked, off-console, or login pending → auth dialog can't display.
    NotInteractive,
    /// No session evidence available at all (e.g. no GUI session).
    NoSession,
}

/// Three flags carrying interactive-session evidence. All optional —
/// `None` means "no info", which the classifier treats as not blocking.
/// Platform adapters fill these in from whatever signals they have. The
/// macOS adapter reads them out of `CGSessionCopyCurrentDictionary`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionFlags {
    pub is_locked: Option<bool>,
    pub is_on_console: Option<bool>,
    pub is_login_done: Option<bool>,
}

/// Pure classifier. `None` flags = no session evidence available.
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

/// Pure: TTL-bounded cache check over an injectable lookup. Production
/// wrapper lives in `crate::server_macos::security`; tests call this directly.
pub(crate) fn lock_cache_check<F: FnOnce() -> SessionState>(
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

/// Pure: dedup gate over an injectable map + clock. Production wrapper
/// lives in `crate::server_macos::security`; tests call this directly.
pub(crate) fn throttle_check(
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
