//! macOS adapters for the platform-neutral authorization engine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;

use crate::core::authorization::{
    AuthorizationAuthenticator, AuthorizationEngine, AuthorizationValidator, Decision, Operation,
    ValidationError,
};
use crate::core::session::{AuthMethod, AuthOutcome, SessionState, UnavailableReason};

use super::se::SeSession;
use super::security::{authenticate_ctx, screen_state_now};
use super::store::{KeychainStore, WRAP_V3};

/// Wall time advancing this much further than monotonic uptime indicates that
/// macOS slept. Shared with the background watcher so request-time validation
/// and periodic invalidation use the same threshold.
pub(super) const SLEEP_DIVERGENCE: Duration = Duration::from_secs(30);

pub(super) fn sleep_diverged(mono_delta: Duration, wall_delta: Option<Duration>) -> bool {
    wall_delta.is_some_and(|wall| wall.saturating_sub(mono_delta) >= SLEEP_DIVERGENCE)
}

/// Secure Enclave sessions the approvals of a wrap v3 store leave behind
/// (docs/app-bundle.md#master-key-wrap-v3). Memory-only; handlers unwrap the
/// master through them and never hold the key across an await.
#[derive(Default)]
pub struct SeSessions {
    /// Behind live reusable grants: written by a `StrictTtl` biometric
    /// approval, read by cache hits, dropped with the grants.
    reusable: Mutex<Option<SeSession>>,
    /// A pending biometric session belongs to the serialized approval. It is
    /// dropped on failure/cancellation or promoted only with a committed grant.
    fresh: Mutex<Option<SeSession>>,
}

impl SeSessions {
    /// Called before every prompt to discard any unconsumed pending session.
    fn begin_prompt(&self) {
        *self
            .fresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn store(&self, session: SeSession) {
        *self
            .fresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(session);
    }

    fn complete(&self, reusable: bool) {
        let pending = self
            .fresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if reusable {
            if let Some(session) = pending {
                *self
                    .reusable
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(session);
            }
        }
    }

    /// The custody behind a permit: a cache hit reads the committed reusable
    /// session, a new approval its own pending one. The engine's approval
    /// guard owns pending-session cleanup.
    pub fn with_session<R>(
        &self,
        decision: Decision,
        f: impl FnOnce(&SeSession) -> R,
    ) -> Option<R> {
        let slot = if decision == Decision::CacheHit {
            &self.reusable
        } else {
            &self.fresh
        };
        slot.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(f)
    }

    /// Drop both sessions. Called under the security write gate after grants
    /// are cleared; `LAContext.invalidate()` is advisory, this drop is the boundary.
    fn clear(&self) {
        *self
            .reusable
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.begin_prompt();
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.reusable.lock().unwrap().is_none() && self.fresh.lock().unwrap().is_none()
    }

    /// Test seam: a pending session, or one already promoted to reusable.
    #[cfg(test)]
    pub(super) fn put(&self, reusable: bool, session: SeSession) {
        self.store(session);
        if reusable {
            self.complete(true);
        }
    }
}

struct MacAuthenticator {
    sessions: Arc<SeSessions>,
}

/// After a biometric approval of a master-needing operation on a wrap v3
/// store, bind the evaluated context to the SE key. Any failure leaves no
/// session: the handler then fails closed and drops its permit, so no grant
/// is written. A password approval never reaches here (no context).
fn bind_session(sessions: &SeSessions, ctx: super::se::BiometricContext) {
    let store = match KeychainStore::load() {
        Ok(store) if store.wrap_v == WRAP_V3 => store,
        Ok(_) => return,
        Err(error) => {
            tracing::warn!("store unreadable after approval: {error}");
            return;
        }
    };
    let session = store
        .se_material_bytes()
        .map_err(|e| e.to_string())
        .and_then(|(blob, _)| SeSession::open(&blob, ctx).map_err(|e| e.to_string()));
    match session {
        Ok(session) => sessions.store(session),
        Err(error) => tracing::warn!("Secure Enclave session not opened: {error}"),
    }
}

#[async_trait]
impl AuthorizationAuthenticator for MacAuthenticator {
    fn approval_complete(&self, reusable: bool) {
        self.sessions.complete(reusable);
    }

    async fn authenticate(
        &self,
        prompt: &str,
        operation: Operation,
        revocation_pending: Arc<AtomicBool>,
    ) -> AuthOutcome {
        let prompt = prompt.to_string();
        let sessions = Arc::clone(&self.sessions);
        match tokio::task::spawn_blocking(move || {
            sessions.begin_prompt();
            let (outcome, ctx) = authenticate_ctx(&prompt);
            if matches!(outcome, AuthOutcome::Unavailable(_)) {
                revocation_pending.store(true, Ordering::Release);
            }
            if let (AuthOutcome::Success(AuthMethod::Biometric), Some(ctx)) = (outcome, ctx) {
                if operation.needs_master() {
                    bind_session(&sessions, ctx);
                }
            }
            outcome
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!("auth prompt task failed: {}", error);
                AuthOutcome::Unavailable(UnavailableReason::NotInteractive)
            }
        }
    }
}

struct MacValidator {
    locked: Arc<AtomicBool>,
    last_clock: Mutex<(Instant, SystemTime)>,
    sessions: Arc<SeSessions>,
}

impl AuthorizationValidator for MacValidator {
    fn validate(&self, revocation_pending: &AtomicBool) -> Result<(), ValidationError> {
        let mut last = match self.last_clock.lock() {
            Ok(last) => last,
            Err(_) => {
                revocation_pending.store(true, Ordering::Release);
                return Err(ValidationError::Invalidated);
            }
        };
        if revocation_pending.load(Ordering::Acquire) {
            return Err(ValidationError::Invalidated);
        }
        if self.locked.load(Ordering::Acquire) {
            revocation_pending.store(true, Ordering::Release);
            return Err(ValidationError::Invalidated);
        }
        let now_mono = Instant::now();
        let now_wall = SystemTime::now();
        let woke = sleep_diverged(
            now_mono.saturating_duration_since(last.0),
            now_wall.duration_since(last.1).ok(),
        );
        *last = (now_mono, now_wall);
        if woke {
            revocation_pending.store(true, Ordering::Release);
            return Err(ValidationError::Invalidated);
        }
        let result = match screen_state_now() {
            SessionState::Interactive => Ok(()),
            SessionState::NotInteractive => Err(ValidationError::Unavailable(
                UnavailableReason::NotInteractive,
            )),
            SessionState::NoSession => Err(ValidationError::Unavailable(
                UnavailableReason::NoGuiSession,
            )),
        };
        if result.is_err() {
            revocation_pending.store(true, Ordering::Release);
            return result;
        }
        if revocation_pending.load(Ordering::Acquire) {
            return Err(ValidationError::Invalidated);
        }
        Ok(())
    }

    fn invalidation_complete(&self) {
        self.sessions.clear();
        let mut last = self
            .last_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = (Instant::now(), SystemTime::now());
    }
}

/// The engine and the Secure Enclave session store its approvals feed.
pub fn new_engine(locked: Arc<AtomicBool>) -> (Arc<AuthorizationEngine>, Arc<SeSessions>) {
    let sessions = Arc::new(SeSessions::default());
    let engine = AuthorizationEngine::new(
        Arc::new(MacAuthenticator {
            sessions: Arc::clone(&sessions),
        }),
        Arc::new(MacValidator {
            locked,
            last_clock: Mutex::new((Instant::now(), SystemTime::now())),
            sessions: Arc::clone(&sessions),
        }),
    );
    (engine, sessions)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Revocation through the real validator drops both SE sessions.
    #[tokio::test]
    async fn invalidation_drops_se_sessions() {
        use super::super::se::test_support::software_session;
        let (engine, sessions) = new_engine(Arc::new(AtomicBool::new(false)));
        sessions.put(true, software_session());
        sessions.put(false, software_session());
        assert!(!sessions.is_empty());
        engine.invalidate_all().await;
        assert!(sessions.is_empty());
    }

    const HIT: Decision = Decision::CacheHit;
    const NEW: Decision = Decision::Approved(AuthMethod::Biometric);

    /// Every new prompt clears pending custody without disturbing live hits;
    /// pending custody survives only until its approval completes, and is
    /// promoted only by a committed grant.
    #[test]
    fn pending_custody_follows_the_approval() {
        use super::super::se::test_support::software_session;
        let sessions = SeSessions::default();
        assert!(sessions.with_session(NEW, |_| ()).is_none());
        sessions.put(false, software_session());
        sessions.put(true, software_session());
        assert!(sessions.with_session(HIT, |_| ()).is_some());
        sessions.begin_prompt();
        assert!(sessions.with_session(NEW, |_| ()).is_none());
        assert!(sessions.with_session(HIT, |_| ()).is_some());

        sessions.store(software_session());
        sessions.complete(false);
        assert!(
            sessions.with_session(NEW, |_| ()).is_none(),
            "dropped, not promoted"
        );
        assert!(
            sessions.with_session(HIT, |_| ()).is_some(),
            "earlier hit custody untouched"
        );

        sessions.clear();
        assert!(sessions.is_empty());
        sessions.store(software_session());
        sessions.complete(true);
        assert!(sessions.with_session(NEW, |_| ()).is_none());
        assert!(
            sessions.with_session(HIT, |_| ()).is_some(),
            "promoted by commit"
        );
    }

    #[test]
    fn sleep_detection_uses_wall_minus_monotonic_divergence() {
        assert!(!sleep_diverged(
            Duration::from_secs(5),
            Some(Duration::from_secs(20))
        ));
        assert!(sleep_diverged(
            Duration::from_secs(5),
            Some(Duration::from_secs(35))
        ));
        assert!(!sleep_diverged(Duration::from_secs(5), None));
    }
}
