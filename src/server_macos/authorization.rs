//! macOS adapters for the platform-neutral authorization engine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;

use crate::core::authorization::{
    AuthorizationAuthenticator, AuthorizationEngine, AuthorizationValidator, ValidationError,
};
use crate::core::session::{AuthOutcome, SessionState, UnavailableReason};

use super::security::{authenticate, screen_state_now};

/// Wall time advancing this much further than monotonic uptime indicates that
/// macOS slept. Shared with the background watcher so request-time validation
/// and periodic invalidation use the same threshold.
pub(super) const SLEEP_DIVERGENCE: Duration = Duration::from_secs(30);

pub(super) fn sleep_diverged(mono_delta: Duration, wall_delta: Option<Duration>) -> bool {
    wall_delta.is_some_and(|wall| wall.saturating_sub(mono_delta) >= SLEEP_DIVERGENCE)
}

struct MacAuthenticator;

#[async_trait]
impl AuthorizationAuthenticator for MacAuthenticator {
    async fn authenticate(&self, prompt: &str, revocation_pending: Arc<AtomicBool>) -> AuthOutcome {
        let prompt = prompt.to_string();
        match tokio::task::spawn_blocking(move || {
            let outcome = authenticate(&prompt);
            if matches!(outcome, AuthOutcome::Unavailable(_)) {
                revocation_pending.store(true, Ordering::Release);
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
        let mut last = self
            .last_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = (Instant::now(), SystemTime::now());
    }
}

pub fn new_engine(locked: Arc<AtomicBool>) -> Arc<AuthorizationEngine> {
    AuthorizationEngine::new(
        Arc::new(MacAuthenticator),
        Arc::new(MacValidator {
            locked,
            last_clock: Mutex::new((Instant::now(), SystemTime::now())),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
