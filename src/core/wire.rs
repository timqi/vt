//! Cross-platform wire envelope for vt extension responses.
//!
//! Every `encrypt@vt` / `decrypt@vt` / `auth@vt` response — success or failure
//! — is serialized as an [`ExtResponse<T>`] before being auth-cipher-encrypted
//! and stuffed into the SSH-agent extension reply. This lets the client
//! distinguish "user rejected Touch ID" from "screen is locked" from
//! "agent returned a malformed response", and map each to a stable exit code
//! (see [`ErrKind::exit_code`]).
//!
//! Two failure paths intentionally do NOT use this envelope and instead
//! collapse to `AgentError::Failure`:
//!
//! 1. `auth_cipher` decryption failure on the incoming request payload — we
//!    have no key with which to encrypt a structured reply.
//! 2. The `ssh-add -x` lock check fires before keychain ciphers are derived;
//!    sending a structured response would require running keychain I/O for
//!    every locked request.
//!
//! Both surface to the client as a parse error → [`ErrKind::Generic`].
//!
//! See `docs/structured-errors.md` for the full design rationale.
//!
//! NOTE: this module is intentionally I/O-free and platform-neutral. It is
//! consumed by both `client.rs` (cross-platform) and `server_macos::ssh_agent`
//! (macOS only). Do not import anything from `server_macos` here.

use serde::{Deserialize, Serialize};

use crate::core::session::{AuthOutcome, UnavailableReason};

/// Current protocol version. Bumped on any breaking change to [`ErrKind`] or
/// the envelope shape. Agent and client refuse mismatches with
/// [`ErrKind::ProtocolVersion`].
pub const WIRE_VERSION: u16 = 1;

/// Structured response envelope. `T` is the success payload type, which the
/// client deserializes only on `status: ok` arms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtResponse<T> {
    pub v: u16,
    #[serde(flatten)]
    pub body: ExtBody<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExtBody<T> {
    Ok {
        data: T,
    },
    Err {
        kind: ErrKind,
        /// Server-controlled static detail string, safe to surface to humans
        /// and to forward over `auth@vt`. NEVER contains user-supplied data
        /// (host, command, reason, fingerprints, paths) — see
        /// `docs/structured-errors.md`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

/// Stable error taxonomy. Append-only: removing or renaming a variant
/// requires bumping [`WIRE_VERSION`].
///
/// The `#[serde(other)]` `Unknown` variant lets an older client deserialize
/// a newer agent's unknown `kind` string into a generic fallback rather than
/// failing the JSON parse outright. The client maps `Unknown` to exit 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrKind {
    /// Unclassified server error.
    Generic,
    /// User actively rejected the biometric / FIDO2 / password prompt.
    AuthRejected,
    /// Screen is locked or off-console; cannot prompt right now.
    SessionLocked,
    /// No GUI session at all (LaunchDaemon-style context).
    NoGuiSession,
    /// `vt init` has not been run, or the keychain store is unreadable.
    NotInitialized,
    /// Agent is locked via `ssh-add -x`. Reserved for future use; today the
    /// lock check pre-empts envelope generation and surfaces as `Generic`.
    AgentLocked,
    /// Request JSON malformed, unknown `SecretType`, mismatched batch shape.
    BadRequest,
    /// Agent started with `--no-legacy-decrypt` and a legacy URL was sent.
    LegacyDisabled,
    /// Client and agent disagree on [`WIRE_VERSION`].
    ProtocolVersion,
    /// Retryable failure (file-lock contention, transient keychain error).
    /// Mirrors sysexits `EX_TEMPFAIL`. Reserved; not currently emitted.
    Transient,
    /// Sentinel for newer-than-known variants on older clients. Treated as
    /// `Generic` for exit-code purposes.
    #[serde(other)]
    Unknown,
}

impl ErrKind {
    /// Stable exit code mapping. See `docs/structured-errors.md` for the
    /// table and the reasoning behind each choice.
    pub fn exit_code(self) -> i32 {
        match self {
            ErrKind::Generic => 1,
            ErrKind::AuthRejected => 10,
            ErrKind::SessionLocked => 11,
            ErrKind::NoGuiSession => 12,
            ErrKind::NotInitialized => 13,
            ErrKind::AgentLocked => 14,
            ErrKind::BadRequest => 20,
            ErrKind::LegacyDisabled => 21,
            ErrKind::ProtocolVersion => 22,
            ErrKind::Transient => 75,
            ErrKind::Unknown => 1,
        }
    }

    /// Short human message used by the client when printing the failure to
    /// the user. Kept terse — callers may append the (allow-listed) `detail`
    /// string in parentheses.
    pub fn human_message(self) -> &'static str {
        match self {
            ErrKind::Generic => "vt: agent returned an unspecified error",
            ErrKind::AuthRejected => "vt: authentication rejected",
            ErrKind::SessionLocked => "vt: screen is locked",
            ErrKind::NoGuiSession => "vt: no GUI session (cannot prompt for Touch ID)",
            ErrKind::NotInitialized => "vt: agent is not initialized — run `vt init`",
            ErrKind::AgentLocked => "vt: agent is locked — unlock with `ssh-add -X`",
            ErrKind::BadRequest => "vt: agent rejected the request as malformed",
            ErrKind::LegacyDisabled => {
                "vt: legacy vt:// URLs are disabled on this agent (--no-legacy-decrypt)"
            }
            ErrKind::ProtocolVersion => {
                "vt: client and agent protocol versions do not match — reinstall both"
            }
            ErrKind::Transient => "vt: transient error, please retry",
            ErrKind::Unknown => "vt: agent returned an unknown error kind",
        }
    }
}

/// Build the byte sequence of an `ok` envelope by prefix-concatenating
/// the wire constants around an already-serialized inner body. This is the
/// single source of truth for the OK envelope shape — both the agent's
/// dispatcher and the client's regression test go through this function so
/// they cannot drift apart.
///
/// The manual concat (rather than `serde_json::to_vec(&ExtResponse{...})`)
/// exists because the inner body may contain DEK bytes; piping them
/// through any intermediate `serde_json::Value` would create a copy outside
/// the caller's `Zeroizing` buffer. By contrast, this function does a
/// single allocation that the caller can wrap in `Zeroizing` so the DEK
/// bytes only ever live in scrubbed memory.
pub fn wrap_ok_envelope(inner_body_json: &[u8]) -> Vec<u8> {
    let prefix = format!(r#"{{"v":{},"status":"ok","data":"#, WIRE_VERSION);
    let mut out = Vec::with_capacity(prefix.len() + inner_body_json.len() + 1);
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(inner_body_json);
    out.push(b'}');
    out
}

/// Pure mapping from a successful/failed [`AuthOutcome`] to an [`ErrKind`].
/// Returns `None` on success. Lives here (not in `server_macos`) so the
/// Linux client-surface check can also see it.
pub fn outcome_to_err(outcome: AuthOutcome) -> Option<ErrKind> {
    match outcome {
        AuthOutcome::Success(_) => None,
        AuthOutcome::Rejected => Some(ErrKind::AuthRejected),
        AuthOutcome::Unavailable(UnavailableReason::NotInteractive) => {
            Some(ErrKind::SessionLocked)
        }
        AuthOutcome::Unavailable(UnavailableReason::NoGuiSession) => {
            Some(ErrKind::NoGuiSession)
        }
    }
}

/// Like [`outcome_to_err`], but never returns `None` for a non-`Success`
/// outcome — falls back to [`ErrKind::Generic`] for any future variant the
/// classifier hasn't grown a case for. Auth-gated paths should use this so
/// a forgotten match arm fails closed (deny) rather than open (allow).
///
/// Today Rust's exhaustive matching ensures `outcome_to_err` covers every
/// variant, but `#[non_exhaustive]` on either enum (or a partial-update
/// PR that maps a new variant to `None`) would silently turn a missed case
/// into an authorization bypass without this shim.
pub fn outcome_to_err_strict(outcome: AuthOutcome) -> Option<ErrKind> {
    match outcome {
        AuthOutcome::Success(_) => None,
        other => Some(outcome_to_err(other).unwrap_or(ErrKind::Generic)),
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::session::AuthMethod;
    use serde_json::{json, Value};

    /// Tiny success payload used in round-trip tests.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Dummy {
        n: u32,
    }

    /// Every named `ErrKind` variant. `Unknown` is intentionally excluded:
    /// it has no on-the-wire string form (it's `#[serde(other)]`, a
    /// receive-only sentinel), so a round-trip test would serialize it as
    /// `"unknown"` and deserialize back to itself, masking real coverage.
    /// `Unknown`'s contract is exercised by
    /// `unknown_kind_deserializes_to_unknown_then_generic_exit`.
    fn all_kinds() -> &'static [ErrKind] {
        &[
            ErrKind::Generic,
            ErrKind::AuthRejected,
            ErrKind::SessionLocked,
            ErrKind::NoGuiSession,
            ErrKind::NotInitialized,
            ErrKind::AgentLocked,
            ErrKind::BadRequest,
            ErrKind::LegacyDisabled,
            ErrKind::ProtocolVersion,
            ErrKind::Transient,
        ]
    }

    #[test]
    fn roundtrip_all_kinds() {
        for &k in all_kinds() {
            let env: ExtResponse<Dummy> = ExtResponse {
                v: WIRE_VERSION,
                body: ExtBody::Err {
                    kind: k,
                    detail: Some("explanation".into()),
                },
            };
            let bytes = serde_json::to_vec(&env).unwrap();
            let parsed: ExtResponse<Dummy> = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed.v, WIRE_VERSION);
            match parsed.body {
                ExtBody::Err { kind, detail } => {
                    assert_eq!(kind, k, "kind mismatch for {:?}", k);
                    assert_eq!(detail.as_deref(), Some("explanation"));
                }
                ExtBody::Ok { .. } => panic!("expected Err variant for {:?}", k),
            }
        }
    }

    #[test]
    fn exit_code_table() {
        // Mirrors docs/structured-errors.md — keep in sync.
        assert_eq!(ErrKind::Generic.exit_code(), 1);
        assert_eq!(ErrKind::AuthRejected.exit_code(), 10);
        assert_eq!(ErrKind::SessionLocked.exit_code(), 11);
        assert_eq!(ErrKind::NoGuiSession.exit_code(), 12);
        assert_eq!(ErrKind::NotInitialized.exit_code(), 13);
        assert_eq!(ErrKind::AgentLocked.exit_code(), 14);
        assert_eq!(ErrKind::BadRequest.exit_code(), 20);
        assert_eq!(ErrKind::LegacyDisabled.exit_code(), 21);
        assert_eq!(ErrKind::ProtocolVersion.exit_code(), 22);
        assert_eq!(ErrKind::Transient.exit_code(), 75);
        assert_eq!(ErrKind::Unknown.exit_code(), 1);
    }

    #[test]
    fn unknown_kind_deserializes_to_unknown_then_generic_exit() {
        // Future agent sends a kind this client doesn't recognize.
        let raw = json!({
            "v": WIRE_VERSION,
            "status": "err",
            "kind": "future_kind_we_havent_added_yet",
            "detail": "something happened",
        });
        let env: ExtResponse<Dummy> = serde_json::from_value(raw).unwrap();
        match env.body {
            ExtBody::Err { kind, detail } => {
                assert_eq!(kind, ErrKind::Unknown);
                // Client maps Unknown → exit 1 (same as Generic).
                assert_eq!(kind.exit_code(), 1);
                assert_eq!(detail.as_deref(), Some("something happened"));
            }
            _ => panic!("expected err"),
        }
    }

    #[test]
    fn version_mismatch_is_detected_by_client_policy() {
        // The wire layer itself accepts any u16; client policy enforces
        // `v == WIRE_VERSION`. This test pins down the value of `v` so the
        // client can branch on it.
        let raw = json!({
            "v": 99,
            "status": "ok",
            "data": { "n": 42 },
        });
        let env: ExtResponse<Dummy> = serde_json::from_value(raw).unwrap();
        assert_ne!(env.v, WIRE_VERSION, "client must reject and emit ProtocolVersion");
    }

    #[test]
    fn outcome_to_err_strict_never_returns_none_for_failure() {
        // Success path: None (unchanged).
        for m in [AuthMethod::Biometric, AuthMethod::Fido2, AuthMethod::Password] {
            assert_eq!(outcome_to_err_strict(AuthOutcome::Success(m)), None);
        }
        // All non-Success outcomes resolve to Some(_) — the fail-closed
        // contract. Today these match `outcome_to_err`'s output, but the
        // shim guarantees they will continue to be `Some` even if a future
        // variant slips past `outcome_to_err`.
        assert!(outcome_to_err_strict(AuthOutcome::Rejected).is_some());
        assert!(outcome_to_err_strict(AuthOutcome::Unavailable(
            UnavailableReason::NotInteractive
        ))
        .is_some());
        assert!(outcome_to_err_strict(AuthOutcome::Unavailable(
            UnavailableReason::NoGuiSession
        ))
        .is_some());
    }

    #[test]
    fn outcome_to_err_table() {
        assert_eq!(outcome_to_err(AuthOutcome::Success(AuthMethod::Biometric)), None);
        assert_eq!(outcome_to_err(AuthOutcome::Success(AuthMethod::Fido2)), None);
        assert_eq!(outcome_to_err(AuthOutcome::Success(AuthMethod::Password)), None);
        assert_eq!(
            outcome_to_err(AuthOutcome::Rejected),
            Some(ErrKind::AuthRejected)
        );
        assert_eq!(
            outcome_to_err(AuthOutcome::Unavailable(UnavailableReason::NotInteractive)),
            Some(ErrKind::SessionLocked)
        );
        assert_eq!(
            outcome_to_err(AuthOutcome::Unavailable(UnavailableReason::NoGuiSession)),
            Some(ErrKind::NoGuiSession)
        );
    }

    #[test]
    fn ok_body_with_unknown_future_field() {
        // A future agent adds an extra top-level field. We must ignore it,
        // NOT fail the parse. This pins down the absence of
        // `#[serde(deny_unknown_fields)]`.
        let raw = json!({
            "v": WIRE_VERSION,
            "status": "ok",
            "data": { "n": 7 },
            "future_field": "ignored",
        });
        let env: ExtResponse<Dummy> = serde_json::from_value(raw).unwrap();
        match env.body {
            ExtBody::Ok { data } => assert_eq!(data, Dummy { n: 7 }),
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn err_body_missing_kind_field_is_parse_error() {
        // Absent `kind` is a hard parse error — `#[serde(other)] Unknown`
        // only catches unknown *values*, not absent fields. Make sure the
        // client sees this as a parse error rather than silently defaulting.
        let raw = json!({
            "v": WIRE_VERSION,
            "status": "err",
        });
        let res: Result<ExtResponse<Dummy>, _> = serde_json::from_value(raw);
        assert!(res.is_err(), "missing kind must fail parse");
    }

    #[test]
    fn detail_none_roundtrip_skips_field() {
        // `detail: None` must NOT serialize as `"detail":null` — it must be
        // omitted. Locks in `#[serde(skip_serializing_if = "Option::is_none")]`.
        let env: ExtResponse<Dummy> = ExtResponse {
            v: WIRE_VERSION,
            body: ExtBody::Err {
                kind: ErrKind::AuthRejected,
                detail: None,
            },
        };
        let json: Value = serde_json::to_value(&env).unwrap();
        let body = json.as_object().unwrap();
        assert!(
            !body.contains_key("detail"),
            "detail:None must serialize as absent field, got: {}",
            json
        );

        // Round-trip preserves None.
        let bytes = serde_json::to_vec(&env).unwrap();
        let parsed: ExtResponse<Dummy> = serde_json::from_slice(&bytes).unwrap();
        match parsed.body {
            ExtBody::Err { kind, detail } => {
                assert_eq!(kind, ErrKind::AuthRejected);
                assert!(detail.is_none());
            }
            _ => panic!("expected err"),
        }
    }

    #[test]
    fn wrap_ok_envelope_matches_ext_response_schema() {
        // The agent produces OK envelopes via the manual byte concat in
        // `wrap_ok_envelope`. If anyone ever renames `data` → `payload` (or
        // similar) in `ExtResponse`/`ExtBody`, the manual concat must be
        // updated in lockstep. This test serializes via `ExtResponse` (the
        // canonical schema) and asserts byte equality with what
        // `wrap_ok_envelope` would emit for the same inner body.
        let inner = serde_json::to_vec(&Dummy { n: 11 }).unwrap();
        let canonical = serde_json::to_vec(&ExtResponse {
            v: WIRE_VERSION,
            body: ExtBody::Ok {
                data: Dummy { n: 11 },
            },
        })
        .unwrap();
        let manual = wrap_ok_envelope(&inner);
        assert_eq!(
            canonical, manual,
            "wrap_ok_envelope has drifted from ExtResponse::Ok serialization"
        );
    }

    #[test]
    fn ok_envelope_roundtrip() {
        let env: ExtResponse<Dummy> = ExtResponse {
            v: WIRE_VERSION,
            body: ExtBody::Ok { data: Dummy { n: 5 } },
        };
        let bytes = serde_json::to_vec(&env).unwrap();
        let parsed: ExtResponse<Dummy> = serde_json::from_slice(&bytes).unwrap();
        match parsed.body {
            ExtBody::Ok { data } => assert_eq!(data, Dummy { n: 5 }),
            _ => panic!("expected ok"),
        }
    }
}
