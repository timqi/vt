//! Cross-platform wire envelope for vt extension responses.
//!
//! Every `encrypt@vt` / `decrypt@vt` / `auth@vt` response — success or failure
//! — is serialized as an [`ExtResponse<T>`] and carried as plain JSON in the
//! SSH-agent extension reply. This lets the client
//! distinguish "user rejected Touch ID" from "screen is locked" from
//! "agent returned a malformed response", and map each to a stable exit code
//! (see [`ErrKind::exit_code`]).
//!
//! Two failure paths intentionally do NOT use this envelope and instead
//! collapse to `AgentError::Failure`:
//!
//! 1. The `ssh-add -x` lock check fires before any keychain I/O; a locked
//!    agent answers like a non-vt agent would, so the client's `ssh-add -X`
//!    hint stays on one path.
//! 2. Store load / wrap-cipher derivation failure precedes dispatch, so no
//!    handler exists yet to pick an `ErrKind`.
//!
//! Both surface to the client as `VtClientError::Transport` (exit 1).
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

/// Structured response envelope. `T` is the success payload type; the client
/// parses with `T = &RawValue` so DEK-bearing `data` stays a borrowed span
/// (never re-allocated through `serde_json::Value`).
///
/// The shape is deliberately flat — `status` is a plain field and `data` /
/// `kind` / `detail` are optional — rather than a `#[serde(tag = "status")]`
/// body enum: serde's flatten/internally-tagged paths buffer through
/// `Content`, which cannot carry a `RawValue`. The client enforces the
/// `ok => data`, `err => kind` pairing in `parse_envelope`.
///
/// The agent emits OK envelopes through [`wrap_ok_envelope`] (see its
/// DEK-copy rationale); tests serialize this type to pin that byte shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtResponse<T> {
    pub v: u16,
    pub status: Status,
    /// Present iff `status == ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Present iff `status == err`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ErrKind>,
    /// Server-controlled static detail string, safe to surface to humans
    /// and to forward over `auth@vt`. NEVER contains user-supplied data
    /// (host, command, reason, fingerprints, paths) — see
    /// `docs/structured-errors.md`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl<T> ExtResponse<T> {
    #[cfg(test)]
    pub fn ok(data: T) -> Self {
        ExtResponse {
            v: WIRE_VERSION,
            status: Status::Ok,
            data: Some(data),
            kind: None,
            detail: None,
        }
    }

    /// `&'static str` detail restricts construction to the agent's reviewed
    /// `DETAIL_*` allow-list: no runtime string can reach the wire here.
    pub fn err(kind: ErrKind, detail: Option<&'static str>) -> Self {
        ExtResponse {
            v: WIRE_VERSION,
            status: Status::Err,
            data: None,
            kind: Some(kind),
            detail: detail.map(str::to_owned),
        }
    }
}

/// `status` discriminator of [`ExtResponse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Err,
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
    /// User actively rejected the Touch ID prompt.
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
    /// Touch ID cannot be evaluated (locked out, not enrolled, no sensor);
    /// no prompt was shown.
    BiometryUnavailable,
    /// Request JSON malformed, unknown `SecretType`, mismatched batch shape.
    BadRequest,
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
            ErrKind::BiometryUnavailable => 15,
            ErrKind::BadRequest => 20,
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
            ErrKind::BiometryUnavailable => {
                "vt: Touch ID is unavailable (locked out, not enrolled, or no sensor)"
            }
            ErrKind::BadRequest => "vt: agent rejected the request as malformed",
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

/// Pure mapping from an [`AuthOutcome`] to an [`ErrKind`]. `Success` is the
/// only `None` arm; the match is exhaustive with no wildcard, so a new
/// outcome variant is a compile error here, never a silent `None` on an
/// auth-gated path. Lives here (not in `server_macos`) so the Linux
/// client-surface check can also see it.
pub fn outcome_to_err_strict(outcome: AuthOutcome) -> Option<ErrKind> {
    match outcome {
        AuthOutcome::Success => None,
        AuthOutcome::Rejected => Some(ErrKind::AuthRejected),
        AuthOutcome::Unavailable(UnavailableReason::NotInteractive) => Some(ErrKind::SessionLocked),
        AuthOutcome::Unavailable(UnavailableReason::NoGuiSession) => Some(ErrKind::NoGuiSession),
        AuthOutcome::Unavailable(UnavailableReason::BiometryUnavailable) => {
            Some(ErrKind::BiometryUnavailable)
        }
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
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
            ErrKind::BiometryUnavailable,
            ErrKind::BadRequest,
            ErrKind::ProtocolVersion,
            ErrKind::Transient,
        ]
    }

    #[test]
    fn roundtrip_all_kinds() {
        for &k in all_kinds() {
            let env: ExtResponse<Dummy> = ExtResponse::err(k, Some("explanation"));
            let bytes = serde_json::to_vec(&env).unwrap();
            let parsed: ExtResponse<Dummy> = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed.v, WIRE_VERSION);
            assert_eq!(parsed.status, Status::Err);
            assert_eq!(parsed.kind, Some(k), "kind mismatch for {:?}", k);
            assert_eq!(parsed.detail.as_deref(), Some("explanation"));
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
        assert_eq!(ErrKind::BiometryUnavailable.exit_code(), 15);
        assert_eq!(ErrKind::BadRequest.exit_code(), 20);
        // 21 retired (`LegacyDisabled`) — never reuse.
        assert_eq!(ErrKind::ProtocolVersion.exit_code(), 22);
        assert_eq!(ErrKind::Transient.exit_code(), 75);
        assert_eq!(ErrKind::Unknown.exit_code(), 1);
    }

    #[test]
    fn unknown_kind_deserializes_to_unknown_then_generic_exit() {
        // Future agent sends a kind this client doesn't recognize; a retired
        // kind (`legacy_disabled`, exit 21) is the same unknown input.
        for kind in ["future_kind_we_havent_added_yet", "legacy_disabled"] {
            let raw = json!({
                "v": WIRE_VERSION,
                "status": "err",
                "kind": kind,
                "detail": "something happened",
            });
            let env: ExtResponse<Dummy> = serde_json::from_value(raw).unwrap();
            assert_eq!(env.status, Status::Err);
            assert_eq!(env.kind, Some(ErrKind::Unknown));
            // Client maps Unknown → exit 1 (same as Generic).
            assert_eq!(ErrKind::Unknown.exit_code(), 1);
            assert_eq!(env.detail.as_deref(), Some("something happened"));
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
        assert_ne!(
            env.v, WIRE_VERSION,
            "client must reject and emit ProtocolVersion"
        );
    }

    #[test]
    fn outcome_to_err_strict_never_returns_none_for_failure() {
        // Success is the only None.
        assert_eq!(outcome_to_err_strict(AuthOutcome::Success), None);
        // Every non-Success outcome maps to its kind — the fail-closed contract.
        assert_eq!(
            outcome_to_err_strict(AuthOutcome::Rejected),
            Some(ErrKind::AuthRejected)
        );
        assert_eq!(
            outcome_to_err_strict(AuthOutcome::Unavailable(UnavailableReason::NotInteractive)),
            Some(ErrKind::SessionLocked)
        );
        assert_eq!(
            outcome_to_err_strict(AuthOutcome::Unavailable(UnavailableReason::NoGuiSession)),
            Some(ErrKind::NoGuiSession)
        );
        assert_eq!(
            outcome_to_err_strict(AuthOutcome::Unavailable(
                UnavailableReason::BiometryUnavailable
            )),
            Some(ErrKind::BiometryUnavailable)
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
        assert_eq!(env.status, Status::Ok);
        assert_eq!(env.data, Some(Dummy { n: 7 }));
    }

    #[test]
    fn detail_none_roundtrip_skips_field() {
        // `detail: None` must NOT serialize as `"detail":null` — it must be
        // omitted. Locks in `#[serde(skip_serializing_if = "Option::is_none")]`.
        let env: ExtResponse<Dummy> = ExtResponse::err(ErrKind::AuthRejected, None);
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
        assert_eq!(parsed.kind, Some(ErrKind::AuthRejected));
        assert!(parsed.detail.is_none());
    }

    #[test]
    fn wrap_ok_envelope_matches_ext_response_schema() {
        // The agent produces OK envelopes via the manual byte concat in
        // `wrap_ok_envelope`. If anyone ever renames `data` → `payload` (or
        // similar) in `ExtResponse`, the manual concat must be updated in
        // lockstep. This test serializes via `ExtResponse` (the canonical
        // schema) and asserts byte equality with what `wrap_ok_envelope`
        // would emit for the same inner body.
        let inner = serde_json::to_vec(&Dummy { n: 11 }).unwrap();
        let canonical = serde_json::to_vec(&ExtResponse::ok(Dummy { n: 11 })).unwrap();
        let manual = wrap_ok_envelope(&inner);
        assert_eq!(
            canonical, manual,
            "wrap_ok_envelope has drifted from ExtResponse::Ok serialization"
        );
    }

    #[test]
    fn ok_envelope_roundtrip() {
        let env: ExtResponse<Dummy> = ExtResponse::ok(Dummy { n: 5 });
        let bytes = serde_json::to_vec(&env).unwrap();
        let parsed: ExtResponse<Dummy> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.status, Status::Ok);
        assert_eq!(parsed.data, Some(Dummy { n: 5 }));
    }
}
