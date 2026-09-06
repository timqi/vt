# Structured Errors over the vt Extension Protocol

Status: shipped. `src/core/wire.rs` owns the envelope schema and error taxonomy;
`src/client.rs` parses responses and classifies fallback; `src/main.rs` maps
propagated errors to process exit codes.

This reference covers the VT_AUTH-encrypted SSH-agent extensions. Structured
errors distinguish rejection, unavailable authentication, and request failures
without changing the SSH-agent transport. The Cloudflare Worker has a separate
protocol; switching to it is backend fallback, not wire compatibility.

## Wire format

The dispatcher in `src/server_macos/ssh_agent.rs` wraps these success payloads
in an envelope before encrypting the response details with the auth cipher:

| Extension | `data` type |
|-----------|-------------|
| `encrypt@vt` | `Vec<EncryptResItem>` |
| `decrypt@vt` | `Vec<DecryptResItem>` |
| `auth@vt` | `AuthRes` (`approved: true`) |
| `run@vt` | `RunRes` (spawned PID, not child output or exit status) |
| `sign@vt` | `SignRes` |
| `diag@vt` | `DiagRes` |

`ExtResponse<T>` and its flattened, `status`-tagged `ExtBody<T>` declare the
wire shape. For example:

```json
{"v":1,"status":"ok","data":{"approved":true}}
```

```json
{"v":1,"status":"err","kind":"auth_rejected","detail":"authentication was declined"}
```

- `v` is a `u16`; `WIRE_VERSION` is currently `1`. The client checks the
  version after envelope deserialization, before accepting either status.
- `kind` uses snake_case enum names. `detail` is optional and omitted on
  serialization when absent; deserialization also accepts `null` as absent.
- Unknown extra fields are ignored. Unknown `kind` values are accepted as
  `ErrKind::Unknown`; a missing `kind` on an error is a parse failure.
- `session-bind@openssh.com` and the token-gated `ui-status@vt` channel are
  plaintext exceptions dispatched before the lock/auth-cipher path. Neither
  uses this envelope. Standard SSH signing also retains SSH-agent wire errors.

Production success serialization uses `wrap_ok_envelope` around raw inner JSON,
not an intermediate `serde_json::Value`: DEK-bearing response buffers remain
under `Zeroizing`. Production errors use `ErrEnvelope` in the dispatcher.

### Versioning policy

- `ErrKind` is **append-only**. Renaming/removing a variant or breaking the
  envelope shape requires bumping `WIRE_VERSION`.
- An unknown `kind` deserializes to the `#[serde(other)]` sentinel
  `ErrKind::Unknown`, **not** `Generic`. Both exit with `1`, but their human
  messages differ. The unknown raw kind is not retained; optional `detail`
  remains available. The enum does not use Rust's `#[non_exhaustive]` attribute.
- The wire schema alone accepts any `u16` version. `parse_envelope` in
  `src/client.rs` rejects a parsed envelope with a mismatched version as
  `VtClientError::Agent(ErrKind::ProtocolVersion, None)`, even on `status: ok`.
  This exits `22` if propagated, but can trigger backend fallback (see below).

## Error taxonomy

`ErrKind` lives in cross-platform `src/core/wire.rs`. These codes apply when
the error reaches the CLI; a successful fallback does not exit with the
original agent error's code.

| Variant              | Meaning                                                      | Exit code |
|----------------------|--------------------------------------------------------------|-----------|
| `Ok`                 | success (not on the error enum, listed for completeness)     | 0         |
| `Generic`            | unclassified handler failure, including key-load/sign/spawn failures | 1  |
| `Unknown`            | unrecognized future wire `kind` value                       | 1         |
| `AuthRejected`       | user actively rejected Touch ID / FIDO2 / password           | 10        |
| `SessionLocked`      | screen locked or off-console (`UnavailableReason::NotInteractive`) | 11    |
| `NoGuiSession`       | no GUI session at all (LaunchDaemon-style context)           | 12        |
| `NotInitialized`     | handler cannot validate or load master-key material after auth-cipher derivation | 13 |
| `AgentLocked`        | reserved; `ssh-add -x` currently causes an unstructured failure | 14 |
| `BadRequest`         | malformed request, unknown v2 decrypt type, size/empty-batch checks, or run allowlist refusal | 20 |
| `LegacyDisabled`     | agent started with `--no-legacy-decrypt`                     | 21        |
| `ProtocolVersion`    | `v` mismatch between client and agent                        | 22        |
| `Transient`          | authorization invalidated; also the defensive invalidated-commit mapping | 75 |

`75` mirrors sysexits' `EX_TEMPFAIL`. `Transient` is currently emitted for
`Decision::Invalidated` by `authorization_failure_wire`, and for
`CommitError::Invalidated` by `commit_authorization`. It is not a reserved
file-lock/keychain-contention code. It does not guarantee that retrying a
non-idempotent operation is safe (see "Cache and side-effect invariants").

Per-item errors **inside successful batch envelopes** retain the wire
`err_message` strings. The client converts record results to `ItemResult`
(`Result<String, ItemError>`); per-record failures do not acquire an `ErrKind`.
Envelope errors fail the whole request, while an `ok` batch may contain partial
failure. Callers decide how to handle that batch; single-item command failures
default to exit `1`.

## Server-side mapping

`AuthOutcome` and `UnavailableReason` are defined in `src/core/session.rs`.
`outcome_to_err` in `src/core/wire.rs` maps rejection to `AuthRejected`,
`NotInteractive` to `SessionLocked`, and `NoGuiSession` to `NoGuiSession`;
success maps to `None`. `outcome_to_err_strict` keeps failure mapping
fail-closed. The agent's `authorization_failure_wire` maps engine decisions
using these kinds and static details. Locked/off-console and absent-GUI
outcomes deliberately stay distinct: one can recover when the session becomes
interactive, while the other needs a GUI session.

The operations in `src/server_macos/ssh_agent/handlers.rs` return
`HandlerSuccess` or `WireFailure`, a tuple of
`(ErrKind, Option<&'static str>)`. For example, `handle_decrypt` rejects an
unknown v2 type as `BadRequest`, and any legacy member under
`--no-legacy-decrypt` as `LegacyDisabled`, before authorization.

Not every failure can use the envelope:

1. **Agent lock (`ssh-add -x`)** returns `AgentError::Failure` before
   `KeychainStore::load` or cipher derivation. Keeping this ordering avoids
   keychain I/O just to report that a locked agent is locked. `AgentLocked`
   remains a reserved envelope kind, not the current lock response.
2. **Initial store load or `derive_passcode_ciphers` failure** is unstructured:
   there is no response cipher yet. A missing/unreadable store therefore does
   not necessarily yield `NotInitialized`; that kind is emitted by handlers
   only after cipher setup succeeds.
3. **Incoming auth-cipher decryption failure** (for example, wrong `VT_AUTH`)
   returns `AgentError::Failure`. The request is not authenticated; do not
   introduce a plaintext diagnostic/presence oracle for unauthenticated peers.
4. **Dispatcher error-envelope serialization or response-encryption failure**
   also propagates as an unstructured agent error.

The client represents SSH-wire failures as `VtClientError::Transport`, **not**
`Agent(Generic, ...)`. Both exit `1` if propagated. The transport path does
not automatically append an unlock hint. For a known `ssh-add -x` lock, the
operator remedy is `ssh-add -X`.

### `auth@vt` and forwarded sockets

`auth@vt` is used over forwarded sockets for remote sudo/PAM; it is not the
only forwarded extension. Response details stay encrypted end-to-end under
`VT_AUTH`, so the forwarding transport does not need that token.

Error `detail` must be **server-controlled static text, never PII or reflected
request data**: no host, command, reason, key fingerprint, or filesystem path.
The `DETAIL_*` constants in `src/server_macos/ssh_agent.rs` are the reviewed
allow-list, and `WireFailure`/`ErrEnvelope` require `Option<&'static str>`.
That type restricts construction; it is not a substitute for reviewing new
constants. The client appends any received detail verbatim in parentheses,
without a client-side allow-list check. This restriction concerns error
details, not operation-specific success payloads such as `DiagRes`.

## Client-side mapping

`try_agent_extension` decrypts response details into a `Zeroizing` buffer and
calls `parse_envelope`. The parser uses a flat `ParsedEnvelope` with borrowed
`&RawValue` data, not `ExtResponse<RawValue>`: serde flattening cannot preserve
the raw JSON span. Successful `data` is copied into another zeroizing buffer.

- `status: err` becomes `VtClientError::Agent(kind, detail)`.
- Malformed JSON, unknown status, missing success data or error kind, and
  socket/SSH/cipher failures become `VtClientError::Transport` (exit `1`).
- Missing/refused sockets return `Ok(None)` from the low-level call, leaving
  the routing layer to choose fallback or an unavailable-agent error.

`main` walks the error chain for `VtClientError`, uses its `exit_code`, and
defaults other failures to `1`. It prints the display chain to stderr; debug
logging retains the debug chain. Human messages come from
`ErrKind::human_message`, for example "vt: authentication rejected" and
"vt: agent returned an unknown error kind". Message text is for humans;
scripts should use exit codes.

## Compatibility and backend fallback

There is no decoder for the old bare success payloads. A pre-envelope response
fails envelope parsing with exit `1` if propagated; a parsed envelope with the
wrong `v` yields `ProtocolVersion` (exit `22`). Keep client and agent builds
aligned during upgrades. Same-version extra fields and unknown error kinds are
forward-compatible as described above; no runtime build-identity check exists.

Wire rejection does **not** prohibit trying a different backend:

- `agent_call_or_fallback` in `auto` mode treats typed transport failures and
  every agent kind except `AuthRejected` and `BadRequest` as fallback-eligible.
  This includes `ProtocolVersion`, `Unknown`, `LegacyDisabled`, and
  `Transient`. An untyped error is not fallback-eligible under
  `should_fallback_to_cf`.
- Rejection is terminal to respect the user's refusal. `BadRequest` is
  terminal because a second backend cannot repair the request. Eligible
  failures in encrypt/decrypt/auth route to the Worker, whose configuration
  and operation can still fail. The eventual command result determines the
  exit code; the original agent code is not preserved across fallback.
- `VT_BACKEND=agent` makes `agent_call_or_fallback` propagate agent errors
  and forbids Worker fallback. `VT_BACKEND=passkey` skips the agent.
- `sign_vt` uses the same error classification to signal local
  decrypt-then-sign fallback, even under an agent pin; the ensuing decrypt
  still obeys that pin. `run@vt` has no Worker implementation: an unavailable
  result from the shared routing helper becomes a command error, not a phone
  ceremony. `diag@vt` is an agent diagnostic, not a Worker operation.

## Cache and side-effect invariants

`src/core/authorization.rs` owns the permit and grant rules. The extension
dispatcher owns response encryption and permit commitment:

1. **Sign grants**: successful authorization returns a non-cloneable permit;
   only fresh approval under a reusable policy carries a pending grant.
   Raw signing or `sign@vt` failure drops the permit; only a successful
   signature (and, for extensions, encrypted response) consumes it with
   `commit()`. Operation, serialization, or encryption failure adds no grant.

2. **Decrypt grants**: pure-v2 batches use all-of lookup. A partial hit followed
   by rejection leaves existing entries untouched and adds none. For approvals
   eligible for reuse, the complete deduplicated scope set is committed only
   after successful response encryption. Any legacy member makes the entire
   request fresh.

3. **Strict TTL**: committing an equal or wider policy never extends a
   still-valid grant. A shorter policy cannot reuse a wider grant and replaces
   it only after a fresh successful approval.

4. **Lock state**: agent lock is checked before deriving the auth cipher or
   showing a prompt, so it remains an unstructured SSH-agent failure and can
   neither consume nor create a grant. Live security validation failure revokes
   existing grants; this differs from an ordinary user rejection, which adds
   none but does not itself revoke existing entries.

`auth@vt` and `run@vt` always use fresh authorization and never create reusable
grants. A live permit blocks revocation; cache-hit notifications run only after
commit releases it. See [unified-authorization-engine.md](unified-authorization-engine.md)
and [authorization-scopes-v2.md](authorization-scopes-v2.md) for scope policy.

Grant commitment is not transactional rollback of the operation: `run@vt`
spawns before serialization/encryption, so a failed reply can follow a completed
spawn. The dispatcher's invalidated-commit response is defensive today because
the live permit blocks epoch advancement. Neither that protection nor an error
exit provides an exactly-once guarantee for client retries.

## Tests covering the contract

The following are existing cross-platform tests; none needs a keychain or a
running native agent. Names below are functions in each file's `tests` module.

### Wire schema: `src/core/wire.rs`

| Tests | Coverage |
|-------|----------|
| `roundtrip_all_kinds`, `exit_code_table` | Named error kinds round-trip; every exit code, including `Unknown`, matches the table. The round-trip set excludes `Unknown`. |
| `unknown_kind_deserializes_to_unknown_then_generic_exit` | Future kind becomes `Unknown`, retains detail, exits `1`. |
| `version_mismatch_is_detected_by_client_policy` | Schema preserves a mismatched `v`; this test only compares it with `WIRE_VERSION`, not client rejection. |
| `outcome_to_err_table`, `outcome_to_err_strict_never_returns_none_for_failure` | Auth outcome mapping and fail-closed failure mapping. These tests live here, not in `session.rs`. |
| `ok_body_with_unknown_future_field`, `err_body_missing_kind_field_is_parse_error` | Schema accepts extra fields but rejects absent error kind. |
| `detail_none_roundtrip_skips_field` | Absent detail is omitted, then round-trips as `None`. |
| `wrap_ok_envelope_matches_ext_response_schema`, `ok_envelope_roundtrip` | Production success wrapper matches the declared schema; success data round-trips. |

### Client parser and routing: `src/client.rs`

| Tests | Coverage |
|-------|----------|
| `parse_envelope_ok_with_array_data`, `parse_envelope_ok_with_object_data` | Production parser accepts wrapped batch/auth data without the flatten/RawValue regression. |
| `parse_envelope_err_auth_rejected_maps_to_exit_10`, `parse_envelope_err_without_detail` | Typed rejection/exit `10` and optional detail. |
| `parse_envelope_version_mismatch` | Production parser rejects a wrong-version success as `ProtocolVersion`. |
| `parse_envelope_unknown_future_kind_falls_back_to_unknown`, `parse_envelope_garbage_is_transport_error` | Unknown kind becomes `Unknown`/exit `1`; garbage is `Transport`. |
| `vt_client_error_display_appends_detail_when_present` | Display appends detail only when present. |
| `fallback_policy_auth_rejected_does_not_fall_back`, `fallback_policy_bad_request_does_not_fall_back` | Terminal errors prohibit fallback. |
| `fallback_policy_session_locked_falls_back`, `fallback_policy_other_agent_kinds_fall_back`, `fallback_policy_transport_falls_back` | Eligible typed errors permit fallback. These classify errors, not a live Worker ceremony. |

The missing-kind and extra-field schema tests do not exercise the production
client parser. There are no dedicated production-parser tests for missing
`kind`/`data` or unknown `status`; the branches are implementation checks,
not coverage supplied by the wire-schema tests. Unit exit-code assertions
also do not verify an actual CLI process exit through a native agent.

### Session and grant behavior

In `src/core/session.rs`, `classify_no_dict_is_no_session`,
`classify_locked_is_not_interactive`, `classify_off_console_is_not_interactive`,
and `classify_login_pending_is_not_interactive` test pure session inputs;
`auth_outcome_is_success` tests outcome classification. They do not exercise
macOS session APIs or a native authentication prompt.

In `src/core/authorization.rs`, `grant_is_written_only_after_operation_commits_permit`,
`rejection_and_unavailable_never_grant`,
`rejected_partial_batch_preserves_existing_grants_and_adds_none`,
`strict_ttl_does_not_slide`, `ttl_policy_tightening_requires_fresh_approval`, and
`prompt_unavailable_revokes_preexisting_grants` cover the engine rules above.
They do not drive dispatcher encryption failures or real signing/decrypt work.

Run these focused suites from the repository root:

```bash
cargo test --bin vt core::wire::tests
cargo test --bin vt client::tests
cargo test --bin vt core::session::tests
cargo test --bin vt core::authorization::tests
```

### Native verification gaps

The end-to-end error scenarios below are **not automated**: no agent integration
tests implementing them exist, including as ignored tests. `--ignored` does
not run this checklist. They require an initialized native macOS agent and
manual verification; use `VT_BACKEND=agent` to observe the agent's exit code
without backend fallback masking it.

| Manual scenario | Expected result; remaining requirement |
|-----------------|----------------------------------------|
| Reject an `auth@vt` prompt | `AuthRejected`, exit `10`; requires a real human rejection, not a programmatic-denial test. |
| Lock with `ssh-add -x`, then call the agent | Unstructured SSH failure, client `Transport`, exit `1`; unlock afterward with `ssh-add -X`. No automatic hint is guaranteed. |
| Send legacy decrypt input under `--no-legacy-decrypt` | `LegacyDisabled`, exit `21`, before prompting. |
| Send an unknown v2 decrypt type | `BadRequest`, exit `20`, before prompting; requires a crafted authenticated request, not an ordinary CLI URL. |
| Call `auth@vt` while screen-locked/off-console or without a GUI session | `SessionLocked`/`NoGuiSession`, exits `11`/`12`; pure classifier tests do not establish native behavior. |
| Wrong `VT_AUTH` or initial store/cipher setup failure | Unstructured failure, exit `1`; no structured-detail disclosure to an unauthenticated caller. |

Native checks are separate from the focused suites above. Existing ignored
biometric/keychain helper tests are not end-to-end error-contract tests and
must not be presented as this coverage.
