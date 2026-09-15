# Extension errors and fallback

Structured extension errors let callers distinguish refusal, unavailable
authentication, and invalid requests while preserving stable process exit codes.
The Worker has a separate wire protocol.

## Envelope contract

SSH-agent VT extensions use a versioned, plaintext JSON `ExtResponse` envelope.
[src/core/wire.rs](../src/core/wire.rs) is the schema and error declaration;
do not maintain a second type definition here.

- Successful responses require data; errors require a kind. Malformed responses
  are transport failures, never successful empty results.
- Unknown extra fields are accepted. Unknown error kinds stay distinguishable
  from known generic failures; mismatched protocol versions are rejected.
- Error kinds are append-only within a wire version; incompatible envelope or
  kind changes require a version bump.
- Error detail is static server-controlled text, never reflected hostnames,
  commands, reasons, paths, fingerprints, or other client data.
- `session-bind@openssh.com`, `ui-status@vt`, and standard SSH signing use their
  own SSH-wire responses, not this envelope.

## Exit codes

These codes apply when the error reaches the CLI. A successful fallback replaces
the original failure; scripts must not interpret human-readable messages.

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic, unknown, transport, or otherwise unclassified failure |
| 10 | Human rejected authentication |
| 11 | Session locked or off-console |
| 12 | No GUI session |
| 13 | Handler cannot validate/load master-key material |
| 14 | Reserved agent-lock kind; not the current `ssh-add -x` response |
| 20 | Bad request, including allowlist refusal |
| 21 | Retired; never reuse |
| 22 | Protocol version mismatch |
| 75 | Authorization invalidated; retry is not an exactly-once guarantee |

Agent lock and initial Keychain/wrap failures precede handler dispatch and
return unstructured SSH failures, normally exit 1. A missing store therefore
does not necessarily produce 13. For a known `ssh-add -x` lock, unlock using
`ssh-add -X`.

Envelope errors fail the request. An otherwise successful batch may contain
per-record failures; these do not acquire an envelope error kind. Invalid local
records retain their input position and never become a wire request.

## Backend fallback

| Failure | Automatic fallback eligibility |
|---|---|
| `AuthRejected`, `BadRequest` | Never: preserve refusal and reject invalid input |
| Other typed agent errors, including version mismatch and invalidation | Eligible |
| Typed socket/SSH transport failure | Eligible |
| Unclassified client error | Not eligible |

Eligibility is not proof that no prompt or side effect occurred. An operation
may fail after approval, and fallback can require another approval.

- `auto` may try the Worker for eligible failures; Worker configuration and
  authorization must still succeed.
- `agent` prohibits Worker fallback; `passkey` skips the agent for protected
  operations.
- SSH decrypt-then-sign fallback also requires a portable record and obeys the
  backend pin; see [sign-vt-design.md](sign-vt-design.md).
- `run@vt` has no Worker implementation. `diag@vt` reports findings without
  using operation fallback; see [doctor](../README.md#diagnostics).

## Effects and retries

A reusable grant commits only after operation success and envelope serialization.
Failure adds no grant; partial decrypt-cache hits followed by rejection retain
existing grants. The full commitment and revocation contract belongs to
[unified-authorization-engine.md](unified-authorization-engine.md).

Grant commitment is not transactional rollback: a child may have spawned before
a reply fails. Neither exit 75 nor transport failure makes retrying a
non-idempotent operation safe.

Client parsing and fallback tests live in [src/client.rs](../src/client.rs).
Native lock/GUI/Keychain behavior requires macOS validation; unit tests do not
establish those operating-system outcomes.
