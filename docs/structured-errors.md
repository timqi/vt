# Structured Errors over the vt Extension Protocol

Status: shipped — `ExtResponse`/`ErrKind` in `src/core/wire.rs`, `VtClientError`
downcast + exit-code mapping in `src/client.rs` (with tests).

This is the current protocol reference. The rollout plan, resolved review
questions, and original questions near the end are historical notes; they are
not pending implementation work.

## Background (historical)

Today the only failure signal a client sees from `vt ssh agent` is `SSH_AGENT_FAILURE` (the bare 0x05 byte from `ssh-agent-lib`). Inside the agent we already distinguish:

- `AuthOutcome::Rejected` — user said no
- `AuthOutcome::Unavailable(NotInteractive)` — screen locked / off-console
- `AuthOutcome::Unavailable(NoGuiSession)` — no GUI session (LaunchDaemon)
- Lock state (`ssh-add -x`)
- Decryption / parse / VT_AUTH mismatch
- `SecretType::UNKNOWN` rejection
- Disabled legacy decrypt

…but all of it collapses to `AgentError::Failure` on the way out. The user sees `Command failed: SSH agent extension failed: SSH agent failure` and a process exit code of `1`. Scripts, PAM modules, and humans all read the same opaque message.

The shipped design is a structured, append-only error payload inside the
auth-cipher-encrypted extension response, mapped to stable exit codes on the
client.

## Non-goals

- We are **not** changing the SSH-agent transport. The wire bytes between client and agent remain extension request → extension response, both opaque to anyone without `VT_AUTH`.
- We are **not** trying to be backwards compatible with old clients. `vt` ships as a single binary; client and agent come from the same build. We bump a version field and require a matching agent.
- We are **not** introducing HTTP, gRPC, or any second transport.

## Wire format

Every successful extension response today is the auth-cipher encryption of a single JSON value:

```
encrypt@vt → Vec<EncryptResItem>
decrypt@vt → Vec<DecryptResItem>
auth@vt    → AuthRes { approved: bool }
```

We move every extension to a single envelope:

```rust
#[derive(Serialize, Deserialize)]
pub struct ExtResponse<T> {
    /// Protocol version. Bump on any breaking change to ErrKind.
    pub v: u16,
    #[serde(flatten)]
    pub body: ExtBody<T>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExtBody<T> {
    Ok { data: T },
    Err { kind: ErrKind, detail: Option<String> },
}
```

- `v` starts at `1`. The client checks `v == WIRE_VERSION` (the constant in
  `src/core/wire.rs`) and refuses anything else.
- `detail` is **optional, server-controlled, never contains PII or user-supplied strings**. The agent populates it only with static `&'static str`s describing the failure in a way that's safe to log on remote machines. Specifically: never reflect `req.host`, `req.reason`, `req.command`, key fingerprints, or filesystem paths. The client may surface `detail` verbatim.
- The enum is `#[non_exhaustive]` on the client side via serde default-case (see "Forwards compatibility" below).

### Versioning policy

- `ErrKind` is **append-only**. Renaming or removing a variant requires bumping `v`.
- Older clients seeing an unknown `kind` MUST treat it as `ErrKind::Generic`
  (exit code `1`). This is implemented with a `#[serde(other)] Unknown`
  variant; the raw value is not surfaced as user-facing detail.
- A wrong `v` is itself a hard error: `ErrKind::ProtocolVersion` with the client's exit `22` (see exit-code table below).

## Error taxonomy

`ErrKind` lives in `core::wire` (cross-platform) so the Linux client surface compiles. Variants:

| Variant              | Meaning                                                      | Exit code |
|----------------------|--------------------------------------------------------------|-----------|
| `Ok`                 | success (not on the error enum, listed for completeness)     | 0         |
| `Generic`            | unclassified server error (default for unknown future kinds) | 1         |
| `AuthRejected`       | user actively rejected Touch ID / FIDO2 / password           | 10        |
| `SessionLocked`      | screen locked or off-console (`UnavailableReason::NotInteractive`) | 11    |
| `NoGuiSession`       | no GUI session at all (LaunchDaemon-style context)           | 12        |
| `NotInitialized`     | `vt init` has not been run, or store unreadable              | 13        |
| `AgentLocked`        | agent is locked via `ssh-add -x` (not emitted in envelope — see § "Server-side mapping"; reserved for future use) | 14 |
| `BadRequest`         | request JSON malformed, `SecretType::UNKNOWN` v2, etc.       | 20        |
| `LegacyDisabled`     | agent started with `--no-legacy-decrypt`                     | 21        |
| `ProtocolVersion`    | `v` mismatch between client and agent                        | 22        |
| `Transient`          | retryable (file lock contention, keychain transient)         | 75        |

(75 mirrors sysexits' `EX_TEMPFAIL`, kept as the only "high" code so scripts can `if [ $? -eq 75 ]; then sleep; retry; fi`.)

Per-item errors **inside batch responses** (`Vec<EncryptResItem>` / `Vec<DecryptResItem>`) keep their existing `err_message` field. The new envelope errors only fire for batch-level failures (auth denied, lock, malformed request). This preserves the partial-success semantics of batch decrypt.

## Server-side mapping

The following is simplified pseudocode. The real implementation keeps the
successful DEK payload on a raw-JSON path so it can preserve zeroization
properties; see `wrap_ok_envelope` in `src/core/wire.rs`.

In `src/server_macos/ssh_agent.rs`:

```rust
fn outcome_to_err(o: AuthOutcome) -> Option<ErrKind> {
    match o {
        AuthOutcome::Success(_) => None,
        AuthOutcome::Rejected => Some(ErrKind::AuthRejected),
        AuthOutcome::Unavailable(UnavailableReason::NotInteractive) => Some(ErrKind::SessionLocked),
        AuthOutcome::Unavailable(UnavailableReason::NoGuiSession) => Some(ErrKind::NoGuiSession),
    }
}
```

The `extension` handler becomes:

```rust
async fn extension(&mut self, ext: Extension) -> Result<Option<Extension>, AgentError> {
    // ... lock check, vt-extension filter, decrypt with auth_cipher ...
    let body = match self.dispatch(&ext.name, decrypted_payload).await {
        Ok(bytes)             => ExtBody::Ok { data_raw: bytes },
        Err(WireFail(kind, d)) => ExtBody::Err { kind, detail: d },
    };
    let envelope = ExtResponse { v: WIRE_VERSION, body };
    let encrypted = auth_cipher.encrypt(&serde_json::to_vec(&envelope)?)?;
    Ok(Some(Extension { name: ext.name, details: Unparsed::from(encrypted) }))
}
```

The agent only returns `AgentError` for cases the SSH agent transport itself cannot recover from. Two are intentionally kept as unstructured `AgentError::Failure`:

1. **`auth_cipher` decryption failure on the incoming payload.** Without `VT_AUTH` we have no key to encrypt a structured response with, and an unencrypted envelope would be a presence oracle ("is this socket a vt agent?"). The marginal "wrong VT_AUTH vs agent crashed" distinguishability for the legitimate caller is not worth the leak.

2. **`AgentLocked` (`ssh-add -x` lock).** The lock check fires *before* `KeychainStore::load()` and `derive_passcode_ciphers()` in the SSH-agent extension dispatcher. Returning a structured error here would force us to run keychain I/O for every locked request just to derive the cipher to encrypt the envelope. The cost is small but the behavioral change is real. We keep `AgentLocked` as `AgentError::Failure`; client maps SSH-wire failure with no parseable envelope to `ErrKind::Generic` (exit 1) and prints a hint to try `ssh-add -X`.

All other vt-level failures travel inside the envelope.

`detail` is filled by a small allow-list of static strings:

```rust
const DETAIL_LOCK_VIA_SSHADD_X: &str = "agent is locked (`ssh-add -x`); unlock with `ssh-add -X`";
const DETAIL_SCREEN_LOCKED:     &str = "screen is locked";
const DETAIL_NO_GUI:            &str = "no active GUI session";
// ... etc.
```

User-supplied strings never enter `detail`.

### `auth@vt` and forwarded sockets

`auth@vt` is the one extension routinely called over forwarded agent sockets (remote sudo via PAM). The forwarded peer cannot distinguish a tunneled call from a local one. **The structured error itself is safe to forward** because:

1. `kind` is a finite enum from a closed set already documented in this file.
2. `detail` is server-controlled static text from the allow-list above, identical to what already appears in the agent's local log.

No new information leaks across the tunnel compared to today's `tracing::warn!` logs. The reason a remote attacker could exploit this is the same reason a local user can: they're holding `VT_AUTH`. If `VT_AUTH` leaks, structured errors are not the marginal risk.

## Client-side mapping

`src/client.rs` grows a typed error so callers can match on kind:

```rust
#[derive(Debug)]
pub enum VtClientError {
    Agent(ErrKind, Option<String>),
    Transport(anyhow::Error),  // socket missing, IO errors, etc.
}

impl VtClientError {
    pub fn exit_code(&self) -> i32 {
        match self {
            VtClientError::Agent(k, _) => k.exit_code(),
            VtClientError::Transport(_) => 1,
        }
    }
}
```

`try_agent_extension` parses `ExtResponse<RawJson>`; if `Err { kind, detail }`, returns `VtClientError::Agent(kind, detail)`. `main.rs::main` becomes:

```rust
if let Err(e) = run(cli).await {
    let code = e.downcast_ref::<VtClientError>().map(|v| v.exit_code()).unwrap_or(1);
    tracing::error!("Command failed: {:?}", e);
    std::process::exit(code);
}
```

Human-readable messages: client maps `ErrKind` → a one-line message (so users don't see `AuthRejected` as raw text). Examples:
- `AuthRejected` → "vt: authentication rejected"
- `SessionLocked` → "vt: screen is locked"
- `NoGuiSession` → "vt: no GUI session (cannot prompt for Touch ID)"
- `AgentLocked` → "vt: agent is locked — unlock with `ssh-add -X`"

If `detail` is present and on the allow-list, append it as `(<detail>)`.

## Cache and side-effect invariants

Failure responses must not leave caches partially populated:

1. **Sign grants**: a successful engine decision returns a non-cloneable
   permit with a pending grant. Raw signing or `sign@vt` failure drops the
   permit; only a successful signature (and, for extensions, encrypted
   response) consumes it with `commit()`.

2. **Decrypt grants**: pure-v2 batches use all-of lookup. A partial hit followed
   by rejection leaves existing entries untouched and adds none; successful
   response encryption commits the complete deduplicated scope set. Any legacy
   member makes the entire request fresh.

3. **Strict TTL**: committing an equal or wider policy never extends a
   still-valid grant. A shorter policy cannot reuse a wider grant and replaces
   it only after a fresh successful approval.

4. **Lock state**: agent lock is checked before deriving the auth cipher or
   showing a prompt, so it remains an unstructured SSH-agent failure and can
   neither consume nor create a grant.

## What can break

- **Cross-version mismatch**: someone runs an old `vt` client against a new agent (or vice versa). Mitigation: hard-fail on `v` mismatch with `ErrKind::ProtocolVersion`. We do **not** silently degrade. Document in CHANGELOG that the client/agent binaries must match.
- **`detail` accidentally containing user data**: easy to regress. Mitigation: `detail` field type is `&'static str` at the construction site; we use an `enum WireFail { kind, detail: Option<&'static str> }` internally and the JSON serializer turns the static into an owned `String` only at the JSON layer. Anything dynamic forces a compile error.
- **Forwarded-socket leak**: see § "auth@vt and forwarded sockets". No regression vs today's logs.
- **Cache poisoning via error path**: ruled out by the engine's pending-grant
  permit. Rejection, unavailable state, operation failure, serialization
  failure, and response-encryption failure all drop without commit.
- **Test surface bloat**: every kind needs a pure unit test. The current suite
  covers wire round-trips, `AuthOutcome` mapping, exit-code mapping, unknown
  future kinds, version mismatches, and malformed envelopes without requiring a
  running agent.

## Tests covering the contract

Pure unit tests (no keychain, no agent):

1. **`wire::roundtrip_all_kinds`** — for each `ErrKind`, serialize an `ExtResponse::Err { kind, detail: Some("x") }`, deserialize, assert equality.
2. **`wire::exit_code_table`** — `ErrKind::*.exit_code()` matches the table in this doc.
3. **`wire::unknown_kind_deserializes_to_generic`** — `{"v":1,"status":"err","kind":"future_kind"}` → `ErrKind::Generic` on the client.
4. **`wire::version_mismatch_is_protocol_version`** — `{"v":99,"status":"ok","data":{}}` → `ErrKind::ProtocolVersion` (client policy: refuse `v != 1` even on `ok`).
5. **`session::outcome_to_kind`** — `AuthOutcome::Rejected` → `AuthRejected`, `Unavailable(NotInteractive)` → `SessionLocked`, etc.
6. **`wire::ok_body_with_unknown_future_field`** — future agent sends `{"v":1,"status":"ok","data":{...},"new_field":1}`; client ignores unknown fields and parses `data` correctly. Confirms we do NOT use `#[serde(deny_unknown_fields)]`.
7. **`wire::err_body_missing_kind_field`** — malformed `{"v":1,"status":"err"}`. Client returns a parse error (no panic). Default-to-`Generic` only applies to unknown *values* of `kind`, not absent fields.
8. **`wire::detail_none_roundtrip`** — `detail: None` serializes as an absent field, not `"detail":null`. Locks in `#[serde(skip_serializing_if = "Option::is_none")]`.

Integration (gated on `--ignored`, needs agent):

9. **`agent_returns_auth_rejected_on_reject`** — programmatically deny Touch ID, observe `ErrKind::AuthRejected` in client.
10. **`agent_locked_returns_generic_via_wire_failure`** — `ssh-add -x` then `vt read`. Today the lock check pre-empts envelope generation, so this surfaces as the unstructured SSH-wire failure → exit 1 with the hint message.
11. **`agent_legacy_disabled_returns_legacy_disabled`** — start agent with `--no-legacy-decrypt`, send a legacy URL, observe `ErrKind::LegacyDisabled` and exit code `21`.
12. **`agent_unknown_secret_type_returns_bad_request`** — send a v2 decrypt
    input with an unknown type, observe `ErrKind::BadRequest` rather than a
    generic agent failure.

## Historical rollout record

Single PR, since this is one binary:

1. Add `core::wire` module with `ExtResponse`, `ErrKind`, `WIRE_VERSION = 1`, exit-code table, serde unknown-kind handling. Pure tests.
2. Convert all three extension arms in `ssh_agent.rs` to return `ExtResponse`. Remove `AgentError::Failure` returns except for transport-level cases (lock state read failure, auth-cipher decrypt failure of the incoming payload).
3. Convert `client.rs::try_agent_extension` to parse `ExtResponse`. Add `VtClientError`. Wire exit codes through `main.rs`.
4. The final implementation places `outcome_to_err` in `src/core/wire.rs` so
   the mapping remains cross-platform.
5. Add ignored integration tests. Update CHANGELOG.

## Compatibility notes

- **Breaking**: client and agent binaries must match versions. An older client running against a newer agent will see `failed to parse response` (its `serde_json::from_slice::<Vec<_>>` chokes on the new envelope) and exit 1. Document the upgrade order: stop the agent, install the new binary, restart the agent, then upgrade clients on the same machine. There is no graceful fallback path.

## Historical decisions

(Resolved during codex-expert review — keeping here for the PR record.)

1. **`SessionLocked` vs `NoGuiSession`**: keep two distinct exit codes (11 / 12). PAM consumers can retry-later on locked, hard-fail on no-GUI.
2. **`detail` on `auth@vt`**: yes, keep it. Forwarded peer already holds `VT_AUTH` so it can decrypt anything; static-string allow-list prevents dynamic leakage. PAM gets a one-line reason.
3. **`Transient` variant**: defer. No current caller surfaces flock contention as an error; add when `KeychainStore::try_modify` becomes a request path.
4. **Per-item batch errors**: defer. Inner `err_message` stays free-form text — only our own client reads it, scripts branch on the envelope-level exit code.

## Historical open questions

1. **`SessionLocked` vs `NoGuiSession` distinction**: worth two separate exit codes (11/12) or fold into one? Argument for two: PAM modules can retry-later on `Locked` (screen will unlock eventually) but should hard-fail on `NoGuiSession` (LaunchDaemon won't ever get a GUI). Recommend keep separate.
2. **Should `detail` exist at all on `auth@vt`?** Conservative read says yes — see § "auth@vt and forwarded sockets" for why I believe it's safe. Reviewer's call.
3. **`Transient` for keychain flock contention**: do we actually have a path that would benefit from a retry exit code today? Currently `KeychainStore::modify` blocks on flock — it doesn't return contention as an error. We could add `Transient` now and keep it unused, or defer until there's a caller. Recommend defer.
4. **Per-item batch errors**: the inner `err_message` strings on `EncryptResItem` / `DecryptResItem` stay as free-form text. Do we want to upgrade those to `ErrKind` too? Recommend defer — they're parsed only by our own client which already treats them as opaque.
