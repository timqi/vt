# `sign@vt`: agent signing, identity routing, and fallback

This document owns the current `sign@vt` contract used by `vt ssh connect`.
The implementation is in `src/ssh_sign.rs`, `src/client.rs`, `src/core.rs`,
`src/server_macos/ssh_agent.rs`, and `src/server_macos/ssh_agent/handlers.rs`.
The filename is retained for existing links; implementation history is in Git.

## 1. Signing paths and key residency

`vt ssh connect` runs system SSH through an ephemeral signer that advertises
configured or discovered public keys and adds VT context to signing requests.
It supports two paths:

- **Agent signing:** `sign@vt` selects an existing Keychain-backed key by its
  public-key fingerprint and signs inside the macOS agent. Only the signature
  crosses back to the caller; no private key or portable record is required.
- **Decrypt-then-sign:** when the agent path returns an eligible fallback and
  that identity has a `vt://` record, the client decrypts the Ed25519 seed and
  signs locally. The decrypt operation uses the configured agent/Worker route.

Standard SSH `SIGN_REQUEST` remains supported alongside `sign@vt`. The same
Keychain key is reachable through it without VT_AUTH or client-supplied VT
context, subject to the agent's authorization engine. Rich VT context is
best-effort, not a property enforced on every use of that key.

Keychain-backed and portable identities can be provisioned separately per host
(section 5). This is an operational choice, not a protocol prohibition on
having both representations: an explicit public key can carry an optional
portable record even when the agent also holds that key.

## 2. Identity resolution and SSH integration

`resolve_identities` in `src/ssh_sign.rs` resolves before spawning SSH:

1. A non-empty `VT_GIT_SSH_PUB` value, otherwise `~/.config/vt/git-ssh.pub`,
   selects exactly one explicit OpenSSH public key. It takes precedence over
   discovery and can be paired with a portable record.
2. With no explicit public key, an agent-enabled client discovers **all**
   upstream identities via `VTClient::list_agent_identities`. Each discovered
   identity has no portable record and must sign through `sign@vt` or fail.
3. With no usable source, connect fails before spawning system SSH. Discovery
   errors are fatal; it does not manufacture a public key from a private record.

`load_private_record_opt` reads non-empty `VT_GIT_SSH_PRIVATE_KEY` first, then
`~/.config/vt/git-ssh`. Missing default files mean `None`; other I/O errors are
fatal. A present value must start with `vt://`, with complete record validation
left to decrypt. This loader runs for the explicit-public-key branch, not
discovered identities. A private-record environment value without a public key
produces a warning before discovery; a record alone is not an identity source.
Malformed explicit public keys are errors, not a reason to discover other keys.

Agent-enabled means the resolved route uses the agent and has VT_AUTH; a
`VT_BACKEND=passkey` pin skips discovery and `sign@vt`, even with VT_AUTH set.
See `ResolvedConfig` in `src/config/client.rs` for transport selection.
The upstream socket is `SSH_AUTH_SOCK` when set, otherwise `~/.ssh/vt.sock`.

The ephemeral socket lives in a private mode-0700 directory and is mode 0600.
The child receives both `SSH_AUTH_SOCK` and a leading
`-o IdentityAgent=<ephemeral socket>`, so an SSH config `IdentityAgent` cannot
bypass the signer. The parent environment remains unchanged, avoiding a
self-connection when the signer calls the upstream agent. `request_identities`
advertises the entire resolved set; signing refuses keys outside that set.
The public key sent in `sign@vt` is the SSH wire encoding of the selected
advertised `KeyData`, not a separately constructed fingerprint string.

With `--forward-real-agent`, a leading `-o ForwardAgent=<ephemeral socket>`
also pins which socket is forwarded. The extension relay permits exactly
`encrypt@vt`, `decrypt@vt`, `auth@vt`, `sign@vt`, and read-only `diag@vt`;
it refuses `run@vt`, `ui-status@vt`, `session-bind@openssh.com`, and unknown
extensions. It routes opaque authenticated payloads without using VT_AUTH to
decrypt them. Without the flag it refuses all extensions. This filter does not
hide unadvertised upstream keys from an authenticated `sign@vt` request: its
encrypted payload can name any upstream key, and the upstream agent authorizes
that request. See [authorization-scopes-v2.md](authorization-scopes-v2.md) for
connection confinement and [approval-transparency.md](approval-transparency.md)
for relay/key disclosure in prompts.

## 3. Wire and agent authorization

`SignReq` / `SignRes` in `src/core.rs` are cross-platform JSON types carried
inside the standard VT_AUTH-encrypted extension protocol:

| Type | Fields |
|---|---|
| `SignReq` | `host`, `command`, `pubkey`, `data`, `flags` (default 0), `meta` (default empty) |
| `SignRes` | `algorithm`, `signature` |

Byte vectors use JSON number arrays. `pubkey` is SSH wire-encoded public
`KeyData`; `data` is the SSH request's bytes to sign. `flags` selects RSA SHA-2
behavior; Ed25519 and ECDSA do not use it. Responses are algorithm-tagged rather
than assuming Ed25519. The shared `sign_data_with_privkey` core supports
Ed25519, RSA-SHA2, and ECDSA P-256/P-384. Do not rely on legacy SHA-1 `ssh-rsa`
success with the current `ssh-key` dependency; the RSA regression tests
explicitly cover SHA-2.

The dispatcher recognizes `EXT_SIGN` both in its extension allowlist and its
handler match. After the lock/Keychain/VT_AUTH checks, `handle_sign_vt`:

1. Parses JSON, enforces `PROMPT_DISPLAY_MAX_BYTES` on command text, decodes
   the public key, and computes `fingerprint_str` with the same function used
   for stored keys.
2. Calls `ensure_keys_loaded` and selects that key from the in-memory map.
   A missing key returns `Generic` with `DETAIL_SIGN_KEY_NOT_IN_AGENT`; a bad
   public key returns `BadRequest` with `DETAIL_SIGN_BAD_PUBKEY`.
3. Builds the sanitized prompt and requests an `Operation::Sign` permit.
   Agent-derived relay, caller, key comment/fingerprint, and reusable-scope
   lines precede the client-reported command body and metadata.
4. Signs and serializes the result while holding the permit. The dispatcher
   encrypts the success envelope before committing the permit; failure adds
   no grant. Cache-hit notification is post-commit only.

The sign TTL is opt-in via `--ssh-auth-cache-duration` or `[agent]` defaults;
`0` means Fresh. Local `sign@vt` scopes follow kernel-derived workspace, cwd,
or parent-app classification, while relay/plain-SSH peers remain connection-
confined. Raw SSH signing can instead use a verified session-bind destination.
Sharing `Operation::Sign` does not merge those families. Exact scope rules
belong to [authorization-scopes-v2.md](authorization-scopes-v2.md), and permit,
dual-clock TTL, prompt serialization, and revocation semantics belong to
[unified-authorization-engine.md](unified-authorization-engine.md).

## 4. Fallback contract and security differences

`VTClient::sign_vt` returns `Some((algorithm, signature))`, `None` for an
eligible fallback, or an error. `decide_sign_route` then uses the identity's
portable-record availability:

| Agent/client outcome | Connect action |
|---|---|
| Valid decoded signature response | Use the agent signature |
| No agent route, missing/refused socket, unsupported extension | Decrypt-then-sign only if a record exists |
| `Generic` (including missing key), `SessionLocked`, `NoGuiSession`, `NotInitialized` | Same eligible fallback |
| Other agent errors except the two refusals below, or classified transport failure | Same eligible fallback |
| `AuthRejected` or `BadRequest` | Fail; never decrypt as a retry |
| Other unclassified client error, including malformed `SignRes` | Fail |
| Eligible fallback but no portable record | Fail with an actionable missing-key/record message |

The classification is `should_fallback_to_cf` in `src/client.rs`, also used by
the normal transport router. **It is error-kind-based, not proof that no prompt
occurred.** `handle_sign_vt` can return `Generic` after approval if signing or
serialization fails; authorization invalidation returns `Transient`. Both are
fallback-eligible. Thus an explicit rejection is never retried, but there is
no general "post-prompt failures never fall back" or "no second prompt"
guarantee. The [structured error contract](structured-errors.md) owns the
complete taxonomy and pre-cipher failure behavior.

An eligible fallback decrypts through the **same configured client**:
`VT_BACKEND=agent` still forbids Worker fallback, and `VT_BACKEND=passkey`
skips the signing-agent probe. `auto` can use agent decrypt or the Worker.
No record means no fallback regardless of transport availability.

Portable signing decodes a base64url-no-padding 32-byte Ed25519 seed and keeps
it in a per-identity `OnceCell<Zeroizing<[u8; 32]>>` for the connect process.
Successful decrypt is reused for later signatures in that process; failed
initialization is not cached. This is **not** the agent sign-grant TTL:
subsequent local signatures need no further agent authorization, and revoking
an agent grant does not erase an already-decrypted seed in a remote process.
The seed is not written to disk by connect. The fallback assumes the configured
portable record matches the advertised public key; connect does not separately
compare the seed's derived public key, so mismatched files fail SSH authentication.

Keeping a key in the Mac agent avoids exporting its seed into caller/remote
RAM. It is still ordinary decrypted key material in agent memory, not a Secure
Enclave signing key or a claim of hardware non-exportability. Directly
forwarding the real agent with `ssh -A` exposes standard context-free signing
and a broader extension surface than the filtering relay. Do not treat
client-claimed `host`, `command`, or `ClientMeta` as verified provenance, nor
assume `sign@vt` context is mandatory for all uses of the same key.

## 5. Provisioning and use

Configure Git to invoke the current driver:

```bash
git config --global core.sshCommand "vt ssh connect"
```

**macOS, Keychain-backed identity:** `vt ssh add -f <file>` imports an OpenSSH
private key into VT's encrypted `rusty.vault.store` Keychain item. It is not
the SSH credential facility configured by `ssh-add --apple-use-keychain`.
With the agent initialized/running and VT_AUTH configured:

```bash
ssh-keygen -t ed25519 -f /tmp/vt-git -C "git@$(hostname -s)" -N ""
vt ssh add -f /tmp/vt-git
mkdir -p ~/.config/vt
install -m 0644 /tmp/vt-git.pub ~/.config/vt/git-ssh.pub
rm -P /tmp/vt-git
# Enroll ~/.config/vt/git-ssh.pub with the provider (GitHub/GitLab).
git config --global core.sshCommand "vt ssh connect"
```

This manual import temporarily creates a plaintext private-key file. Use a
trusted local path and remove it after import; macOS `rm -P` is only a
best-effort overwrite, not guaranteed erasure on APFS/SSDs or snapshots. No
`~/.config/vt/git-ssh` record is needed. Without one, missing agent signing
authority hard-fails rather than exporting/decrypting a seed. The explicit
`.pub` pins one key; omitting explicit public-key sources enables discovery
of all agent identities instead.

**Linux/CI, portable identity:** configure an encryption/decryption backend,
then generate a separate per-host identity, or deliberately distribute a
shared portable identity to hosts that should use it:

```bash
vt ssh keygen
# Writes ~/.config/vt/git-ssh (ciphertext, 0600) and git-ssh.pub (0644).
# Enroll .pub; copy BOTH files when distributing the same identity.
git config --global core.sshCommand "vt ssh connect"
```

`keygen` generates the seed in memory, encrypts it as a RAW v2 `vt://` record,
and never imports it into the agent. `--key-file <path>` changes its output
path; `VT_GIT_SSH_PRIVATE_KEY` and `VT_GIT_SSH_PUB` are raw-content read inputs
for connect, not keygen destinations. Preserve the public-key/record pairing
when copying files. Ciphertext distribution does not itself authorize decrypt.

## 6. Verification entry points

Cross-platform tests cover wire round-trip, fallback classification, the pure
connect route decision, seed encoding, public-key fingerprint consistency,
and the relay extension filter:

```bash
cargo test --locked sign_req_res_roundtrip
cargo test --locked fallback_policy_
cargo test --locked sign_route_
cargo test --locked pubkey_wire_roundtrip_preserves_fingerprint
cargo test --locked relay_filter_
cargo check --target x86_64-unknown-linux-gnu
```

`resolved_routes_control_agent_probes_and_fallbacks` in `src/client.rs` covers
shared resolved-route behavior. The macOS-only
`sign_data_with_privkey_ed25519_signs_and_verifies` and
`sign_data_with_privkey_rsa_signs_and_verifies` tests in
`src/server_macos/ssh_agent.rs` exercise the shared signing core:

```bash
cargo test --locked sign_data_with_privkey_
```

These tests do not establish end-to-end Keychain/Touch ID or system-SSH behavior.
Native verification must exercise explicit and discovered identities, a missing
agent key with/without a record, rejection without decrypt retry, matching
provider authentication, config/backend pins, and forwarded relay prompts.
Repository gates remain `cargo test`, `just check`, and `just check-worker`;
Linux checks cannot compile macOS-only handlers.
