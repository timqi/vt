# `sign@vt` design — context-carrying agent signing for `vt ssh connect`

Status: **implemented design reference**. The current implementation is in
`src/core.rs`, `src/client.rs`, `src/ssh_sign.rs`, and
`src/server_macos/ssh_agent.rs`. The revision history and PR breakdown below
are historical context only; they are not a task list.

## Current implementation summary

`sign@vt` is the VT-authenticated signing extension used by `vt ssh connect`:

- On macOS, the agent signs with a matching Keychain-backed key without
  exposing the private key to the caller.
- If the matching agent key is unavailable before authentication, the client
  may fall back to decrypt-then-sign using the portable `vt://` record. A
  rejection or post-prompt failure is not silently converted into another
  approval path.
- The route shares the standard sign auth cache (`none` by default) and keeps
  the advertised public key as the binding between lookup and signature.
- The wire types are cross-platform; only the Keychain-backed agent handler is
  macOS-specific.

The `PR-A`/`PR-B` labels and implementation snippets below are retained as
design history. They are not instructions to split or redo the implementation.

## 1. Goal

A single, uniform git SSH configuration on every host:
`git config core.sshCommand "vt ssh connect"`. The agent supports **two**
signing entry points side by side:

1. **Standard `SIGN_REQUEST`** (unchanged) — any ssh client talking to the vt
   agent gets the existing behaviour: look up the Keychain key by fingerprint,
   Touch ID with a generic prompt (`sign: <key> (<proc>)`), sign in-agent.
2. **New `sign@vt` extension** — `vt ssh connect` uses this. Same in-agent
   signing with the same Keychain key, but the request is VT_AUTH-gated and
   carries vt execution context (`host`, `command`, `meta`) so the Touch ID
   prompt / audit log read `ssh-sign: push -> github.com` plus the caller's
   user/cwd/tty.

Key-residency model is **per-host** (each host has its own Ed25519 identity and
its own public key enrolled on the provider):

- **Host with a vt agent (macOS workstation):** the private key lives **only in
  VT's encrypted macOS Keychain-backed store** (added via `vt ssh add`). `vt ssh
  connect` signs via `sign@vt`.
  The private key never leaves the agent. There is no `vt://` record for this
  key.
- **Agent-less host (Linux / CI):** the private key lives **only as a portable
  `vt://0…` record** (`vt ssh keygen`). `vt ssh connect` falls back to the
  existing decrypt-then-sign path (agent `decrypt@vt` if a forwarded agent
  serves the record, else CF worker), signing locally.

Because each key exists in exactly one place, there is **no dual
representation** — the objection that sank the "shared portable identity +
Keychain copy" idea does not apply here.

## 2. Non-goals

- Not removing or changing the standard `SIGN_REQUEST` handler. It stays, and
  the **same Keychain key remains reachable through it** (a bare `SIGN_REQUEST`
  for that fingerprint signs with the generic prompt, no VT_AUTH, no vt
  context). This is intentional: "compatible with standard ssh" is a goal, so
  the rich vt context is **best-effort — guaranteed only when the request
  arrives via `vt ssh connect`/`sign@vt`**. Forcing context would require
  hiding the key from the standard path, which would break normal ssh use of
  it. See §10 for the threat-model consequence.
- Not RSA-only or Ed25519-only at the protocol layer. `sign@vt` reuses the
  agent's existing multi-algorithm signing core (Ed25519 / RSA-SHA2 / ECDSA
  P-256/P-384), so it is not pinned to Ed25519 even though the git identity from
  `vt ssh keygen` is Ed25519.
- `sign@vt` shares the sign grant store with the standard `SIGN_REQUEST` path
  (opt-in via `--ssh-auth-cache-duration`; default `0` = always prompts). v1
  shipped cache-free; see §6 for the revised decision and
  [`authorization-scopes-v2.md`](authorization-scopes-v2.md) for the current
  activity scopes.

## 3. Wire additions (`src/core.rs`, cross-platform)

```rust
/// Request: client → agent for `sign@vt`. The agent looks up the Keychain key
/// identified by `pubkey`, prompts with vt context, and signs `data` in-agent.
/// The private key never leaves the agent.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SignReq {
    /// Display/audit only; never trusted (caller-asserted, esp. under -A).
    pub host: String,
    /// Human label, e.g. "ssh-sign: push -> github.com". Bounded like
    /// `DecryptReq::command` (PROMPT_DISPLAY_MAX_BYTES) and sanitized.
    pub command: String,
    /// SSH wire-encoded public key (`KeyData`) identifying WHICH Keychain key
    /// to sign with. The agent decodes it and computes the fingerprint with
    /// the SAME `fingerprint_str` used for stored keys, so lookup cannot drift.
    pub pubkey: Vec<u8>,
    /// Bytes to sign (the blob from the system ssh SIGN_REQUEST).
    pub data: Vec<u8>,
    /// SSH-agent signature flags (RSA SHA2 selection). Ed25519/ECDSA ignore.
    #[serde(default)]
    pub flags: u32,
    #[serde(default)]
    pub meta: ClientMeta,
}

/// Response: the SSH signature, algorithm-tagged so the client can rebuild an
/// `ssh_key::Signature` without assuming the key type. Not secret.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SignRes {
    /// e.g. "ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp256".
    pub algorithm: String,
    pub signature: Vec<u8>,
}
```

Notes:
- `pubkey`/`data`/`signature` serialize as JSON number arrays (same shape as the
  existing `[u8;32]` salt/dek fields) — no `serde_bytes` dependency.
- **No new `ErrKind` variants.** The taxonomy in `core/wire.rs` already covers
  every case used here: `BadRequest`, `AuthRejected`, `SessionLocked`,
  `NoGuiSession`, `NotInitialized`, and `Generic` (used for "this agent does not
  hold that key" — a fallback-eligible condition, see §5/§7).

## 4. Agent: refactor the signing core (`src/server_macos/ssh_agent.rs`)

The standard `sign` handler (lines ~1479-1555) inlines the per-algorithm signing
match. Extract it verbatim into a free function reused by both entry points:

```rust
/// Pure signing core: given an unlocked PrivateKey, sign `data` honoring the
/// SSH `flags` (RSA SHA2 selection). No auth, no lookup, no cache — callers do
/// that. Identical algorithm coverage to today's `Session::sign`.
fn sign_data_with_privkey(
    privkey: &PrivateKey,
    data: &[u8],
    flags: u32,
) -> Result<Signature, AgentError> {
    match privkey.key_data() {
        KeypairData::Ed25519(key) => { /* …moved verbatim… */ }
        KeypairData::Rsa(key)     => { /* …moved verbatim (uses `flags`)… */ }
        KeypairData::Ecdsa(key)   => { /* …moved verbatim… */ }
        _ => Err(AgentError::Failure),
    }
}
```

`Session::sign` (standard path) performs lookup, requests an
`Operation::Sign` permit from the unified authorization engine, then calls
`sign_data_with_privkey(...)`. The permit commits only after signing succeeds.

## 5. Agent: `sign@vt` handler + dispatcher wiring (current)

The extension name and both dispatcher sites are implemented as follows:

```rust
pub const EXT_SIGN: &str = "sign@vt";
```
- `EXT_SIGN` is in the allow-list `matches!(…, EXT_ENCRYPT | EXT_DECRYPT | EXT_AUTH | EXT_RUN | EXT_SIGN)`. An older agent without this arm returns `Ok(None)` from the dispatcher, which is the fallback signal the client expects.
- The dispatch match contains `EXT_SIGN => self.handle_sign_vt(&decrypted).await,`.
  (`handle_sign_vt` does its own Keychain lookup via the in-memory `keys` map,
  so it does not need the `store`/`passphrase_cipher` that encrypt/decrypt take;
  pass them only if a future cache needs them.)

> ⚠️ **Atomic dual edit.** The dispatcher has TWO places that must both contain
> `EXT_SIGN`: the `matches!(…)` allow-list guard (~1572) and the dispatch match
> with `_ => unreachable!()` (~1622). Updating only one compiles but fires
> `unreachable!()` at runtime for every `sign@vt` call. Keep an end-to-end test
> in place so a half-edit cannot regress silently.

```rust
async fn handle_sign_vt(
    &self,
    decrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>, (ErrKind, Option<&'static str>)> {
    use ssh_agent_lib::ssh_encoding::Decode; // KeyData::decode is a trait method — MUST be in scope.
    let req: SignReq = serde_json::from_slice(decrypted)
        .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;
    if req.command.len() > PROMPT_DISPLAY_MAX_BYTES {
        return Err((ErrKind::BadRequest, Some(DETAIL_DISPLAY_FIELD_TOO_LARGE)));
    }

    // Decode the requested pubkey → KeyData → fingerprint (same fn as storage).
    // `&[u8]: Reader`, so `decode(&mut &[u8])` is the correct call pattern.
    let key_data = ssh_key::public::KeyData::decode(&mut req.pubkey.as_slice())
        .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_SIGN_BAD_PUBKEY)))?;
    let fp_str = fingerprint_str(&key_data);

    // Ensure keys are loaded, then look up. "Not in this agent" is
    // FALLBACK-ELIGIBLE (Generic), NOT BadRequest — an agent-less/other-key
    // host must be able to fall back to decrypt-then-sign. (Clone the
    // PrivateKey out so we don't hold the keys read-lock across the prompt.)
    self.ensure_keys_loaded().await.map_err(|_| (ErrKind::Generic, Some(DETAIL_SIGN_KEYS_LOAD)))?;
    let privkey = {
        let keys = self.keys.read().await;
        match keys.get(&fp_str) {
            Some(k) => k.clone(),
            None => return Err((ErrKind::Generic, Some(DETAIL_SIGN_KEY_NOT_IN_AGENT))),
        }
    };

    // Rich prompt from vt context (mirrors handle_decrypt formatting).
    let who = who_at_host(&req.meta.user, &req.host);
    let mut auth_message = header_with_who("ssh-sign", "for", &who);
    let body = sanitize_prompt_multiline(&req.command, PROMPT_COMMAND_MAX_LINE_LEN, PROMPT_COMMAND_MAX_LINES);
    if !body.is_empty() { auth_message.push('\n'); auth_message.push_str(&body); }
    append_meta_lines(&mut auth_message, &req.meta);

    // Shared Operation::Sign grant scope; distinguish reject vs unavailable
    // so the client gets the right ErrKind (AuthRejected => no fallback).
    let permit = self.authorization.authorize(sign_request).await?;
    /* … sign + serialize; the dispatcher commits after response encryption … */

    let sig = sign_data_with_privkey(&privkey, &req.data, req.flags)
        .map_err(|_| (ErrKind::Generic, Some(DETAIL_SIGN_FAILED)))?;
    let res = SignRes { algorithm: sig.algorithm().to_string(), signature: sig.as_bytes().to_vec() };
    serde_json::to_vec(&res).map(Zeroizing::new)
        .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))
}
```

New server-controlled `DETAIL_*` strings (no user data, per `core/wire.rs`):
`DETAIL_SIGN_BAD_PUBKEY`, `DETAIL_SIGN_KEYS_LOAD`, `DETAIL_SIGN_KEY_NOT_IN_AGENT`,
`DETAIL_SIGN_FAILED`.

The dispatcher already runs the lock check and `auth_cipher` (VT_AUTH)
verification BEFORE dispatch, so `sign@vt` is VT_AUTH-gated for free, and the
`handle_sign_vt` errors flow back through the same `ExtResponse` envelope as the
other extensions.

## 6. Grant decision — shared with standard SSH signing (v1 was NO cache)

v1 always prompted, on the theory that git pushes are infrequent and a
per-sign Touch ID is cheap. In practice `vt ssh connect` is also the transport
for multi-host fan-outs (`tssh h1 h2 …`), where a single command produced one
Touch ID **per host** — exactly the prompt storm the sign cache exists to
prevent.

`sign@vt` and standard signing therefore both use `Operation::Sign` in the
unified grant store (opt-in via `--ssh-auth-cache-duration`, default `0` = v1
behaviour). Under activity scopes V2
([`authorization-scopes-v2.md`](authorization-scopes-v2.md)) a local
`sign@vt` caller is scoped to its kernel-derived git workspace, so a
multi-host fan-out from one project shares one grant and avoids one prompt
per host; raw ssh signs are scoped to their session-bind-verified destination
instead, and relay callers stay confined per connection.
The shared store carries all the standard protections:
strict TTL, dual-clock expiry, lock/wake/idle flush, and the prompt-queue
re-check that collapses concurrent bursts to one dialog.

## 7. Client: `VTClient::sign_vt` (`src/client.rs`, `#[cfg(unix)]`)

```rust
/// Ok(Some((alg, sig)))  -> agent signed (key never left agent).
/// Ok(None)              -> caller should fall back to decrypt-then-sign
///                          (socket missing/refused, old agent, or recoverable
///                          agent error per should_fallback_to_cf — including
///                          "key not in this agent" = Generic).
/// Err(_)                -> AuthRejected / BadRequest: do NOT fall back (G3).
pub async fn sign_vt(
    &self, host: &str, command: &str, pubkey: &[u8], data: &[u8], flags: u32,
) -> Result<Option<(String, Vec<u8>)>> {
    let req = SignReq {
        host: host.into(), command: command.into(), pubkey: pubkey.to_vec(),
        data: data.to_vec(), flags, meta: cf::collect_client_meta(),
    };
    let payload = serde_json::to_vec(&req)?;
    let auth_token = self.auth_token.clone();
    // Same blocking + classification as agent_call_or_fallback, but WITHOUT the
    // "falling back to phone passkey" eprintln (our fallback is local
    // decrypt-then-sign, not necessarily CF).
    let result = tokio::task::spawn_blocking(move || {
        Self::try_agent_extension(&auth_token, "sign@vt", &payload)
    }).await?;
    match result {
        Ok(Some(bytes)) => { let r: SignRes = serde_json::from_slice(&bytes)?; Ok(Some((r.algorithm, r.signature))) }
        Ok(None) => Ok(None),
        Err(e) if should_fallback_to_cf(&e) => Ok(None),
        Err(e) => Err(e),
    }
}
```

`should_fallback_to_cf` encodes guardrail G3 exactly: it returns `false` only
for `AuthRejected` (post-prompt decline) and `BadRequest` (malformed request);
everything else — transport, `SessionLocked`, `NoGuiSession`, `NotInitialized`,
`Generic` ("key not in this agent") — is pre-prompt / environmental and
fallback-eligible.

## 8. connect: routing (`src/ssh_sign.rs`, `#[cfg(unix)]`)

Current `connect_unix` behavior:

1. An explicit public key (`VT_GIT_SSH_PUB`, otherwise
   `~/.config/vt/git-ssh.pub`) takes precedence. It is advertised to system
   `ssh` and may be paired with an optional `vt://` record from
   `VT_GIT_SSH_PRIVATE_KEY` or `~/.config/vt/git-ssh`.
2. If no explicit public key exists and `VT_AUTH` is set, `connect` discovers
   all identities from the upstream VT agent and advertises them. These use
   `sign@vt` and do not need a local `vt://` record.
3. If neither source provides an identity, `connect` fails before starting
   system `ssh` with an actionable error. A missing `vt://` record is therefore
   normal for an agent-backed identity, not a sign-time error.

`load_private_record_opt()` returns `Result<Option<String>>`: an absent default
file is `Ok(None)`, other IO errors are fatal, and a present value must start
with `vt://`. The macOS Keychain-backed flow intentionally uses `None`.

### Explicit-record loading details

- **`vt://` record is optional** — `load_private_record_opt()` returns
  `Result<Option<String>>`:
  - if `VT_GIT_SSH_PRIVATE_KEY` is set and non-empty → `Some(value)`;
  - else read the default file `~/.config/vt/git-ssh`: map
    **`ErrorKind::NotFound` (ENOENT) → `Ok(None)`**, propagate any OTHER IO error
    (permission, etc.) as fatal;
  - a present-but-malformed value (not starting with `vt://`) stays a hard error.
  The macOS provisioning flow (§14) deliberately leaves no `vt://` file and does
  not set `VT_GIT_SSH_PRIVATE_KEY`, so `None` is the normal Keychain-backed
  case — not an error.

### Wire encoding detail

- `pubkey_bytes: Vec<u8>` = SSH wire encoding of the advertised `KeyData`,
  computed once. **`encode_vec()` does not exist** in ssh-encoding 0.2; use the
  `Encode` trait's `encode(&mut writer)` with a `Vec<u8>` writer:
  ```rust
  use ssh_agent_lib::ssh_encoding::Encode;
  let mut pubkey_bytes = Vec::new();
  key_data.encode(&mut pubkey_bytes).context("encode pubkey")?; // Vec<u8>: Writer
  ```
  The agent decodes these exact bytes with `KeyData::decode` and computes
  `fingerprint_str` the same way it does for stored keys, so the lookup
  fingerprint matches the one connect advertised — no format drift.

```rust
async fn sign(&mut self, request: SignRequest) -> Result<ssh_key::Signature, AgentError> {
    if request.pubkey != self.inner.pubkey { return Err(AgentError::Failure); }

    // 1) Agent-internal sign with vt context (macOS Keychain path).
    match self.inner.client.sign_vt(
        &self.inner.host, &self.inner.command,
        &self.inner.pubkey_bytes, &request.data, request.flags,
    ).await {
        Ok(Some((alg, sig))) =>
            return ssh_key::Signature::new(ssh_key::Algorithm::new(&alg).map_err(AgentError::other)?, sig)
                .map_err(AgentError::other),
        Ok(None) => { /* fall through */ }
        Err(e) => return Err(sign_err(e.to_string())), // AuthRejected/BadRequest: no fallback
    }

    // 2) Fallback: decrypt-then-sign locally — only if a vt:// record exists.
    let Some(vt_url) = self.inner.vt_url.as_deref() else {
        return Err(sign_err("no vt agent holds this key and no vt:// record is configured"));
    };
    let seed = self.inner.key.get_or_try_init(|| async { /* …current decrypt body, using vt_url… */ }).await?;
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let sig = signing.sign(&request.data);
    ssh_key::Signature::new(ssh_key::Algorithm::Ed25519, sig.to_bytes().to_vec()).map_err(AgentError::other)
}
```

`request_identities` still advertises exactly the one pubkey loaded from disk
(unchanged).

## 9. Guardrails → code (must-verify checklist)

- **G1 — lookup binding.** `sign@vt` signs only with a Keychain key whose
  fingerprint matches the caller-supplied `pubkey` (decoded and fingerprinted
  by the agent itself). It never signs with caller-supplied key material. This
  is strictly weaker capability than the standard `sign` path already grants
  for the same key.
- **G2 — cache.** Shares the standard sign operation/store (opt-in, default
  duration `0` = always prompt), while the workspace / destination / relay
  scopes still partition individual grants; see §6.
- **G3 — fallback only on pre-prompt failure.** Enforced by reusing
  `should_fallback_to_cf`. All `handle_sign_vt` rejections that occur before the
  prompt are `BadRequest`/`Generic`; `Generic` ("key not here") falls back,
  `BadRequest` (malformed) does not (decrypt-then-sign would fail identically),
  and once `authenticate()` runs the only outcomes are success or a
  no-fallback auth `ErrKind`. No double-prompt is possible.

### Fallback truth table (connect `sign()`)

| `sign@vt` outcome | client maps to | connect action |
|---|---|---|
| signature returned | `Ok(Some((alg,sig)))` | use it (key never left agent) |
| socket missing/refused | `Ok(None)` | decrypt-then-sign (if `vt://` present) |
| old agent (unknown ext) | `Ok(None)` | decrypt-then-sign (if `vt://` present) |
| key not in this agent (`Generic`) | `Ok(None)` | decrypt-then-sign (if `vt://` present) |
| `SessionLocked`/`NoGuiSession`/`NotInitialized`/transport | `Ok(None)` | decrypt-then-sign (if `vt://` present) |
| `AuthRejected` (declined) | `Err` | **fail, no fallback** |
| `BadRequest` (malformed) | `Err` | **fail, no fallback** |
| `Ok(None)` but no `vt://` file | — | **fail with actionable message** |

## 10. Security notes

- **Standard-path coexistence (accepted).** The git Keychain key is signable via
  a bare `SIGN_REQUEST` (generic prompt, no VT_AUTH, no vt context). For a local
  workstation that is fine. Do **not** `ssh -A`-forward this agent to an
  untrusted host expecting the vt-context guarantee — a forwarded `SIGN_REQUEST`
  bypasses `sign@vt`. (Per-host keys mean you would not forward this key for
  remote signing anyway.) If a future need arises to force context, add a
  per-key "vt-only" flag that makes the standard `sign` handler refuse that
  fingerprint; out of scope for v1.
- **ClientMeta is caller-asserted display context, not verified provenance** —
  same trust model as today's `decrypt@vt` `command` field. Prompt context is
  for display/audit, not access control.
- **Forwarding prerequisite (N2 unchanged).** `sign_vt` goes through
  `try_agent_extension`, which short-circuits to `Ok(None)` when `VT_AUTH` is
  empty. On a remote host the `sign@vt` path engages only if that host has
  `VT_AUTH` set; otherwise connect uses the decrypt-then-sign fallback.

## 11. Platform / build impact

- `cargo check --target x86_64-unknown-linux-gnu` MUST stay green. `SignReq`/
  `SignRes` (core.rs), `VTClient::sign_vt`, and the `connect` change
  (ssh_sign.rs) are cross-platform and never touch `server_macos`.
  `handle_sign_vt` + `sign_data_with_privkey` live in the macOS-gated
  `server_macos` module.
- **No new dependencies.**

## 12. Why rev2 (Keychain-backed C) over rev1 (C′)

rev1 had the agent decrypt a `vt://` seed and sign internally — keeping a single
portable representation but (a) feeding ciphertext through the agent (a v2
invariant deviation) and (b) requiring a key-binding guard so the agent isn't a
signing oracle over arbitrary RAW records. rev2 instead uses a **per-host key in
the Keychain** on agent hosts, which the user prefers because (i) different hosts
already hold different keys, so there is no dual representation to keep in sync;
(ii) on a local macOS workstation a Keychain-resident key (ACL + Touch ID gated,
not synced, not on disk in plaintext) is a higher bar than a `vt://` ciphertext
decrypted into process RAM; and (iii) it reuses the agent's existing
multi-algorithm signing core unchanged. The cost is the accepted standard-path
coexistence in §10. (Note: Ed25519 keys are regular Keychain items, not Secure
Enclave — SE is P-256 only — so they are protected and non-exportable but loaded
into agent RAM at sign time.)

## 13. Historical PR breakdown

1. **PR-A (wire):** `SignReq`/`SignRes` in `core.rs` + round-trip test. Linux-green.
2. **PR-B (agent):** extract `sign_data_with_privkey`; add `EXT_SIGN`, dispatcher
   arm, `handle_sign_vt`, `DETAIL_*`. macOS tests: key-not-in-agent → Generic
   (no prompt), bad pubkey → BadRequest, reject → AuthRejected (no cache write),
   happy path signs and verifies; equivalence test old-inline vs helper.
3. **PR-C (client+connect):** `VTClient::sign_vt`; `SignerInner` gains
   `pubkey_bytes` + optional `vt_url`; `SignerSession::sign` agent-first routing.
   Tests: fallback truth table (mock agent per `ErrKind`), no-`vt://`-no-agent
   hard fail, signature verifies against the advertised pubkey.

## 14. Provisioning (closes the keygen↔Keychain gap)

`vt ssh keygen` writes a `vt://` record; it does **not** put a key in the agent.
`vt ssh add -f <file>` imports an OpenSSH private key into **vt's own encrypted
KeychainStore** (`rusty.vault.store`, encrypted under the master key — NOT the
macOS login keychain, so `ssh-add --apple-use-keychain` is irrelevant here).
The two key-residency models are provisioned differently:

**macOS workstation (Keychain-backed, no `vt://` file):**
```bash
ssh-keygen -t ed25519 -f /tmp/vt-git -C "git@$(hostname -s)" -N ""   # plaintext key + .pub
vt ssh add -f /tmp/vt-git                                            # import into vt store (Touch-ID gated)
install -m 0644 /tmp/vt-git.pub ~/.config/vt/git-ssh.pub            # connect advertises + identifies via this
rm -P /tmp/vt-git                                                   # macOS best-effort overwrite + remove
# enroll ~/.config/vt/git-ssh.pub with the provider (GitHub/GitLab)
git config --global core.sshCommand "vt ssh connect"
```
There is no `~/.config/vt/git-ssh` (vt:// ciphertext) on this host, so connect
uses `sign@vt` exclusively; `vt_url` is `None` and the decrypt fallback is
unreachable (hard-fails with an actionable message if the agent ever lacks the
key).

**Agent-less host (Linux / CI, `vt://`-backed):**
```bash
vt ssh keygen           # writes ~/.config/vt/git-ssh (vt:// ciphertext, 0600) + .pub
# copy BOTH files to each host (ciphertext is safe to distribute); enroll .pub
git config --global core.sshCommand "vt ssh connect"
```

**"No dual representation" holds per host:** a macOS host has the key in the vt
store and *no* `vt://` file; a Linux host has the `vt://` file and the key is
*not* in any agent. The keys are distinct identities (distinct provider pubkeys).
The only way BOTH would exist for one identity is if a user copies a `vt://`
record onto a macOS host AND `vt ssh add`s the same key — explicitly out of the
supported flow.

**Optional future convenience (not v1):** a `vt ssh keygen --in-keychain` that
generates the Ed25519 key in memory, imports it straight into the vt store (same
`KeychainStore::modify` path as `ssh add`), writes only the `.pub`, and never
emits a `vt://` file — collapsing the macOS provisioning to one command. Listed
as future work; v1 uses the manual steps above.

## 15. Test plan (highlights)

- **G3 no-fallback on reject:** mock `sign@vt` → `AuthRejected`; assert connect
  does not invoke the decrypt path (no second prompt) and fails.
- **Fallback on key-not-here:** agent returns `Generic`; connect with a `vt://`
  file present drives the signature via decrypt-then-sign.
- **Hard fail on neither:** no agent key + no `vt://` file → actionable error.
- **Signature correctness:** a `sign@vt` signature verifies under the advertised
  OpenSSH pubkey for the same `data`, and is byte-identical to a standard-path
  signature for the same key/data (Ed25519).
- **Linux surface:** `cargo check --target x86_64-unknown-linux-gnu` green.
