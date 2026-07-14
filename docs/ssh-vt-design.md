# SSH-over-`vt://` design

Status: **implemented design reference**. The current implementation is in
`src/ssh_sign.rs`, `src/client.rs`, and `src/main.rs`; user-facing setup starts
in `README.md`. Sections describing review rounds, branches, and PR planning
are historical context only.

## Current implementation summary

- `vt ssh keygen` writes an encrypted `vt://` record to
  `~/.config/vt/git-ssh` (or `--key-file`) and writes the matching public key
  beside it. The record is ciphertext and may be copied between hosts.
- `vt ssh connect` is a `GIT_SSH_COMMAND` driver. It uses the public key to
  advertise an identity, runs the system `ssh` for transport and host-key
  checks, and obtains signatures through the VT approval path.
- On a host with an appropriate VT agent, signing can use the agent's
  Keychain-backed key. Otherwise the driver decrypts the portable record on
  demand through the agent/Passkey routing described in `README.md`.
- `--forward-real-agent` is opt-in and forwards only the filtered VT extension
  set documented in §11; `run@vt` and unknown extensions are refused.

The older `PR1`/`PR2`, review-round, and changelog labels below describe how
the feature was built. They are not pending work items.

## 1. Goal

Provide a **portable SSH identity** (Ed25519) for `git push` whose private key is
stored as a single `vt://` encrypted record, usable identically on macOS, Linux,
and headless/CI hosts. Signing **reuses the existing vt decrypt ceremony**
(SSH-agent path → CF passkey fallback). The key plaintext exists only momentarily
in RAM at creation and at sign time.

Headline property: **one key, generated once, used everywhere; the worker stores
nothing new and needs zero code change.**

## 2. Non-goals

- Not migrating macOS Keychain SSH keys to `vt://` (**Opt 1 coexist**). `vt ssh
  agent` + `vt ssh add/list/remove/comment/show` stay as-is.
- Not RSA / ECDSA. **Ed25519 only**.
- Not covering interactive `ssh`. Wires **git** only, via `GIT_SSH_COMMAND`.
- Not building a full SSH client. Transport / known_hosts / ssh_config delegated to
  the system `ssh` binary.

## 3. Storage format — RAW `vt://` text record holding base64url(seed)

The Ed25519 private key is stored as an **ordinary `SecretType::RAW` v2 record whose
plaintext is `BASE64_URL_SAFE_NO_PAD(seed)`** — a 43-char ASCII string. No new type
byte.

**Alphabet is pinned (NEW-B1):** `base64::prelude::BASE64_URL_SAFE_NO_PAD`, the same
encoder used by the shared crypto/client code (`src/core.rs`, `src/cf.rs`,
`src/client.rs`).
32 bytes → **43 chars** (NOT 44; standard padded base64 would be 44 and is forbidden
here). keygen and connect MUST use this exact encoder; a round-trip unit test
(§9.3) guards against an alphabet/padding mismatch silently yielding a wrong key.

```
plaintext stored = BASE64_URL_SAFE_NO_PAD(seed[32])     # 43 ASCII chars
vt://0{b64u(salt(16) || ct || tag(16))}                  # SecretType::RAW, byte '0'
DEK   = HKDF-SHA256(master_key, salt, "vt-dek-v2", 32)
nonce = salt[..12]
ct    = AES-256-GCM(DEK, nonce, base64url(seed), AAD="vt:v2:0")
```

Why this is correct: `client_encrypt_v2` accepts arbitrary plaintext bytes;
the v2 parser preserves the `RAW` type; and the RAW decrypt arm converts the
plaintext to a string, which always succeeds for ASCII base64. See
`src/core.rs::{client_encrypt_v2,parse_v2_url,client_decrypt_v2}`.

`vt ssh connect` decodes the recovered string with `BASE64_URL_SAFE_NO_PAD` into
`Zeroizing<[u8;32]>`, asserts `len()==32`, and rejects otherwise. This is the only
"is this an ssh key" validation needed.

### 3.1 Why this is cheap

- `VTClient::encrypt` already falls back to CF with fresh salts.
- `decrypt` already reads `$SSH_AUTH_SOCK` first, then `~/.ssh/vt.sock`, then CF
  (`VTClient::connect_agent_socket`, `should_fallback_to_cf`).
- Worker records `op_kind`/`command` as doubly-sanitized, capped passthrough
  (`cf::collect_meta` → `index.ts::capChallengeMeta` → `approve.js` `textContent`). `op_kind="ssh-sign"`
  flows through with **no worker change** (confirmed round 1 focus 6).

### 3.2 Free two-tier routing (no router agent) — with prerequisite

- `ssh -A` forwards the laptop's `vt ssh agent` as `$SSH_AUTH_SOCK` → remote `connect`
  decrypts via `decrypt@vt` (laptop Touch ID) → signs on the remote.
- No laptop / CI → fallback CF (phone passkey).

**Prerequisite (N2):** `try_agent_extension` short-circuits to CF when `VT_AUTH` is
empty (`VTClient::try_agent_extension`). The laptop tier engages **only if the remote host also
has `VT_AUTH` set**; otherwise `connect` goes straight to CF even with a forwarded
socket. Documented requirement, not a bug.

## 4. Where the `vt://` lives — file by default, env override supported

The default and recommended location is a file. `connect` also supports the
explicit `VT_GIT_SSH_PRIVATE_KEY` environment override for CI or wrappers; that
variable contains the encrypted `vt://` record, not the plaintext seed.

Reason (NEW-B2): `client::inject` scans the process environment for any value containing a
`vt://` URL, decrypts it, and injects the plaintext into the child's environment
(`env_vt_vars` in `src/client.rs`). If `VT_GIT_SSH_PRIVATE_KEY` held the `vt://` directly, any
`vt inject -- cmd` on that host would decrypt the seed (base64) into the child's
`/proc/<pid>/environ` / `ps e` — a new exposure of a *signing* key. Keeping the
record in the default file avoids that scan. If the environment override is
used, do not run an unrestricted `vt inject -- ...` with that variable inherited;
use the default file or `--only-env` to keep the signing record out of the
decryption set.

Layout (default, overridable):

```
~/.config/vt/git-ssh        # the vt://0… record (ciphertext at rest, mode 0600)
~/.config/vt/git-ssh.pub    # the OpenSSH public key line (cleartext, mode 0644)
```

Overrides: `keygen` writes to `--key-file <path>` or the default. `connect` reads
the **raw `vt://` record** from `VT_GIT_SSH_PRIVATE_KEY` (env value, not a path),
falling back to the default key file. The public key may likewise be supplied as
the raw OpenSSH line via `VT_GIT_SSH_PUB` (cleartext is harmless).
`VT_GIT_SSH_PRIVATE_KEY` is still ciphertext at rest/in the environment, but its
presence makes it eligible for the generic `vt inject` environment scan described
above. Only the plaintext seed must never be written to disk or placed in an
environment variable.

**Deployment note (round-3 N4):** every host where `git push` runs must reach the
key material — either the ciphertext file at the default path (copy it; safe to
distribute) or `VT_GIT_SSH_PRIVATE_KEY=<vt:// record>` (+ `VT_GIT_SSH_PUB` when the
`.pub` is not copied). `keygen` docs/help must state this.

## 5. Platform structure (current)

`SshCommands` and its `Keygen`/`Connect` variants are cross-platform. The local
agent and key-management variants (`Agent`, `Add`, `List`, `Remove`,
`RemoveAll`, `Comment`, `Show`) remain macOS-only through `#[cfg]`. The
cross-platform implementation is in `src/ssh_sign.rs`; it uses the
cross-platform `ssh-agent-lib` agent/codec features needed by the ephemeral
signer. Keep this split intact when changing the CLI or Cargo features.

## 6. Components

### A. `vt ssh keygen`

```
vt ssh keygen [--label <name>] [--comment <text>] [--key-file <path>]
```

1. Generate Ed25519 keypair in memory (`ed25519_dalek::SigningKey::generate`). Seed in
   `Zeroizing<[u8;32]>`; **plaintext never written to disk** (N5).
2. `BASE64_URL_SAFE_NO_PAD(seed)` → `VTClient::encrypt()` (RAW) → `vt://0…`.
3. Write `~/.config/vt/git-ssh` (vt://, mode 0600) + `~/.config/vt/git-ssh.pub`
   (OpenSSH pubkey, mode 0644) using `OpenOptions::create_new(true)` +
   `custom_flags(O_NOFOLLOW)` + `.mode(...)` — mirror the existing safe-write pattern
   in `client::inject` to defeat symlink redirection (round-3 N3).
   Also echo both to stdout with guidance.
4. Zeroize seed, base64 buffer, `SigningKey`. (Only ciphertext `vt://` + cleartext
   pubkey are written to disk; the plaintext seed never is.)

Routing: key generation uses the normal encrypt path (which does not require a
Touch ID prompt); later signing requires the agent or phone approval path.

### B. `vt ssh connect` (git SSH driver)

```
git config core.sshCommand "vt ssh connect"
```

git invokes: `vt ssh connect [ssh-opts] [user@]host 'git-receive-pack …'`.

1. **Capture `$SSH_AUTH_SOCK` immediately** into a parent-local var (before any
   override) — used for decrypt (confirmed safe, round 1 focus 2).
2. Collect meta from self (git's child): cwd, ppid cmdline, own argv → host + push/fetch.
   `op_kind="ssh-sign"`, `command="push → <host>:<repo>"` (reuse `cf::collect_client_meta`).
3. Start an ephemeral in-process signer agent on a private temp unix socket:
   - temp dir `0700`; socket explicitly `chmod 0600` after bind (not umask — N4).
   - `REQUEST_IDENTITIES` → answer with the resolved identity/identities (see §B.1),
     no decrypt, no tap (no integrity gap — wrong pubkey → auth failure only, round 1 focus 4).
   - `SIGN_REQUEST(T)` → read the key file with `tokio::fs` (or inside `spawn_blocking`
     — never a blocking `std::fs` read on the tokio thread, round-3 N2) → decrypt the
     `vt://` via `VTClient::decrypt` → `BASE64_URL_SAFE_NO_PAD` decode →
     `Zeroizing<[u8;32]>` → `SigningKey::from_bytes` → sign `T`.
   - **Key cache (round-3 N1, D13):** guard the decrypt-once with
     `tokio::sync::OnceCell::get_or_try_init` (NOT `get_or_init` — decrypt is fallible;
     a rejected Touch ID must allow a later retry, and the error must NOT be cached) so
     concurrent SIGN_REQUESTs cannot trigger two approval prompts or race the slot.
4. **Pass `SSH_AUTH_SOCK=<temp sock>` to the child via `Command::env()` ONLY. The parent
   process MUST NOT call `std::env::set_var("SSH_AUTH_SOCK", …)` (round-3 B1).**
   `VTClient::decrypt` reads `SSH_AUTH_SOCK` from the process env at call time
   (via `VTClient::connect_agent_socket`); if the parent mutated its own env, the signer's SIGN handler would
   resolve `SSH_AUTH_SOCK` to the ephemeral socket and connect to itself
   (recursion / self-connect). Keeping the override child-scoped means the parent retains
   the original (possibly forwarded) agent for decrypt. Then spawn system `ssh` with the
   original argv (`trailing_var_arg` + `allow_hyphen_values`); pump stdio; propagate exit.
5. On exit: remove temp socket + dir (best-effort; SIGKILL may leave a stale socket,
   harmless — ECONNREFUSED → `Ok(None)`, N3). Zeroize key material.

Decrypt routing = free two-tier (§3.2). One decrypt = one tap per push.

### B.1 Identity resolution & client config (UPDATED)

`connect` resolves the identity/identities it advertises in this precedence
(`resolve_identities` in `src/ssh_sign.rs`):

1. **Explicit pubkey** — `VT_GIT_SSH_PUB` (env), else `~/.config/vt/git-ssh.pub`
   (file). One identity; may carry a `vt://` record (`VT_GIT_SSH_PRIVATE_KEY` /
   `~/.config/vt/git-ssh`) for the decrypt-then-sign fallback. Reproducible pin.
2. **Agent discovery** — if no explicit pubkey AND `VT_AUTH` is set: list **all**
   keys the upstream `vt ssh agent` holds (standard `REQUEST_IDENTITIES`, no Touch
   ID, via `VTClient::list_agent_identities` in `spawn_blocking`) and advertise
   every one. Each signs via `sign@vt` (no record → no decrypt-then-sign
   fallback). Makes the agent-present case zero-config.
3. Otherwise → actionable error (set `VT_GIT_SSH_PUB`, write the `.pub`, or start
   the agent with `VT_AUTH`).

Notes / limitations:
- Discovery is gated on `VT_AUTH` because `sign@vt` needs that key; if
  `$SSH_AUTH_SOCK` points at a **non-vt** agent, its keys advertise but every
  sign then fails — unset it or pin `VT_GIT_SSH_PUB`.
- `VT_GIT_SSH_PRIVATE_KEY` set without a pubkey is unusable here (logs a warning,
  then falls through to discovery).
- Advertising many keys can trip ssh's `Too many authentication failures`; pin
  with `VT_GIT_SSH_PUB` to avoid it.
- SSH **certificate** keys (decoded as `KeyData::Other`) can't be matched for
  `sign@vt` and hard-fail (no signing without Touch ID — safe, but unsupported).

**Required client config:**
```
git config --global core.sshCommand "vt ssh connect"
git config --global ssh.variant ssh   # else git can't pass -p to non-default-port remotes
```
`ssh.variant ssh` is needed because git auto-detects an unknown `core.sshCommand`
as the `simple` variant, which refuses `-p <port>` (and other options); `vt ssh
connect` forwards all args to real `ssh`, so declaring `ssh` is correct.

`connect` also pins the child to its ephemeral socket with `-o
IdentityAgent=<sock>` (highest precedence), so a user's `IdentityAgent
~/.ssh/vt.sock` in `~/.ssh/config` can't hijack the child straight to the real
agent and bypass the context-injecting shim.

### C. Worker / audit — UNCHANGED (confirmed round 1 focus 6)

## 7. Security boundary (explicit, accepted)

- Plaintext seed in RAM only at (a) keygen and (b) sign-time decrypt. On a remote host
  (b) briefly places the seed in that host's RAM — inherent to decrypt-then-sign-locally.
- **`vt inject` exposure (NEW-B2) avoided by default** by keeping the `vt://` in a
  file that inject does not auto-scan. The supported environment override has the
  explicit inheritance caveat described in §4.
- **Zeroization residual (B3, documented):** the decrypt pipeline returns a plain
  `String` (`base64(seed)`) — identical to every existing vt secret. We decode into
  `Zeroizing<[u8;32]>` immediately and best-effort clear the String. No raw-bytes
  decrypt arm is added in this work; that would be a future hardening for all secrets.
  No new exposure vs current vt behavior.
- Public key non-secret; cleartext fine. Seed confidentiality == `vt://` == existing KMS.
- Ephemeral signer socket: `0700` dir / `0600` socket, removed on clean exit.
- known_hosts/transport delegated to system `ssh` — no new MITM surface (round 1 focus 5).

## 8. Locked decisions

| # | Decision | Choice |
|---|---|---|
| D1 | storage / type byte | `SecretType::RAW` (`vt://0`), plaintext = `BASE64_URL_SAFE_NO_PAD(seed)`. No core.rs change. |
| D2 | key representation | 32-byte seed (base64url at rest; `Zeroizing<[u8;32]>` in use). |
| D3 | `vt://` location | default **file** (`~/.config/vt/git-ssh`, 0600), or raw ciphertext via `VT_GIT_SSH_PRIVATE_KEY`. The environment override is scanned by unrestricted `vt inject`; see §4. Pubkey in sibling `.pub` / `VT_GIT_SSH_PUB`. |
| D4 | overrides / multi-key | `keygen --key-file`; `connect` via `VT_GIT_SSH_PRIVATE_KEY` (raw record). single key v1; host→key map deferred. |
| D5 | keygen import | generate-only v1. |
| D6 | signer impl | ephemeral agent + exec system `ssh`. |
| D7 | op_kind | keygen → `"encrypt"`; sign → `"ssh-sign"`. |
| D8 | Historical PR split | PR1 = keygen; PR2 = connect. Neither needed core.rs changes. |
| D9 | macOS strategy | Opt 1 coexist. |
| D10 | algorithm | Ed25519 only. |
| D11 | Current clap/platform | `SshCommands` is cross-platform; macOS-only variants retain per-variant `#[cfg]`; keygen/connect live in `src/ssh_sign.rs`; `ssh-agent-lib` agent/codec features are cross-platform. |
| D12 | base64 alphabet | `BASE64_URL_SAFE_NO_PAD` (43 chars), pinned + round-trip test. |
| D13 | signer cache | `tokio::sync::OnceCell::get_or_try_init` (fallible; rejected auth retriable, error not cached). |
| D14 | child env override | `Command::env("SSH_AUTH_SOCK", temp)` ONLY; parent never `env::set_var` (prevents signer self-connect). |

## 9. Test gates

1. `cargo check` (native macOS).
2. `cargo check --target x86_64-unknown-linux-gnu` — **must include keygen/connect**
   (proves B5/D11 fix: commands exist + compile on Linux, signer features enabled).
3. `cargo test`:
   - `base64url(seed)` round-trips encrypt→`vt://0`→decrypt→`from_bytes`→same pubkey
     (guards NEW-B1 alphabet);
   - malformed/short record rejected (len != 32);
   - argv → (host, push/fetch) parsing.

## 10. Historical changelog

Round 1: B1/B4 (no new type byte; base64 in RAW); B2 (base64 UTF-8-safe); B3 (downgraded
to documented residual); B5 (clap restructure plan); N2 (VT_AUTH prereq); N3 (stale
socket harmless); N4 (explicit chmod); N5 (Zeroizing seed, no disk).

Round 2: NEW-B1 → §3 pins `BASE64_URL_SAFE_NO_PAD` (43 chars) + round-trip test (D12);
NEW-B2 → §4 prefers a file and documents the environment override caveat; NIT-1 → 43 not 44 chars;
NIT-2 → §5 moved `ssh-agent-lib` agent/codec features cross-platform; NIT-3 → §5
recorded the platform split; NIT-4 → §6.B `OnceCell` serializes the signer's
decrypt (D13).

Round 3 (both round-2 blockers confirmed resolved): B1 → §6.B step 4 (D14) forbids
`env::set_var`, child gets `SSH_AUTH_SOCK` via `Command::env()` only, preventing signer
self-connect/recursion (decrypt reads the sock from env at call time via
`VTClient::connect_agent_socket`);
B2 → §5 promotes the `ssh-agent-lib` `agent` feature move to a hard PR2 compile gate;
N1 → `get_or_try_init` (D13); N2 → §6.B async-safe key-file read (`tokio::fs`/`spawn_blocking`);
N3 → §6.A `O_NOFOLLOW`+`create_new` safe write; N4 → §4 per-host key-file deployment note.

## 11. Forwarded relay: `vt ssh connect --forward-real-agent`

Default **OFF**. Solves: `vt ssh connect -A host` for an interactive login used
to forward only the ephemeral *signer*, which speaks nothing but
`REQUEST_IDENTITIES` + `SIGN_REQUEST` — so `vt read` / `vt inject` on the
remote could not reach the Mac agent through the forwarded socket and silently
fell back to the phone/worker passkey ceremony on every decrypt.

With the flag, the ephemeral agent additionally implements the agent-protocol
`extension` op as a **transparent, filtering relay** to the UPSTREAM real vt
agent, and the child `ssh` forwards the ephemeral socket to the remote:

```
remote vt CLI ──(forwarded $SSH_AUTH_SOCK)──> sshd unix sock ──ssh channel──>
  ephemeral agent (op filter) ──fresh conn per request──> real vt agent
                                                            ($SSH_AUTH_SOCK
                                                             captured at start,
                                                             else ~/.ssh/vt.sock)
```

### Op filter (`route_extension`, pure + unit-tested)

Decided on the CLEARTEXT extension `name` only. The `details` payload is an
opaque AES-GCM(`VT_AUTH`) blob: the relay holds **no `VT_AUTH`**, never
decrypts, and passes `name` + `details` byte-for-byte (`Extension` re-encodes
as `string name || raw details`; the upstream's response `Extension` is
returned unchanged). Remote CLI and Mac agent share `VT_AUTH`, so end-to-end
authentication/encryption is between *them* — the relay cannot read or forge
requests.

| extension | route | why |
|---|---|---|
| `decrypt@vt`, `auth@vt`, `sign@vt` | relay | Touch-ID-gated on the upstream agent per request; the sign@vt prompt names the requested key (agent-derived) and carries the relay-origin marker |
| `encrypt@vt` | relay | unauthenticated by design (same as running it locally) |
| `run@vt` | **refuse** | spawns processes on the local machine — never over a forwarded socket |
| `session-bind@openssh.com`, anything else | refuse | unknown ops stay unsupported (pre-flag behavior) |

`sign@vt` was originally refused ("would expose ALL local keys"). Relaying it
is the better trade: the refusal pushed a nested remote `vt ssh connect` (git
on the remote host) into the decrypt-then-sign fallback, which decrypts the
git key's raw Ed25519 seed INTO REMOTE PROCESS MEMORY after one approval —
strictly worse than signing on the Mac, where the private key never leaves
the agent and only signatures cross. The "all local keys" exposure is real
(the relay cannot filter by key — the payload is opaque) and is mitigated
upstream instead: every relayed sign is Touch-ID-gated, the prompt shows the
agent-derived key label plus a `via forwarded vt relay` origin marker, and
sign-cache grants (opt-in, default `none`) are narrowed to this connection.

Refusals and an unreachable upstream socket both answer `SSH_AGENT_FAILURE`;
the remote CLI treats that as recoverable and falls back to the passkey
ceremony (`should_fallback_to_cf`), so the failure mode is "phone tap", never
a hang. `request_identities` / `sign` behavior is unchanged (login context
injection preserved).

### Why standard agent forwarding (not `RemoteForward`)

- **Universal**: sshd creates a unique per-connection socket and exports
  `$SSH_AUTH_SOCK` automatically; no remote sshd config
  (`StreamLocalBindUnlink`), no fixed path to collide/squat, cleanup on
  disconnect for free.
- The child is pinned with `-o ForwardAgent=<ephemeral sock>` (OpenSSH ≥ 8.2
  path form) rather than bare `-A`: it pins BOTH "forwarding on" and *which*
  socket, and a command-line `-o` beats `~/.ssh/config` (first-obtained wins).
  A config line `ForwardAgent /path/to/real.sock` could otherwise forward the
  real agent **unfiltered** — the same hijack class the existing
  `-o IdentityAgent=` pin defends against.
- The upstream socket path is captured ONCE at startup from the parent env
  (`$SSH_AUTH_SOCK`, else `~/.ssh/vt.sock`) — the child-only env override
  (D14) plus path capture make relay self-connection impossible.

### Cache-context narrowing IS preserved for the relay

The macOS `vt ssh agent`'s "forwarded-agent narrowing" anchors the auth cache
to a per-connection `(peer_pid, peer_start_time)` context when the connecting
peer is a forwarding agent. That check keys on the peer's executable basename
being `ssh` — but under `--forward-real-agent` the peer reaching the real agent
is the **`vt` relay process** (basename `vt`), which would otherwise fall into
the ordinary local-caller context (per-session / per-app / global) and lose the
per-connection scoping. `resolve_cache_context` therefore ALSO recognises the
relay peer — by its kernel-derived argv (`KERN_PROCARGS2`, parsed by the pure
`parse_procargs2`; predicate `is_vt_relay_invocation`: basename `vt` +
`ssh connect` + `--forward-real-agent`) — and gives it the **identical**
`(pid, start)` per-connection context `ssh` gets, in every cache mode (incl.
`global`) and with no TTY requirement (the relay may be scripted). So a relayed
`decrypt@vt` grant is scoped to that one `vt ssh connect` process and dies with
it — matching a plain `ssh -A` of the real agent, not widening it. Argv is
process-controlled, but a spoofed match only *narrows* a caller to its own
`(pid, start)` — it can never widen scope or ride another context's grants
(the same asymmetry the `ssh` basename check relies on). `is_vt_relay_invocation`
+ `parse_procargs2` are pure and unit-tested on the Linux/host target; only the
sysctl fetch and the wiring are macOS-only.

### Threat model (what the remote gains)

- `decrypt@vt` / `auth@vt`: the remote can *request* them, but each is
  Touch-ID-gated on the Mac. Subject to the agent's own opt-in decrypt cache
  policy — and that cache is narrowed to this connection (see above), so a
  remote host rides only its own connection's grants within the TTL, never
  those of local tabs or other remote hosts.
- `sign@vt`: the remote can request a signature with ANY key held by the Mac
  agent — not just the advertised git identity — and the relay cannot narrow
  that (opaque payload). Each request is Touch-ID-gated; the prompt's `key:`
  line is agent-derived truth (comment, else SHA256 fingerprint) while
  host/command are client-reported, and relayed prompts carry the
  `via forwarded vt relay` marker. Sign-cache grants (opt-in, default `none`)
  are per-connection: within the TTL the remote can silently re-sign with a
  fingerprint approved on that same connection — the same residual class as
  the decrypt cache. In exchange, when the Mac agent HOLDS the requested key,
  the nested-`vt ssh connect` git flow signs on the Mac instead of decrypting
  the raw key seed onto the remote host. If the agent does NOT hold the key
  (e.g. the portable `git-ssh` identity is only a `vt://` record, not enrolled
  in the Keychain), `sign@vt` misses and `decide_sign_route` still falls back
  to decrypt-then-sign — the seed lands on the remote as before. The win is
  conditional on the key living in the agent.
- `encrypt@vt`: unauthenticated by design — a remote can mint new `vt://`
  records; it could already do that via the worker path.
- `run@vt`: blocked at the relay. This is the deliberate narrowing vs raw
  `ssh -A` of the real agent (with which a remote could reach `run@vt`
  directly).
- Residual risk (same as any `ssh -A`): while the connection is up, ANY
  process on the remote that can open the forwarded socket can trigger
  relayed requests — i.e. cause Touch ID prompts / ride the decrypt cache
  window. Keep the flag off for hosts you don't trust; it is off by default.
- Concurrency: one fresh upstream connection per relayed request; prompt
  stacking is bounded by the upstream agent's global one-permit semaphore.
