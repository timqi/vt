# SSH-over-`vt://` design

Status: DRAFT rev4 (addresses codex review rounds 1+2+3 — see §10 changelog)
Branch: `ssh-sign`

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
encoder used everywhere else in the codebase (`core.rs:8`, `cf.rs`, `client.rs`).
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

Why this is correct (verified round 2): `client_encrypt_v2` takes arbitrary bytes
(`core.rs:351`); `vt://0…` parses (`core.rs:304-310`); the RAW decrypt arm does
`String::from_utf8` (`core.rs:382-384`) which always succeeds on ASCII base64.

`vt ssh connect` decodes the recovered string with `BASE64_URL_SAFE_NO_PAD` into
`Zeroizing<[u8;32]>`, asserts `len()==32`, and rejects otherwise. This is the only
"is this an ssh key" validation needed.

### 3.1 Why this is cheap

- `encrypt` already falls back to CF with fresh salts (`client.rs:296`, `cf.rs:43/250`).
- `decrypt` already reads `$SSH_AUTH_SOCK` first, then `~/.ssh/vt.sock`, then CF
  (`client.rs:216`, `should_fallback_to_cf` `client.rs:117`).
- Worker records `op_kind`/`command` as doubly-sanitized, capped passthrough
  (`cf.rs:132-144` → `index.ts:219` → `approve.js` `textContent`). `op_kind="ssh-sign"`
  flows through with **no worker change** (confirmed round 1 focus 6).

### 3.2 Free two-tier routing (no router agent) — with prerequisite

- `ssh -A` forwards the laptop's `vt ssh agent` as `$SSH_AUTH_SOCK` → remote `connect`
  decrypts via `decrypt@vt` (laptop Touch ID) → signs on the remote.
- No laptop / CI → fallback CF (phone passkey).

**Prerequisite (N2):** `try_agent_extension` short-circuits to CF when `VT_AUTH` is
empty (`client.rs:211-214`). The laptop tier engages **only if the remote host also
has `VT_AUTH` set**; otherwise `connect` goes straight to CF even with a forwarded
socket. Documented requirement, not a bug.

## 4. Where the `vt://` lives — a FILE, never an env value (REVISED, NEW-B2)

**The `vt://` record is stored in a file, never exported in an environment variable.**

Reason (NEW-B2): `vt inject` scans the process environment for any value containing a
`vt://` URL, decrypts it, and injects the plaintext into the child's environment
(`client.rs:1086-1099`). If `VT_GIT_SSH_KEY` held the `vt://` directly, any
`vt inject -- cmd` on that host would decrypt the seed (base64) into the child's
`/proc/<pid>/environ` / `ps e` — a new exposure of a *signing* key. Keeping the
`vt://` in a file (which `vt inject` does NOT auto-scan; it only reads an explicit
`-r FILE`) eliminates this without modifying the security-sensitive inject code.

Layout (default, overridable):

```
~/.config/vt/git-ssh        # the vt://0… record (ciphertext at rest, mode 0600)
~/.config/vt/git-ssh.pub    # the OpenSSH public key line (cleartext, mode 0644)
```

Overrides: `keygen` writes to `--key-file <path>` or the default. `connect` reads
the **raw `vt://` record** from `VT_GIT_SSH_PRIVATE_KEY` (env value, not a path),
falling back to the default key file. The public key may likewise be supplied as
the raw OpenSSH line via `VT_GIT_SSH_PUB` (cleartext is harmless).
Note: `VT_GIT_SSH_PRIVATE_KEY` holds the **`vt://` ciphertext** record — env
exposure is equivalent to the 0600 ciphertext file, since decryption still
requires the ceremony (Touch ID / phone passkey). Only the plaintext seed must
never touch disk or env.

**Deployment note (round-3 N4):** every host where `git push` runs must reach the
key material — either the ciphertext file at the default path (copy it; safe to
distribute) or `VT_GIT_SSH_PRIVATE_KEY=<vt:// record>` (+ `VT_GIT_SSH_PUB` when the
`.pub` is not copied). `keygen` docs/help must state this.

## 5. clap / platform structure (B5 — implementation prerequisite)

The entire `Commands::Ssh(SshCommands)` subtree is currently `#[cfg(target_os=
"macos")]` (`main.rs:139-141, 181-183, 280`). Implementation MUST:

- ungate the `SshCommands` enum and the `Commands::Ssh` dispatch arm;
- keep `#[cfg(target_os="macos")]` on each mac-only variant (Agent/Add/List/Remove/
  RemoveAll/Comment/Show) **and** its dispatch arm (Rust strips cfg'd variants before
  clap's derive macro runs, so the derived `Subcommand` stays exhaustive per target —
  confirmed valid round 2);
- add ungated `Keygen` / `Connect` variants;
- place keygen/connect impl in a **cross-platform module** `src/ssh_sign.rs` (NOT under
  the macOS-gated `server_macos`).

**Cargo.toml — BLOCKING prerequisite for PR2 (round-3 B2, promoted from NIT-2):**
`ssh-agent-lib` currently enables `features=["agent","codec"]` only on the macOS-gated
dependency (`Cargo.toml:45`); the base unix entry has `default-features=false` with no
features (`Cargo.toml:28`). Note `ssh_agent_lib::blocking::Client` + `proto::{Extension,
Unparsed}` used today in `client.rs` are unconditional (not behind `agent`), so the
current Linux build is fine. BUT the ephemeral signer in `ssh_sign.rs` needs
`ssh_agent_lib::agent::{listen, Agent, Session}`, which ARE behind `#[cfg(feature=
"agent")]`. Therefore **PR2 cannot compile on Linux until `["agent","codec"]` is moved
to the cross-platform dependency entry.** This is a hard gate on PR2, verified by §9.2.
`ed25519_dalek` and `base64` are already cross-platform.

This restructure is a prerequisite for the §9.2 Linux check to be meaningful (NIT-3):
the changelog's "B5 resolved" refers to the *plan*; the source change happens in
implementation.

## 6. Components

### A. `vt ssh keygen` (PR1)

```
vt ssh keygen [--label <name>] [--comment <text>] [--key-file <path>]
```

1. Generate Ed25519 keypair in memory (`ed25519_dalek::SigningKey::generate`). Seed in
   `Zeroizing<[u8;32]>`; **plaintext never written to disk** (N5).
2. `BASE64_URL_SAFE_NO_PAD(seed)` → `VTClient::encrypt()` (RAW) → `vt://0…`.
3. Write `~/.config/vt/git-ssh` (vt://, mode 0600) + `~/.config/vt/git-ssh.pub`
   (OpenSSH pubkey, mode 0644) using `OpenOptions::create_new(true)` +
   `custom_flags(O_NOFOLLOW)` + `.mode(...)` — mirror the existing safe-write pattern
   in `inject()` (`client.rs:1166-1175`) to defeat symlink redirection (round-3 N3).
   Also echo both to stdout with guidance.
4. Zeroize seed, base64 buffer, `SigningKey`. (Only ciphertext `vt://` + cleartext
   pubkey are written to disk; the plaintext seed never is.)

Routing: Mac+agent → no Touch ID; headless → one CF approval (`op_kind="encrypt"`).
**Safe standalone increment** — RAW records work on all existing binaries (B4 resolved).

### B. `vt ssh connect` (PR2 — git SSH driver)

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
   - `REQUEST_IDENTITIES` → answer from cleartext pubkey (file/`VT_GIT_SSH_PUB`), no
     decrypt, no tap (no integrity gap — wrong pubkey → auth failure only, round 1 focus 4).
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
   (`client.rs:216`); if the parent mutated its own env, the signer's SIGN handler would
   resolve `SSH_AUTH_SOCK` to the ephemeral socket and connect to itself
   (recursion / self-connect). Keeping the override child-scoped means the parent retains
   the original (possibly forwarded) agent for decrypt. Then spawn system `ssh` with the
   original argv (`trailing_var_arg` + `allow_hyphen_values`); pump stdio; propagate exit.
5. On exit: remove temp socket + dir (best-effort; SIGKILL may leave a stale socket,
   harmless — ECONNREFUSED → `Ok(None)`, N3). Zeroize key material.

Decrypt routing = free two-tier (§3.2). One decrypt = one tap per push.

### C. Worker / audit — UNCHANGED (confirmed round 1 focus 6)

## 7. Security boundary (explicit, accepted)

- Plaintext seed in RAM only at (a) keygen and (b) sign-time decrypt. On a remote host
  (b) briefly places the seed in that host's RAM — inherent to decrypt-then-sign-locally.
- **`vt inject` exposure (NEW-B2) eliminated** by never holding the `vt://` in an env
  value (§4); the record lives in a file inject does not auto-scan.
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
| D3 | `vt://` location | default **file** (`~/.config/vt/git-ssh`, 0600), or raw `vt://` via `VT_GIT_SSH_PRIVATE_KEY` env (ciphertext — same exposure as the file). pubkey in sibling `.pub` / `VT_GIT_SSH_PUB`. |
| D4 | overrides / multi-key | `keygen --key-file`; `connect` via `VT_GIT_SSH_PRIVATE_KEY` (raw record). single key v1; host→key map deferred. |
| D5 | keygen import | generate-only v1. |
| D6 | signer impl | ephemeral agent + exec system `ssh`. |
| D7 | op_kind | keygen → `"encrypt"`; sign → `"ssh-sign"`. |
| D8 | PR split | PR1 = keygen (safe standalone). PR2 = connect. Neither needs core.rs changes. |
| D9 | macOS strategy | Opt 1 coexist. |
| D10 | algorithm | Ed25519 only. |
| D11 | clap/platform | ungate `SshCommands`; per-variant `#[cfg]`; keygen/connect in `src/ssh_sign.rs`; move `ssh-agent-lib` agent/codec features cross-platform. |
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

## 10. Changelog

Round 1: B1/B4 (no new type byte; base64 in RAW); B2 (base64 UTF-8-safe); B3 (downgraded
to documented residual); B5 (clap restructure plan); N2 (VT_AUTH prereq); N3 (stale
socket harmless); N4 (explicit chmod); N5 (Zeroizing seed, no disk).

Round 2: NEW-B1 → §3 pins `BASE64_URL_SAFE_NO_PAD` (43 chars) + round-trip test (D12);
NEW-B2 → §4 stores `vt://` in a file, never an env value; NIT-1 → 43 not 44 chars;
NIT-2 → §5 move `ssh-agent-lib` agent/codec features cross-platform; NIT-3 → §5 B5 is an
implementation prerequisite (plan only in doc); NIT-4 → §6.B `OnceCell` serializes the
signer's decrypt (D13).

Round 3 (both round-2 blockers confirmed resolved): B1 → §6.B step 4 (D14) forbids
`env::set_var`, child gets `SSH_AUTH_SOCK` via `Command::env()` only, preventing signer
self-connect/recursion (decrypt reads the sock from env at call time, `client.rs:216`);
B2 → §5 promotes the `ssh-agent-lib` `agent` feature move to a hard PR2 compile gate;
N1 → `get_or_try_init` (D13); N2 → §6.B async-safe key-file read (`tokio::fs`/`spawn_blocking`);
N3 → §6.A `O_NOFOLLOW`+`create_new` safe write; N4 → §4 per-host key-file deployment note.
