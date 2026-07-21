# VT — coding-agent brief

This file is a navigation and invariant sheet for coding agents. The detailed
operator documentation is indexed in [`docs/README.md`](docs/README.md); do not
duplicate those procedures here.

## Project shape

VT is a single Rust binary with two authentication transports:

- macOS SSH-agent transport: Touch ID, local Keychain, and optional FIDO2;
- Cloudflare Worker transport: phone Passkey/WebAuthn approval for Linux,
  CI, and headless hosts.

The client tries the SSH-agent path first when `VT_AUTH` is set, then falls
back to the Worker in `auto` mode. `VT_BACKEND=agent` and `VT_BACKEND=passkey`
pin the transport. See [`config.example.toml`](config.example.toml) and
[`docs/README.md`](docs/README.md).

## Source map

| Area | Files |
|---|---|
| CLI and command routing | `src/main.rs` |
| Transport selection and client protocol | `src/config.rs`, `src/client.rs`, `src/cf.rs` |
| `vt://` format and cryptography | `src/core.rs`, `src/core/crypto.rs`, `src/core/wire.rs` |
| Agent authorization scopes, grants, and revocation | `src/core/authorization.rs`, `src/server_macos/authorization.rs`, `src/server_macos/ssh_agent.rs` |
| SSH identity and `vt ssh connect` | `src/ssh_sign.rs` |
| macOS Keychain, Touch ID, and SSH agent | `src/server_macos/` |
| AI-agent command hook | `src/hook.rs`, [`docs/hook.md`](docs/hook.md) |
| Worker routes and admin pages | `cf-worker/src/index.ts`, `cf-worker/pwa/admin/` |
| Worker ceremony/cache lifecycle | `cf-worker/src/do_account.ts` |
| Worker notification channels | `cf-worker/src/notify.ts`, `pushover.ts`, `slack.ts`, `slack_app.ts`, `feishu.ts` |

## Current behavior that must not drift

- Environment variables override `~/.config/vt/config.toml`; `VT_CONFIG`
  overrides that path. The file may contain secrets and should be mode 600.
- Hook rules live separately in `~/.config/vt/agent.toml`; they are not part of
  the secret config file. `VT_AGENT_CONFIG` overrides that path.
- `VT_AUTH` enables agent routing; `VT_PASSKEY_URL` plus
  `VT_PASSKEY_TOKEN` enables the Worker route. Never silently change fallback
  behavior when adding a new command.
- `vt inject -r` restores ciphertext through its self-exec'd restore
  supervisor. `vt inject --recover` must remain unauthenticated and only move
  the ciphertext backup back over the target.
- DEK caching is opt-in, requires `CACHE_SECKEY`, and uses the Worker-selected
  TTLs. A cache hit is not a phone approval; preserve its audit/notification
  behavior and IP binding.
- `auth@vt` and `run@vt` always require a fresh approval. Do not add them to
  auth caches.
- `auth@vt`, `run@vt`, SSH signing, and `decrypt@vt` all use the unified
  authorization engine. Reusable grants are operation- and subject-scoped,
  and a non-cloneable permit is committed only after the protected operation
  and, for extensions, response encryption succeed. A live permit holds the
  global prompt slot and blocks revocation; handlers must not perform
  unbounded-latency work while one is live.
- Grants are activity-scoped
  ([`docs/authorization-scopes-v2.md`](docs/authorization-scopes-v2.md)):
  raw SSH signs bind to the session-bind-verified destination host key
  (forwarding-capable or tainted connections are never cached); local vt
  callers bind to their kernel-derived `.git` workspace root; relay traffic
  is confined per connection. `session-bind@openssh.com` is plaintext and
  must be handled before the VT_AUTH cipher path, and must not reset the
  idle clock. The Touch ID prompt must state the reuse scope whenever an
  approval can create a grant. Cache duration `0` (the default) maps to the
  engine's first-class `Fresh` policy, never `StrictTtl(0)`.
- A live locked/non-interactive check failure revokes all grants. Agent lock,
  idle timeout, an observed screen lock, and a detected wake advance the
  authorization epoch even when the grant store is empty, so an in-flight
  prompt cannot recreate a revoked grant.
- Plaintext secrets and private key seeds must not be written to disk or logs.
  Do not add credentials to examples, test output, or command-line arguments
  unless the existing design explicitly requires it.
- Extension errors use the structured wire envelope in
  [`docs/structured-errors.md`](docs/structured-errors.md). Preserve stable
  exit-code semantics when changing agent/client behavior.

## High-risk feature notes

- `run@vt` is agent-only and allowlist-gated. It can launch a program on the
  Mac through a forwarded socket, returns no child output/exit code, and always
  requires a fresh approval. Never expose it through the phone-only backend or
  the `--forward-real-agent` relay.
- `vt ssh connect --forward-real-agent` is opt-in. Its relay filter permits only
  `encrypt@vt`, `decrypt@vt`, `auth@vt`, `sign@vt`, and the read-only
  `diag@vt`; it refuses `run@vt` and
  unknown extensions. The relay holds no `VT_AUTH`; authentication remains
  between the remote client and the upstream agent.
- `diag@vt` is read-only and requires no Touch ID; it must never reset the
  agent's idle-activity clock (a polling loop must not keep grants alive), and
  its `live_entries` stays scoped to the caller's own cache context.
- `vt inject -r` decrypts a file briefly and starts a self-exec'd restore
  supervisor. Keep the supervisor path before Tokio/clap initialization and
  keep `--recover` limited to restoring ciphertext backups.
- Hook rules use `~/.config/vt/agent.toml`, are default-accept, and only rewrite
  commands whose configured rule names a `vt://` variable. `--only-env` is the
  boundary that prevents unrelated environment secrets from being injected.
- Worker admin routes are under the fixed `ADMIN_SEG` and require both the
  Cloudflare Access gate and Worker JWT verification. Secrets in
  `wrangler.toml` examples are placeholders; real secrets belong in Wrangler
  secret storage.

## Editing workflow

1. Use `rg` to locate the command/config key/protocol symbol.
2. Read the relevant row in [`docs/README.md`](docs/README.md), then inspect
   the implementation anchor and nearby tests.
3. Keep the change scoped. Update the operator document when behavior,
   configuration, routes, secrets, or security assumptions change.
4. Prefer a focused test before the full gates. The repository gates are:

   ```bash
   cargo test
   just check
   just check-worker
   ```

`just check` covers the host and `x86_64-unknown-linux-gnu` Rust builds.
`just check-worker` installs worker dependencies when needed, type-checks, and
runs Vitest.

## Documentation rules

- `README.md` is the user-facing entry point: installation, quick start,
  command overview, and links.
- `docs/*.md` owns feature procedures and security decisions.
- This file owns repository navigation, invariants, and test gates.
- Design files may contain historical review material. Their current behavior
  must be checked against code; do not copy a superseded plan into a patch.
- Use exact file paths and symbols instead of fragile line-number references.
- When adding a document, add it to [`docs/README.md`](docs/README.md) and give
  it one clear owner; avoid creating a second explanation of an existing flow.
