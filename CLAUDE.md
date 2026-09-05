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
| VT.app menu-bar shell and bundle packaging | `app/VTShell.swift`, `app/Info.plist`, `justfile` (`app`, `install-app`), [`docs/app-bundle.md`](docs/app-bundle.md) |
| Worker routes and admin pages | `cf-worker/src/index.ts`, `cf-worker/src/page.ts`, `cf-worker/pwa/approve.html`, `cf-worker/pwa/admin/` |
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
  the ciphertext backup back over the target. The ciphertext backup's
  deterministic per-target name (`.{name}.vt-backup`) IS the exposure lock:
  it is created O_EXCL before any plaintext hits disk (and removed if
  filling it fails — a partial copy must not read as a lock), and every
  restore path must consume it via rename() — never copy+delete — so an
  overlapping `inject -r` of the same file fails EEXIST instead of
  snapshotting exposed plaintext as its "ciphertext" backup. Because that
  path is reused across exposures, every new sidecar MUST carry its backup's
  `(dev, ino)` generation id, recovery refuses a backup whose generation or
  mtime-vs-deadline ordering its sidecar did not record (the ordering bound
  is all an id-less legacy record has), arming retires stale sidecars naming
  the path, and every restorer — the supervisor and the parent's failure
  paths alike — only renames the `(dev, ino)` generation it armed for (a
  suspend can delay either past the wall-clock deadline, into a successor's
  window) and keeps its sidecar when a restore fails or the backup's state
  is unknowable — only "not there" counts as consumed; other stat errors
  must never clean a recovery record. Do not reintroduce a randomized
  backup name, and keep refusing `-r` files with zero `vt://` records.
- The DEK cache binding ctx is `SHA-256("vt-dek-ctx-v4" || len(ip) || ip ||
  cacheScopePwd(pwd))`. The worker-derived IP is the hard boundary; the pwd half
  is advisory and is NORMALIZED by `cacheScopePwd` (each path segment loses its
  final `.suffix`, hidden dirs and `.`/`..` untouched) so git-worktree siblings
  (`<repo>.<branch>`) share one scope instead of one approval each. Normalize
  inside `cacheCtx` only — a write and a read must never key on different halves
  of the rule — and never normalize `meta.pwd` itself: the literal directory is
  what the approval page, notifications, audit, and admin listing show. Since the
  scope can be wider than the caller's cwd, the approval page must keep stating
  it (`cache_scope_pwd`) beside the duration radios.
- DEK caching is opt-in, requires `CACHE_SECKEY`, and uses the Worker-selected
  TTLs. A cache hit is not a phone approval; preserve its audit row and IP
  binding. Every write mints an immutable `cache_group_id` (the handle the admin
  surface selects on) plus a `created_ms` stamp (forensic only since the lifetime
  budget was removed). Never rewrite either — an extension touches `expires_ms`
  and nothing else.
- The admin cache surface is deliberately asymmetric
  ([`docs/dek-cache.md`](docs/dek-cache.md)): listing and clearing reduce
  authority and need only the Cloudflare Access gate, while EXTENDING a cache
  grants it and must never be reachable from an Access session alone. The extend
  route only mints a pending ceremony; `expires_ms` moves solely in
  `commitExtend`, called from `opApprove` after a verified Passkey assertion.
  Keep all of: laddered TTLs only, NEVER resurrect a lapsed entry (this is now the
  load-bearing bound — see below), never shorten, refuse drifted/`no_gain` groups,
  re-read each entry with no await before the write, and audit both the
  authorization and the effect.
- Extension is measured from the APPROVAL, every time: `expires_ms = now + ttl`.
  There is deliberately NO total-lifetime ceiling — an entry may be renewed
  indefinitely, one Passkey-approved hop at a time — so `created_ms` is forensic
  only and pre-migration entries are extendable like any other. Do not reintroduce
  a `created_ms`-anchored budget: the previous one made the feature a no-op for the
  common 8h grant and constrained only the legitimate operator, since a ceiling
  binds nobody who can already complete a WebAuthn ceremony. What replaces it is
  liveness — extension CONTINUES a live grant and can never recreate a lapsed one.
- Two TTL ladders, one rule — a TTL is legal only if some PASSKEY ceremony offers
  it. `APPROVE_TTL_WHITELIST` (20m/2h/8h) guards `writeCache`, so a tampered
  approve body cannot arm a multi-day cache without the extension ceremony;
  `EXTEND_TTL_WHITELIST` (adds 1d/2d/1w and a 100-year, effectively-permanent rung)
  guards extension requests. That rung MUST stay a finite far-future TTL, never a
  null/Infinity sentinel: a sentinel would need a branch in the read check, the
  sweep, the audit column, and the countdown, and a missed branch there is a cache
  that survives its own revocation. It is also the one rung that forfeits the
  liveness bound — an entry on it never lapses, so only an explicit clear or a
  `CACHE_SECKEY` rotation revokes it.
  `MAX_EXTEND_TTL_MS` (the largest single hop) must stay COMPUTED from the extend
  ladder, never hardcoded, so trimming the ladder shortens the hop automatically. `CACHE_ADMIN_EXTEND` is
  a kill switch, NOT an authorization — never treat it as one. The arithmetic
  lives in `cf-worker/src/cache_policy.ts` and is unit-tested; keep it pure.
- Cache listings must never expose sealed material, salts, or the binding ctx
  digest (ctx + a known IP is an offline oracle for the client-reported `pwd`),
  and must report `truncated` rather than silently showing a partial view.
  `audit.cache_ttl_s` is the TTL the approver CHOSE and is never rewritten;
  `audit.cache_expires_ms` is the live expiry an extension updates. The admin
  per-row clear button must render for every cache-armed row — a wrong liveness
  projection may cost an extra click, but must never hide the only revoke path.
  For the same reason CLEARING is exhaustive where listing may be partial: every
  clear path streams the whole `dek:` prefix (`sweepCacheEntries`), never the
  `truncated`-capped `scanCacheGroups`, and reports the count storage actually
  removed. A revoke that answers `200 {"cleared":0}` for entries it never reached
  is read as a completed revocation; if a clear cannot finish it must fail loudly.
  EVERY multi-key storage call must stay chunked to the platform's 128-key limit
  — `get()`, `put()` and `delete()` all throw on a longer array, and a ceremony
  may carry up to 256 salts: an over-long `delete()` removes NOTHING while its
  caller reports success, and an over-long `get()` turns a routine cache miss
  into a 500 on the decrypt hot path. The real-time 免审批 push (Pushover / Slack / Slack App / Feishu)
  is separately opt-in via the `CACHE_HIT_NOTIFY` var and off by default —
  it is too noisy on busy hosts. Never make the audit row conditional on it.
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
  callers bind to their kernel-derived `.git` workspace root, falling back
  to the exact cwd directory, then — for broad shared cwds (`$HOME`, its
  ancestors, temp roots) — to the kernel-derived parent application. Each
  fallback is a distinct grant family with its own digest domain; relay
  traffic is confined per connection. `session-bind@openssh.com` is plaintext and
  must be handled before the VT_AUTH cipher path, and must not reset the
  idle clock. The Touch ID prompt must state the reuse scope whenever an
  approval can create a grant, and agent-derived truth lines (relay marker,
  `caller:`, raw-sign `dest:`/taint warning, reuse) must precede every
  client-reported line
  ([`docs/approval-transparency.md`](docs/approval-transparency.md)). Cache
  duration `0` (the default) maps to the engine's first-class `Fresh`
  policy, never `StrictTtl(0)`.
- A live locked/non-interactive check failure revokes all grants. Agent lock,
  idle timeout, an observed screen lock, and a detected wake advance the
  authorization epoch even when the grant store is empty, so an in-flight
  prompt cannot recreate a revoked grant. Screen lock and idle timeout also
  wipe decrypted SSH keys from memory (not just grants); `ensure_keys_loaded`
  must refuse to reload keys while the screen is non-interactive — checked
  both before and after the keychain read — so a request during lock cannot
  repopulate RAM ([`docs/app-bundle.md`](docs/app-bundle.md) §10). Idle
  timeout is floored at 60s (idle `0` is not a `Fresh`-style special case;
  it would busy-loop the sweeper).
- `ui-status@vt` is the ONE deliberate whole-store visibility channel
  ([`docs/app-bundle.md`](docs/app-bundle.md) §5): plaintext, dispatched with
  `session-bind@openssh.com` before the lock check and the VT_AUTH cipher
  path, gated by the 32-byte spawn token the VT.app shell pipes to
  `--ui-token-fd` (never env/argv/file; constant-time compare; no token ⇒
  every request fails unstructured). It never resets the idle clock, is never
  audit-pushed, and its only actions are `status` and the authority-reducing
  `revoke_all` — no action may grant, extend, or approve. (This is the AGENT's
  unauthenticated UI channel and stays authority-reducing-only; it is not the
  Worker's Passkey-gated cache extension, which is a separate surface with its own
  ceremony.) The relay filter must keep refusing it. Grant `display` labels are
  memory-only.
- The master-key wrap is versioned (`KeychainStore.wrap_v`): new stores are
  always wrap v2 (path-independent `vt-wrap-v2` label); v1 stores upgrade
  transparently at agent startup via the flock-guarded minimal mutator that
  touches ONLY `encrypted_passphrase` + `wrap_v`. Never route a rewrap
  through `create_and_save_passcode_passphrase` — it mints a fresh
  passcode/auth_token and would silently rotate every client's VT_AUTH.
  `vt secret rebind` is the manual migration/rollback path.
- Notifications must never block or fail a protected operation: `notify_macos`
  is fire-and-forget (reaper thread), prefers the bundled `VTApp notify`
  helper (bundle identity) with `osascript` fallback, and both paths share
  one sanitize. Cache-hit notifications fire only AFTER `permit.commit()`
  returns — a live permit blocks revocation, so no unbounded-latency work
  (e.g. the first-use notification permission dialog) may run while one is
  held.
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
  its `live_entries` counts only grants the caller's own scope classification
  could reuse — a caller whose basis never caches reports 0, never a
  whole-store count.
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
- Admin/approval page shells are static files under `cf-worker/pwa/` served
  through the `ASSETS` binding from INSIDE the gated handler, with server data
  substituted into `{{NAME}}` placeholders by `renderTemplate`
  (`cf-worker/src/page.ts`). Every page response must keep `STRICT_CSP`,
  `text/html; charset=utf-8`, and the global security headers — build a fresh
  `Response`, since `ASSETS.fetch` headers are immutable. JSON injected into a
  page goes through `escapeJsonForHtml`, never raw. The unauthenticated
  `/pwa/*` route must keep refusing anything that resolves into `pwa/admin/`
  (`isAdminAssetPath`, percent-decoding included) — that folder is reachable
  only via the Access-gated `/${ADMIN_SEG}/pwa/*` mount. `ASSET_VER` is
  stamped by `just bump-assets`; there is deliberately no build/bundling step.

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
