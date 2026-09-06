# VT coding-agent guide

This is the canonical agent guide; `CLAUDE.md` is a relative symlink to it.
VT is one Rust binary with a macOS SSH-agent transport (Touch ID, Keychain,
optional FIDO2) and a Cloudflare Worker transport (Passkey/WebAuthn).

## Start here

- [docs/README.md](docs/README.md) owns the feature/source map, change routing,
  and editing workflow. Use `rg` to find the symbol, then read its feature doc,
  implementation, and nearby tests before editing. Do not duplicate that map here.
- [README.md](README.md) owns installation and CLI quick starts; `docs/*.md`
  owns procedures and security decisions. This guide owns agent-facing red lines.
  Verify historical design notes against code; do not implement superseded plans.
- Keep changes scoped; update the owning feature doc when behavior, configuration,
  routes, secrets, or security assumptions change. Use stable file paths and
  symbols, not line numbers. Register new documents in the documentation map.

## Configuration and data handling

- Environment variables override `~/.config/vt/config.toml`; `VT_CONFIG` selects
  that file, which may contain secrets and should be mode 600. In `auto` mode,
  nonempty `VT_AUTH` enables agent-first routing with Worker fallback on
  recoverable errors; `VT_PASSKEY_URL` + `VT_PASSKEY_TOKEN` enable the Worker.
  `VT_BACKEND=agent` and `VT_BACKEND=passkey` pin the transport. Never silently
  broaden fallback. See [config.example.toml](config.example.toml).
- Hook rules are separate: `~/.config/vt/agent.toml`, overridden by
  `VT_AGENT_CONFIG`. Preserve default-accept and rewrite only when a configured
  rule names a resolved `vt://` variable; `--only-env` prevents injecting unrelated
  environment secrets. The hook is not a sandbox. See [docs/hook.md](docs/hook.md).
- Plaintext secrets and private seeds must never enter logs, examples, or test
  output. Do not introduce disk/argv exposure beyond explicit product flows such
  as transient injection.
  Notifications must never block or fail protected operations; agent cache-hit
  notifications run only after `permit.commit()` returns, fire-and-forget.
  See [docs/app-bundle.md](docs/app-bundle.md).
- Preserve structured extension envelopes and stable exit codes; error details
  must not reflect client data. See [docs/structured-errors.md](docs/structured-errors.md).

## Transient file injection

The operator entry is [README.md](README.md); recovery mechanics and tests live
in [src/client/inject.rs](src/client/inject.rs). Keep these implementation bounds:

- `vt inject -r` uses a self-exec restore supervisor, dispatched before Tokio/clap
  initialization. `--recover` stays unauthenticated and restores ciphertext only.
- The deterministic `.{name}.vt-backup` ciphertext backup IS the exposure lock:
  create it with `O_EXCL` before plaintext reaches disk, refuse overlap (`EEXIST`),
  and remove a newly created backup if filling it or obtaining its generation
  fails. Never remove another exposure's lock; never randomize the backup name.
  Refuse `-r` files with no `vt://` records.
- Every restore consumes the backup by atomic `rename`, never copy+delete.
  New sidecars must record `(dev, ino)`; arming retires stale sidecars for that
  backup path. Recovery checks generation and mtime versus the recorded deadline
  (mtime is the legacy id-less record's ordering bound), including a re-probe
  after publication cancellation. Never restore a known successor's backup.
- Supervisor and parent failure paths also check their armed `(dev, ino)` before
  restoring. Preserve recovery records on cancellation/restore failure or unknown
  backup state; stat errors must not be mistaken for absence. Only successful
  restoration or a known gone/superseded generation permits stale-record cleanup.
- Reserve the empty publication temp before arming; write only through its held
  fd, never recreate its path. Every restorer cancels publication before consuming
  the backup; cancellation errors preserve backup and recovery record. Record the
  recovery deadline before supervisor startup so stalled startup is recoverable.

## SSH-agent authorization

- All auth/run/sign/decrypt operations use the unified engine. `auth@vt` and
  `run@vt` always require fresh approval; legacy-containing decrypt batches stay
  fresh. Duration `0` means `Fresh`, never `StrictTtl(0)`. Reusable grants remain
  operation/subject/resource-scoped. Commit the non-cloneable permit only after
  operation success AND extension response encryption; failure drops without a
  grant. A live permit blocks revocation: no unbounded-latency work while held.
  See [docs/unified-authorization-engine.md](docs/unified-authorization-engine.md).
- Lock, idle timeout, observed screen lock, and detected wake advance the epoch
  even with no stored grants; live locked/non-interactive failures revoke grants.
  Screen lock/wake and idle also wipe decrypted SSH keys. Automatic key reload
  checks interactivity before AND after Keychain I/O; idle timeout stays >= 60s.
  See [docs/app-bundle.md](docs/app-bundle.md).
- Preserve activity scope families: verified destination for bound raw signs;
  kernel-derived workspace, exact cwd, then parent app for broad shared cwds.
  Forwarding-capable/tainted raw signs never cache; relay/SSH-carried vt extensions
  stay per-connection and cannot reuse local scopes. `session-bind@openssh.com`
  is plaintext, before lock/cipher checks, and never resets idle activity.
  See [docs/authorization-scopes-v2.md](docs/authorization-scopes-v2.md).
- Prompts must state reusable scope; agent-derived truth lines precede every
  client-reported line. See [docs/approval-transparency.md](docs/approval-transparency.md).
- `run@vt` is agent-only, allowlist-gated, and returns no child output/exit code.
  Never expose it through the Worker or `--forward-real-agent`. That opt-in relay
  holds no `VT_AUTH` and forwards only encrypt/decrypt/auth/sign/diag extensions;
  refuse run, ui-status, session-bind, and unknown extensions.
  See [src/ssh_sign.rs](src/ssh_sign.rs) (`route_extension`).
- `diag@vt` is VT_AUTH-encrypted, read-only, prompt-free, not audit-pushed, and
  never resets idle. `live_entries` counts only grants this caller could reuse;
  never-cache callers report 0. See [docs/diag-design.md](docs/diag-design.md).
- `ui-status@vt` alone exposes the whole grant store: plaintext before lock/cipher
  checks, gated by constant-time comparison of the 32-byte spawn token piped to
  `--ui-token-fd` (never env/argv/file; absent/wrong token fails unstructured).
  Only `status` and authority-reducing `revoke_all`: never grant/extend/approve,
  reset idle, or audit-push. Grant display labels are memory-only.
  See [docs/app-bundle.md](docs/app-bundle.md).
- Keychain rewrap must preserve `VT_AUTH`: new stores use wrap v2; upgrades use
  the flock-guarded mutator changing only `encrypted_passphrase` + `wrap_v`, never
  `create_and_save_passcode_passphrase`. Manual migration is `vt secret rebind`.
  See [docs/app-bundle.md](docs/app-bundle.md).

## Worker cache and admin

Cache policy and operator details: [docs/dek-cache.md](docs/dek-cache.md).

- Worker-derived IP is the hard cache boundary; client `pwd` is advisory.
  Apply `cacheScopePwd` only inside `cacheCtx` for both reads and writes; retain
  literal `meta.pwd` and show `cache_scope_pwd` beside approval duration controls.
- Caching is opt-in and requires `CACHE_SECKEY`. A hit is not a phone approval:
  always audit it. `CACHE_HIT_NOTIFY` independently enables best-effort hit pushes
  and is off by default. Group IDs and creation stamps are immutable.
- Access-gated list/clear need no Passkey; extension requires a verified Passkey
  via `opApprove` -> `commitExtend`, never Access alone. `CACHE_ADMIN_EXTEND` is
  only a kill switch. Never resurrect expired entries, shorten expiry, or extend
  drifted/no-gain groups; re-read entries with no await before the write, and audit
  authorization plus actual effects. Expiry is approval-time + TTL, not a lifetime
  budget. Keep distinct approve/extend TTL ladders and finite expiries, never
  null/Infinity; policy lives in [cf-worker/src/cache_policy.ts](cf-worker/src/cache_policy.ts).
- Listing exposes no sealed material, salts, or binding ctx digest, and reports
  `truncated`. Clearing must exhaust the `dek:` prefix, report actual deletions,
  and fail loudly if incomplete. Keep every cache-armed audit row's revoke button.
  `audit.cache_ttl_s` stays immutable; only `audit.cache_expires_ms` tracks extension.
  Every multi-key storage `get`/`put`/`delete` is chunked to <= 128 keys.
- Fixed `ADMIN_SEG` routes require both Cloudflare Access and Worker JWT checks.
  Serve admin shells/assets only inside gated handlers; public `/pwa/*` must reject
  paths resolving into `pwa/admin/`, including percent-encoded forms. Preserve
  `STRICT_CSP`, HTML UTF-8 content type, and global security headers on fresh
  responses; template JSON uses `escapeJsonForHtml`, never raw interpolation.
  See [cf-worker/src/index.ts](cf-worker/src/index.ts) and
  [cf-worker/src/page.ts](cf-worker/src/page.ts). Real secrets belong in Wrangler
  secret storage, never TOML examples: [docs/cf-worker-deploy.md](docs/cf-worker-deploy.md).

## Validation and deployment entry points

Run focused tests before the relevant repository gates: `cargo test`, `just check`
(host + Linux GNU Rust checks), and `just check-worker` (dependency setup,
TypeScript + Vitest). Linux gates do not validate macOS-only code or native
Touch ID/Keychain/UI behavior; use macOS CI and native checks where needed.
Report checks not run. Recipes live in [justfile](justfile).

Worker deployment: [docs/cf-worker-deploy.md](docs/cf-worker-deploy.md),
`just deploy-worker`; PWA changes need `just bump-assets` first (no bundling step).
macOS packaging/install: [docs/app-bundle.md](docs/app-bundle.md), `just app` /
`just install-app`. Follow these operator procedures; tests are not a deployment.
