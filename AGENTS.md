# VT coding-agent guide

This is the canonical agent guide; `CLAUDE.md` is a relative symlink to it.
VT is one Rust binary with a macOS SSH-agent transport (Touch ID, Keychain)
and a Cloudflare Worker transport (Passkey/WebAuthn).

## Principles

1. **Less code is the feature.** Every line is a liability; a security tool
   is audited by the line. If the OS, OpenSSH, or the Worker platform already
   does it, we don't.
2. **Two custodies, one engine each.** Keychain + Touch ID locally, PRF passkey
   via the Worker. Every local authorization passes the unified engine; every
   Worker authorization passes `opApprove`. No third custody, no side door.
3. **Hard boundaries come from the kernel or the token, never the client.**
   Locally the verified caller (pid/uid, `session-bind`); on the Worker the
   host `token_id`. Everything a client reports (cwd, project, app name) is
   advisory: display and scope narrowing only, never a trust boundary.
4. **Three seams.** `core/` is platform-blind (no Keychain, no HTTP, no
   `cfg(target_os)`); `server_macos/` is the only macOS tree; `client/` speaks
   to the agent socket and to `cf.rs` and nothing else. The Worker mirrors it:
   `do_account.ts` owns state, `index.ts` owns routes, nothing else touches
   storage.
5. **Compatibility is removed, never widened.** A migration branch ships for
   one release with its operator step named, then goes; its test becomes a
   rejected-input test. See [docs/refactor.md](docs/refactor.md).
6. **No speculative generality.** The third repeat earns an abstraction. No
   knobs, traits, or config keys for a caller that does not exist.
7. **Fail closed, fail loudly.** An unavailable check denies; an error reaches
   the operator as a stable structured code. A silent fallback is a bug even
   when it works.
8. **Minimal dependencies.** Std first, then audited crypto staples and the
   platform SDKs. A new runtime dep names in its commit what code it deletes.
   `Cargo.lock` / `package-lock.json` diffs are reviewed on upgrade.

## Budgets

The target is disordered growth and duplication; line counts are a proxy, so
the rules fail on the thing, not on the number.

1. **Growth is a claim.** A change that adds net lines to an area names, in
   the commit, what the feature could not have been without them.
2. **Splitting is not a reduction.** A module splits when it has two reasons
   to exist; a header that needs "and" is the tripwire.
3. **The third copy is a bug.** Same logic in three places is fixed or deleted;
   a copy-paste pair past ~30 lines is reported at two.
4. **Never traded for a number.** Tests, failure paths, fresh-approval
   semantics, lock/epoch invalidation, structured error codes, type and seam
   declarations.
5. **Ceilings are a prompt with a deadline.** `just size` prints the table
   below with live numbers. Crossing a ceiling asks "what is in there?"; if the
   answer is "the right things", raise it with that sentence. A ceiling exceeded
   for more than one release without a raise or a deletion is the failure this
   section exists to catch.

| Area | Ceiling | What the size is |
| --- | --- | --- |
| `src/core/` | 1.7k | `core.rs` + `core/`: record format, crypto, wire envelopes, authorization engine and session model — platform-blind; `authorization.rs` is half of it, pending step 4 |
| `src/client/` | 1.8k | `client.rs` + `client/`: transport routing, CLI verbs, `inject` with its recovery supervisor, `doctor`, record parsing |
| `src/server_macos/` | 4.5k | SSH agent, scopes, Keychain, socket owner check, audit push, UI status; step 4 of refactor.md decides the scopes share |
| root `src/*.rs` | 2.0k | entry, config, `cf.rs` Worker client, `ssh_sign.rs` relay routing, caller metadata, audit push (its master-key form is an open step 1 row) |
| `cf-worker/src/` | 4.0k | one DO owning state, routes, host tokens, DEK cache policy, WebAuthn, notifications, admin page; raised from 3.5k when steps 4–5 of worker-slim.md landed: the root key, config blob, passkey admin session and login ceremony (`account_admin.ts` ≈ 450, `admin_auth.ts`) are the right things, and nothing else in the area is a copy |
| one module | 750 | rule 2 before splitting; `core/authorization.rs`, `server_macos/ssh_agent.rs`, `client/inject.rs` are the open tripwires |

Non-blank, non-comment lines, `#[cfg(test)]` and `*.test.ts` excluded. No
repo-wide number. Ceilings are the post-slim targets: steps 1–2 of
[docs/refactor.md](docs/refactor.md) close the current `core` and root
overages.

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
- `inject --only-env` restricts env-var decryption to the named variables; a
  wrapper uses it so a command never receives unrelated environment secrets.
- Plaintext secrets and private seeds must never enter logs, examples, or test
  output. Do not introduce disk/argv exposure beyond explicit product flows such
  as transient injection.
  Notifications must never block or fail protected operations; agent cache-hit
  notifications run only after `permit.commit()` returns, fire-and-forget.
  Web Push is the Worker's only channel: fan-out runs via `waitUntil` after the
  ceremony write, never on the ceremony path, never a warning to the CLI.
  See [docs/app-bundle.md](docs/app-bundle.md), [docs/worker-slim.md](docs/worker-slim.md) §5.
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
  Every sidecar records `(dev, ino)`; an id-less record is unknown state (never
  parsed, never restored, never retired). Arming retires stale sidecars for that
  backup path. Recovery checks generation and mtime versus the recorded deadline
  (mtime catches a successor reusing the inode), including a re-probe after
  publication cancellation. Never restore a known successor's backup.
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
  `run@vt` always require fresh approval; a decrypt item that is not a v2
  envelope is a `BadRequest`, never a fresh-prompt batch. Duration `0` means
  `Fresh`, never `StrictTtl(0)`. Reusable grants remain
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

- `SECRET` is the only Wrangler secret and only a KEK: the root key `R` is
  generated at bootstrap, stored as `root:v1` wrapped under
  HKDF(`SECRET`, `vt-kek-v1`), unwrapped into DO memory only, never logged.
  Every other key derives from `R` (`account_admin.ts`): host tokens, `K_cfg`,
  `K_sess`, the cache scalar. Rotation appends a second wrap and returns the
  new value once; the first load under the new `SECRET` drops the old wrap;
  never a third. A root that does not unwrap is unconfigured (fail closed,
  `config.unreadable` once), and bootstrap over it is the factory reset.
  No `[vars]`: `cache_enabled`, `cache_hit_notify`, `uv_policy` live in
  `cfg:v1` and `PUT /api/admin/config` accepts nothing else; `origin` is
  captured at bootstrap and immutable. See [docs/worker-slim.md](docs/worker-slim.md).
- Hosts authenticate with per-host tokens (`vt1.<id>.<secret>`, secret =
  HKDF(`R`, id)); the edge checks header shape and body caps, the DO compares
  the MAC (`verifyHostMac`, constant time) before it touches the token, then
  checks liveness and slides expiry to now + 7 d on every use, never reviving
  a revoked/expired token. `/api/enroll` is unauthenticated: keep the per-IP
  rate limiter (`LIMITER`, absent → 503), the pending cap, and the pairing
  code. Issue a token only inside `opApprove` → `commitEnroll`; never store
  the secret. On the token path `meta.host`/`user` come from the record, never
  the body. Every daemon request, audit push included, carries a host token;
  never add a token-less or master-keyed branch. See [docs/host-token.md](docs/host-token.md).
- The host `token_id` is the hard cache boundary; client `project` (common git
  dir, else cwd) is advisory and Worker-derived IP is audit metadata. Derive the
  key only inside `cacheCtx` for both reads and writes; it refuses a missing
  `token_id`. Retain literal `meta.pwd` and show `metadata.project` beside
  approval duration controls.
- Caching is opt-in (`cache_enabled`, off by default); the scalar is
  `HKDF(R, vt-cache-seckey-v1)` and exists either way, so disabling deletes
  nothing and makes every probe a miss. A hit is not a phone approval: always
  audit it. `cache_hit_notify` independently enables best-effort hit pushes
  and is off by default. Group IDs and creation stamps are immutable.
- Session-gated list/clear need no Passkey; extension requires a verified Passkey
  via `opApprove` -> `commitExtend`, never a session alone, and is offered iff
  `cache_enabled`. Never resurrect expired entries, shorten expiry, or extend
  drifted/no-gain groups; re-read entries with no await before the write, and audit
  authorization plus actual effects. Expiry is approval-time + TTL, not a lifetime
  budget. Keep distinct approve/extend TTL ladders and finite expiries, never
  null/Infinity; policy lives in [cf-worker/src/cache_policy.ts](cf-worker/src/cache_policy.ts).
- Listing exposes no sealed material, salts, or binding ctx digest, and reports
  `truncated`. Clearing must exhaust the `dek:` prefix, report actual deletions,
  and fail loudly if incomplete. Keep every cache-armed audit row's revoke button.
  `audit.cache_ttl_s` stays immutable; only `audit.cache_expires_ms` tracks extension.
  Every multi-key storage `get`/`put`/`delete` is chunked to <= 128 keys.
- Admin is a passkey session: `/admin` and every `/api/admin/*` op are verified
  in the DO (`AccountAdmin.session`), never at the edge; the cookie is
  `__Host-vt_admin` (8 h absolute, MAC'd under `K_sess` from `R`, bound to
  `config.epoch`); every non-GET and the audit-stream upgrade also require
  `Origin == config.origin`. Only bootstrap, login-challenge and login are open,
  and the first two sit behind `LIMITER login:<ip>` (absent → 503). Revoking a
  passkey or 退出所有会话 bumps the epoch; the last credential is never revoked.
  Unconfigured (no readable `root:v1`) fails closed everywhere but `/admin`,
  bootstrap and public assets. A `Cf-Access-Jwt-Assertion` header means nothing.
  `opCreate` decides the UV level from `config.uv_policy` against the verified
  host; the edge decides nothing.
  `pwa/*` (admin included) is public and carries no data: a shell on disk is
  markup plus `{{VT_DATA}}`; data reaches a page only through the shell route
  (state for this cookie) or the gated API. Preserve `STRICT_CSP`, HTML UTF-8 content type, and
  global security headers on fresh responses; template JSON uses
  `escapeJsonForHtml`, never raw interpolation.
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
