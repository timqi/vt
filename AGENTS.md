# vt coding-agent guide

This is the canonical agent guide; `CLAUDE.md` is a relative symlink to it.
vt is one Rust binary with a macOS SSH-agent transport (Touch ID, Keychain)
and a Cloudflare Worker transport (Passkey/WebAuthn).

## Start here

- [docs/README.md](docs/README.md) owns task-to-document navigation.
  Find the symbol with `rg`, then read its owning doc, implementation, and nearby
  tests before editing. Verify historical plans against code.
- [README.md](README.md) owns installation and CLI quick starts; feature docs own
  procedures and security decisions. This guide owns agent-facing red lines.
- Keep changes scoped. Update the owning doc when behavior, configuration, routes,
  secrets, or security assumptions change. Use stable paths and symbols, not line
  numbers; register new documents in the map. Do not duplicate operator procedures here.

## Documentation

A document holds contracts, facts, and commands. State its purpose and goals;
keep only the design constraints needed to judge future changes. The reasoning
history belongs in the commit that made the decision; the history is `git log`.

- One reason per file, named in its opening: an operator runbook, one area's
  behavior/security contract, or agent instructions. Delete a paragraph that
  does not serve that reason; do not move it into an archive document.
- A rule is one sentence, a fact one bullet, a command a code block. No "what
  it replaced", incident history, completed plans, or justification longer than
  a clause. Keep unresolved work explicitly separate from current contracts.
- Nothing the code already says: no copied types, generated config, directory
  trees, helper call sequences, CSS values, or test-function inventories. Link
  to the owning file. Preserve independent cross-implementation wire contracts.
- One owner per fact. Link from other documents instead of repeating it; merge
  overlapping documents only after removing duplication.
- Keep installation, recovery, and still-required upgrade steps in operator
  runbooks; remove release-specific migration steps when their window ends.
- Write documentation in English; describe localized UI controls in English
  while preserving exact commands, protocol fields, and identifiers.
- A growing document must name what reader need requires the added content.
  After moves or merges, update navigation and all repository references;
  use semantic heading anchors rather than section numbers. Check local links
  and headings. Keep validation limits without narrating tests.

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
   rejected-input test.
6. **No speculative generality.** The third repeat earns an abstraction. No
   knobs, traits, or config keys for a caller that does not exist.
7. **Fail closed, fail loudly.** An unavailable check denies; an error reaches
   the operator as a stable structured code. A silent fallback is a bug even
   when it works.
8. **Minimal dependencies.** Std first, then audited crypto staples and the
   platform SDKs. A new runtime dep names in its commit what code it deletes.
   `Cargo.lock` / `package-lock.json` diffs are reviewed on upgrade.

## Budgets

Line counts are a proxy for growth and duplication, not a reason to weaken code.

- Net growth names in the commit what the feature could not have been without it.
- Split a module only when it has two reasons to exist; splitting is not reduction.
- Fix or delete the third copy; report a copy-paste pair past ~30 lines at two.
- Never trim tests, failure paths, fresh approval, lock/epoch invalidation,
  structured errors, or type/seam declarations to meet a number.
- An exceeded ceiling needs deletion or a justified raise within one release.
  Explain what belongs there; run `just size` for current counts.

| Area | Ceiling | Counted scope |
| --- | --- | --- |
| `src/core/` | 1.7k | `core.rs` + `core/` |
| `src/client/` | 1.8k | `client.rs` + `client/` |
| `src/server_macos/` | 4.5k | macOS server tree |
| root `src/*.rs` | 2.7k | root modules excluding `core.rs` / `client.rs`, plus `config/` (includes `hook.rs`, the shim exec-gateway) |
| `cf-worker/src/` | 4.1k | Worker TypeScript |
| one module | 750 | consider responsibilities before splitting |

Non-blank, non-comment lines; `#[cfg(test)]` and `*.test.ts` excluded. No
repo-wide number.

## Configuration and data handling

Routing and precedence: [config.example.toml](config.example.toml).
Errors and fallback classes: [docs/structured-errors.md](docs/structured-errors.md).

- Environment overrides config; `VT_CONFIG` selects the file (mode 600).
  `VT_BACKEND` alone selects routing: `auto` tries an existing agent socket and
  falls back only on recoverable errors; `agent` / `passkey` pin the transport.
  Never silently broaden fallback.
- Wrappers use `inject --only-env` to limit environment-variable decryption.
  Shim rules are separate: `~/.config/vt/agent.toml`, overridden by
  `VT_AGENT_CONFIG`. Preserve default-accept, inject only when a configured rule
  names a resolved `vt://` variable, and keep the self-resolution guards. The
  shims are not a sandbox. See [docs/hook.md](docs/hook.md).
  Plaintext secrets and private seeds never enter logs, examples, or test output.
  Do not add disk/argv exposure beyond explicit product flows such as injection.
- Preserve structured extension envelopes and stable exit codes; error details
  must not reflect client data.
- Notifications never block or fail protected operations. Agent cache-hit notices
  run after `permit.commit()` returns, fire-and-forget. Worker channels are Web
  Push and the Slack Bot; fan-out uses `waitUntil` after the ceremony write, never
  a CLI warning. Only the Slack message handle is written back to a challenge,
  never status. See [local notifications](docs/app-bundle.md#notifications),
  [Web Push](docs/worker-slim.md#web-push) and [Slack](docs/slack.md).

## Transient file injection

Usage: [README.md](README.md#inject-command). Recovery mechanics and tests:
[src/client/inject.rs](src/client/inject.rs). Preserve these race boundaries:

- The self-exec restore supervisor dispatches before Tokio/clap initialization.
  `--recover` stays unauthenticated and restores ciphertext only.
- The deterministic `.{name}.vt-backup` IS the exposure lock: create with `O_EXCL`
  before plaintext reaches disk, refuse overlap and files without `vt://` records.
  Clean up a newly created backup if filling it or obtaining its generation fails;
  never remove another exposure's lock or randomize the backup name.
- Restore by atomic `rename`, never copy+delete. Every sidecar and every parent /
  supervisor failure path checks the armed `(dev, ino)`, and every backup create
  and check+rename holds the parent-directory `flock` (`lock_backup_dir`); a lock
  failure refuses to arm and leaves backup and record in place. Id-less records are unknown
  state: never parse, restore, or retire them. Arming retires stale sidecars for
  that backup path; recovery checks generation and mtime against the recorded
  deadline, including a re-probe after publication cancellation. Never restore a successor.
- Preserve recovery records on cancellation/restore failure or unknown backup state;
  stat errors are not absence. Cleanup requires successful restoration or a known
  gone/superseded generation.
- Reserve the empty publication temp before arming; write only through its held fd,
  never recreate its path. Every restorer cancels publication before consuming the
  backup; cancellation failure preserves backup and recovery record. Record the
  deadline before supervisor startup so stalled startup remains recoverable.

## SSH-agent authorization

Authorization and scopes: [unified-authorization-engine.md](docs/unified-authorization-engine.md).
Lifecycle, status token, and Keychain format: [app-bundle.md](docs/app-bundle.md).

- All auth/run/sign/decrypt/encrypt operations use the unified engine. `auth@vt` /
  `run@vt` / `encrypt@vt` / protocol `ssh-add` always require fresh approval;
  non-v2 decrypt envelopes are `BadRequest`.
  Duration `0` means `Fresh`, never `StrictTtl(0)`. Reusable grants remain scoped
  by operation, subject, and resource.
- Commit the non-cloneable permit only after operation success AND envelope
  serialization; failure drops without a grant. A live permit blocks revocation:
  no unbounded-latency work while held.
- Lock, idle, observed screen lock, and detected wake advance the epoch even with
  no grants; live locked/non-interactive failures revoke grants. Screen lock/wake
  and idle also wipe decrypted SSH keys. Reload checks interactivity before AND
  after Keychain I/O; idle timeout stays >= 60s.
- Preserve scope families: verified destination, kernel-derived workspace, exact
  cwd, then parent app for broad shared cwds. Forwarding-capable/tainted raw signs
  never cache; relay/SSH-carried vt extensions stay per-connection, never local.
  `session-bind@openssh.com` stays SSH-wire, before the lock check, without idle activity.
- Prompts state reusable scope; agent truth precedes client claims.
  See [approval-transparency.md](docs/approval-transparency.md).
- `run@vt` is agent-only, allowlist-gated, with no child output/exit code. Never
  expose it through the Worker or `--forward-real-agent`; that relay forwards only
  encrypt/decrypt/auth/sign/diag, unparsed. See [sign-vt-design.md](docs/sign-vt-design.md).
- `diag@vt` is plaintext, read-only, prompt-free, not audit-pushed, and never resets
  idle. Count only caller-reusable grants; never-cache callers report 0.
  See [authorization visibility](docs/unified-authorization-engine.md#visibility).
- Only `ui-status@vt` exposes all grants: before lock checks and Keychain reads,
  gated by constant-time comparison of the 32-byte spawn token piped to
  `--ui-token-fd` (never env/argv/file; absent/wrong token fails unstructured).
  Only status and revoke-all; never grant/extend/approve, reset idle, or audit-push.
  Display labels stay memory-only.
- New stores are wrap v3 (Secure Enclave, `se.rs`, `biometryCurrentSet`); wrap
  v2 is read only by `rotate-passcode` this release; reject other `wrap_v`
  values before unwrapping. Never re-add a v1 reader, in-binary upgrade, or
  rebind command. SE sessions are one-shot and live only in `SeSessions`: a
  biometric approval leaves one pending session that its permit drops and
  `invalidation_complete` clears; `master_for` fails closed on a cache hit.
  Repeat authorization never touches the SE: decrypt hits serve the DEKs cached
  as grant material, sign hits use resident keys. The master is unwrapped inside
  a handler scope and never held across an await or a prompt. Public SSH keys
  are plaintext; private keys reload only through a freshly approved sign. `init`/`import` never replace a
  store they could not read; import over a readable store is a same-master
  re-wrap proven by its SSH keys. Migration belongs in the app doc.

## Worker cache and admin

Root, admin, and host authority: [worker-slim.md](docs/worker-slim.md).
Cache storage, TTL ladders, and UI: [dek-cache.md](docs/dek-cache.md).

- `SECRET` is the only Wrangler secret and only a KEK; other derived keys come
  from root `R`, unwrapped only in DO memory. Rotation permits at most two wraps.
  An unreadable root fails closed as unconfigured (`config.unreadable` once).
  No `[vars]`: config lives in the DO; only `cache_hit_notify` / `uv_policy` /
  `slack` are mutable settings, and bootstrap origin stays immutable. The Slack
  bot token is write-only: the console API reports only that one is set.
- Every daemon request, audit push included, requires a live per-host token.
  Verify its MAC in constant time in the DO before token access; never revive
  expired/revoked tokens or store token secrets. Issue only via `opApprove` →
  `commitEnroll`; host/user come from the token record, never the body.
  Preserve enrollment rate limiting (absent `LIMITER` → 503), pending cap, and pairing code.
- Derive cache keys only in `cacheCtx` for reads and writes; refuse missing
  `token_id`. Client project is advisory; preserve literal pwd and show project
  beside approval duration controls. Record names are operator-owned: client
  suggestions stay self-reported until verified adoption or session-gated rename.
- Default approval `0` means no cache; no cache switch. Cache hits always audit,
  never count as phone approval. Hit pushes are independent and off by default.
  Entries are individual, with immutable `created_ms` and finite expiries.
- Session permits list/clear; extension needs verified Passkey via `opApprove` →
  `commitExtend`, one token + project per ceremony. Never resurrect, shorten, or
  write a no-gain entry. Re-read without await before writing; audit authorization
  and actual effects. Expiry is approval-time + TTL; preserve distinct TTL ladders.
- List live entries only, report truncation, expose no sealed material/storage key.
  Named clears delete exact keys; clear-all exhausts the prefix. Report actual
  deletions and fail loudly if incomplete. Multi-key storage operations use <= 128 keys.
- Cache revocation belongs on the cache tab; audit deletion is retention-only,
  never a clear-audit op. `audit.cache_ttl_s` is immutable; extension updates only
  `audit.cache_expires_ms`.
- The DO verifies admin sessions and decides UV against the verified host; the
  edge never authorizes. Sessions have absolute expiry and bind to config epoch;
  mutations and audit-stream upgrades require matching Origin. Passkey revocation
  and revoke-all-sessions bump epoch; never revoke the last credential.
- Preserve the documented bootstrap/login exceptions and their rate limits
  (absent limiter → 503). Unconfigured allows only admin shell, bootstrap, and
  public assets; Cloudflare Access headers grant nothing.
- Public PWA shells contain no data. Inject data only through gated routes/APIs;
  use `escapeJsonForHtml`, preserve `STRICT_CSP`, HTML UTF-8, and global security
  headers. Real secrets never belong in TOML examples.

## Validation and deployment entry points

Run focused tests before the relevant repository gates: `cargo test`, `just check`
(host + Linux GNU Rust checks), and `just check-worker` (dependency setup,
TypeScript + Vitest). `just check-darwin` type-checks `server_macos` from Linux;
nothing on Linux runs it or native Touch ID/Keychain/UI behavior — use macOS
CI and native checks where needed.
Report checks not run. Recipes live in [justfile](justfile).

Worker deployment: [docs/cf-worker-deploy.md](docs/cf-worker-deploy.md),
`just deploy-worker`; PWA changes need `just bump-assets` first (no bundling step).
macOS packaging/install: [docs/app-bundle.md](docs/app-bundle.md), `just app` /
`just install-app`. Follow these operator procedures; tests are not a deployment.
