# Slim refactor — targets and order

Status: **plan**. This document owns the `slim` branch: what leaves, what
changes shape, what stays untouched. Each step is one reviewable change; the
row is deleted here when it lands and the owning feature doc is updated in the
same change.

## Keep as is

Two custodies stay: macOS Keychain + Touch ID for the local path, PRF passkey
via the Worker for everything else. `auto` routing (agent first, Worker on
recoverable errors), `inject` including `-r` file mode, `run@vt`, PAM `auth`,
`diag@vt`, `ui-status@vt`, agent audit push, Worker DEK cache
with its approve/extend ladders and admin.

## 1. Delete migration layers

| Leaves | Files | Operator step |
| --- | --- | --- |
| Keychain wrap v1 | `derive_passphrase_secret` (v1), `upgrade_wrap_v2_if_needed`, `secret rebind --to-v1`, the now-unused AES `mac_cipher` returned by `load_mac_cipher` | `vt secret rebind` stays one release for v1 stores, then goes with wrap v1 |
| Audit SQLite rebuilds | `account_audit.ts`: the `DROP TABLE audit` for the per-event table of an early build and `DROP TABLE IF EXISTS cache_audit`, with their comments | none; one deploy after this release has run on every account |

Landed: the audit-ingest master key (hostname-salted HKDF in `src/audit.rs`,
the `--audit-key` master form, the `/api/audit-ingest` master verifier) went
with worker-slim.md step 5 — the Worker's secret is a KEK now, so there was
nothing left to derive from; `--audit-key` is the Mac's host token only.

Rule: a compatibility branch is removed, never widened, and its test moves to
a "rejected input" test.

## 2. Landed

The AI-agent hook and the FIDO2 fallback are gone. `cargo check --target
aarch64-apple-darwin` on Linux still stops at `ring`'s C build (rustls via
`reqwest`/`tokio-tungstenite`); macOS-only code is validated on macOS CI.

## 3. Landed

Cache key v5 (`dek:{token_id}:{project_h}:{salt}`) is in; `cacheScopePwd` is
gone. Release note: a Worker ahead of the CLI keys every cache on
`project=''` per token; a CLI ahead of the Worker sends an ignored field. No
flag day.

## 4. Decide, then do or drop

- **Agent grant scopes.** `src/core/authorization.rs` + `ssh_agent/scopes.rs`
  are 4k lines for four scope families. Candidate shape: two scopes only —
  `local` (kernel-verified same-user caller) and `destination` (the
  `session-bind@openssh.com` host key on a forwarded connection). Workspace,
  cwd, and parent-app families would go. Needs a decision on how much prompt
  reuse the local path loses.
- **Record naming (decided: server-owned map).** A DO `names` table keyed by
  salt, edited from the console; client-sent names are suggestions the approver
  adopts. Lands with the approve-page trim; owning doc `docs/dek-cache.md`.

## Order

1 → 2 → 3 landed, each behind `cargo test`, `just check`, `just check-worker`, then
a macOS native check for the Keychain and agent changes. Step 4 items are
separate documents when decided.

## Budget

Steps 1–3 remove roughly 5k lines of Rust and 1k of TypeScript and add fewer
than 300. A step that adds net lines names, in its commit, what could not have
been done without them.
