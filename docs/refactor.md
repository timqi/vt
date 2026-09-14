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
| Audit-ingest master key | hostname-salted HKDF in `src/audit.rs`, `--audit-key` master form in `src/main.rs`, `/api/audit-ingest` verifier in `index.ts`; the agent pushes with its host token instead | every agent host runs `vt enroll`; needs a Rust + Worker change landed together |

Rule: a compatibility branch is removed, never widened, and its test moves to
a "rejected input" test.

## 2. Landed

The AI-agent hook and the FIDO2 fallback are gone. `cargo check --target
aarch64-apple-darwin` on Linux still stops at `ring`'s C build (rustls via
`reqwest`/`tokio-tungstenite`); macOS-only code is validated on macOS CI.

## 3. Cache key v5

```
dek:{token_id}:{project_h}:{salt_b64u}
```

- `token_id` is the hard boundary; it replaces the Worker-derived IP, which
  becomes audit metadata only. A host on a new egress still hits.
- `project_h = sha256(project)` truncated to 16 bytes. `project` is sent by
  the CLI: `git rev-parse --git-common-dir` (absolute) when inside a
  repository, else the cwd. Client-reported and advisory, as `pwd` was. The
  worktree suffix heuristic `cacheScopePwd` is deleted.
- `meta.pwd` keeps the literal cwd for display; the approval page shows
  `project` where `cache_scope_pwd` was.
- Requests without a `token_id` do not cache (there are none after step 1).
- Tag `vt-dek-ctx-v5`; v4 entries lapse or are cleared from the admin tab.
- Ladders, extension, listing, `truncated`, chunked deletes, audit fields:
  unchanged.

Depends on step 1 (bare-master gone) so `token_id` is always present.

## 4. Decide, then do or drop

- **Agent grant scopes.** `src/core/authorization.rs` + `ssh_agent/scopes.rs`
  are 4k lines for four scope families. Candidate shape: two scopes only —
  `local` (kernel-verified same-user caller) and `destination` (the
  `session-bind@openssh.com` host key on a forwarded connection). Workspace,
  cwd, and parent-app families would go. Needs a decision on how much prompt
  reuse the local path loses.
- **Notification channels.** Feishu and Pushover stay until one is unused for
  a release; Slack App likewise.
- **Record naming.** Not part of this plan; reopen as its own document if
  still wanted after step 3.

## Order

1 → 2 → 3, each behind `cargo test`, `just check`, `just check-worker`, then
a macOS native check for the Keychain and agent changes. Step 4 items are
separate documents when decided.

## Budget

Steps 1–3 remove roughly 5k lines of Rust and 1k of TypeScript and add fewer
than 300. A step that adds net lines names, in its commit, what could not have
been done without them.
