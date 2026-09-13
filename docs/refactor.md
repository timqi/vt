# Slim refactor — targets and order

Status: **plan**. This document owns the `slim` branch: what leaves, what
changes shape, what stays untouched. Each step is one reviewable change; the
row is deleted here when it lands and the owning feature doc is updated in the
same change.

## Keep as is

Two custodies stay: macOS Keychain + Touch ID for the local path, PRF passkey
via the Worker for everything else. `auto` routing (agent first, Worker on
recoverable errors), `inject` including `-r` file mode, `run@vt`, PAM `auth`,
FIDO2 fallback, `diag@vt`, `ui-status@vt`, agent audit push, Worker DEK cache
with its approve/extend ladders and admin, `VT_AUTH_CF_PREV` rotation.

## 1. Delete migration layers

| Leaves | Files | Operator step |
| --- | --- | --- |
| Legacy `vt://mac/` v0/v1 records | `src/core/compat.rs`, `VtUrl::Legacy`, `legacy_decrypt`, legacy branches in `client/records.rs`, `ssh_agent/handlers.rs` | ship one release with `vt rewrap`; the next removes `rewrap` too |
| `vt rewrap` | `src/client/rewrap.rs`, README row | one release after the above |
| Keychain wrap v1 | `derive_passphrase_secret` (v1), `upgrade_wrap_v2_if_needed`, `secret rebind --to-v1` | `vt secret rebind` stays one release for v1 stores, then goes with wrap v1 |
| Worker bare-master auth | `auth.legacy_master` branch in `cf-worker/src/index.ts`, "absent = legacy master" fields in `types.ts`, IP-only cache derivation | every host runs `vt enroll` first |
| Cache ctx v3 mentions | comments in `account_cache.ts`, `dek-cache.md` history | none; v4 entries are re-keyed by step 3 anyway |
| Legacy id-less inject sidecars | `client/inject.rs` mtime-ordering branch | none after one release (sidecars live minutes) |
| `docs/dek-v5-design.md` | replaced by this document and step 3 | none |

Rule: a compatibility branch is removed, never widened, and its test moves to
a "rejected input" test.

## 2. Delete the AI-agent hook

`src/hook.rs`, `docs/hook.md`, `agent.example.toml`, `VT_AGENT_CONFIG`,
`VT_HOOK_BIN`, `vt hook {claude,check,exec,install-shims}`, README and
`docs/README.md` rows, hook rows in `config.example.toml`. `inject --only-env`
stays: it is a user flag, not hook plumbing.

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
- **Record naming** (`dek-v5-design.md` §4). Not part of this plan; reopen as
  its own document if still wanted after step 3.

## Order

1 → 2 → 3, each behind `cargo test`, `just check`, `just check-worker`, then
a macOS native check for the Keychain and agent changes. Step 4 items are
separate documents when decided.

## Budget

Steps 1–3 remove roughly 5k lines of Rust and 1k of TypeScript and add fewer
than 300. A step that adds net lines names, in its commit, what could not have
been done without them.
