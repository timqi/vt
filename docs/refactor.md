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
| Audit SQLite rebuilds | `account_audit.ts`: the `DROP TABLE audit` for the per-event table of an early build and `DROP TABLE IF EXISTS cache_audit`, with their comments | none; one deploy after this release has run on every account |

Rule: a compatibility branch is removed, never widened, and its test moves to
a "rejected input" test.

## 2. Decide, then do or drop

- **Agent grant scopes.** `src/core/authorization.rs` + `ssh_agent/scopes.rs`
  are 4k lines for four scope families. Candidate shape: two scopes only —
  `local` (kernel-verified same-user caller) and `destination` (the
  `session-bind@openssh.com` host key on a forwarded connection). Workspace,
  cwd, and parent-app families would go. Needs a decision on how much prompt
  reuse the local path loses.
