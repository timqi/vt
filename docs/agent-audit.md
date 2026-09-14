# Agent audit push (fire-and-forget)

Status: **implemented**. This page documents the wire contract, security
tradeoffs, and provisioning. The implementation is in `src/audit.rs`,
`src/server_macos/audit.rs`, and `cf-worker/src/crypto.ts`; deferred items at
the end are intentionally not part of the current feature.

The macOS SSH agent (`src/server_macos/ssh_agent.rs`) emits one record per
decision (Touch ID approve/reject, silent cache hit) and POSTs it to the
Worker, which inserts it into the ceremony `audit` table marked
`source='agent'`, queryable from the admin shell's 审计 tab at `/admin#audit`
(passkey login).

## Scope — simplified fire-and-forget

- **No local persistence.** After a decision is returned to the caller, the
  agent spawns a one-shot background POST (`audit::spawn_push`). It is never
  awaited → **zero added latency** on the decision path.
- **Loss semantics.** If the agent has no network at decision time the
  record is dropped (it still reaches `tracing` on stderr). A local
  write-ahead buffer is explicitly out of scope (deferred).

## What is audited

All six agent decision points, each with `outcome ∈ {approved, rejected,
unavailable, cache_hit, spawn_failed}`:

| op_kind   | source                              | notes |
|-----------|-------------------------------------|-------|
| `encrypt` | `handle_encrypt`                    | no Touch ID gate → always `approved` ("minted N DEKs"); EncryptReq carries no client meta |
| `decrypt` | `handle_decrypt`                    | emits `cache_hit` on a decrypt-cache hit; `salts` = batch size |
| `auth`    | `handle_auth` (auth@vt)             | always prompts |
| `run`     | `handle_run` (run@vt)               | `approved` at the human tap, **plus** a second `spawn_failed` row if the launch fails (two events, two rows) |
| `sign`    | `Session::sign` (standard SSH auth) | distinct from `auth@vt`; carries no vt ClientMeta, so the prompt label is the audit `command` — the structured `key_fp` / `dest` / `peer_exe` fields carry the key, verified destination, and caller |
| `ssh-sign`| `handle_sign_vt` (`sign@vt`)         | context-carrying git signing; carries `ClientMeta` and shares the sign auth cache |

`latency_ms` measures prompt-shown → decision; cache hits are `0`.

## HMAC key scheme

The agent signs with this Mac's own host token (`vt ssh agent --audit-key
vt1.<id>.<secret>`, the token `vt enroll` writes to the config file): the
token secret is the HMAC key and `agent_id = t:<id>` names it. The Worker's
`SECRET` is a KEK that never reaches a host, so there is no master to derive a
per-host key from; any other `agent_id` form is a rejected input
(`bad agent token id`).

- The **agent** keeps only the 32-byte token secret in memory
  (`host_token_audit_key`, `src/audit.rs`); the flag value remains visible in
  `ps`, as any command-line secret does.
- The **Worker** edge checks the header shape and the 64 KB cap, reads
  `agent_id` (unverified — it only selects the token), and forwards the raw
  bytes plus the MAC to the Durable Object, which derives the token secret
  from the root key (`HKDF(R, token_id, "vt-host-token-v1")`,
  [host-token.md](host-token.md) §1), compares in constant time, and refuses
  a revoked or lapsed token (`isLive`, no sliding — a background push is not a
  use the operator would count).

### Security tradeoff (accepted)

Nothing beyond this host's own `VT_PASSKEY_TOKEN` is present on the agent
host. A compromised agent can therefore forge audit rows **for this host**,
make authenticated `/api/challenge` requests (still gated by a phone approval),
and make `/api/dek-cache` requests that return cached DEKs with **no phone in
the loop** for a project this token already holds a live entry for (see
[dek-cache.md](dek-cache.md)). It does **not** decrypt secrets that aren't
currently cached — the vault master never leaves the phone — and revoking the
token on the 主机令牌 tab ends all of it.

### `agent_id`

`t:<token_id>`, the host token the row is signed with. The display hostname
(`hostname::get()`, falling back to the literal `"unknown"`) rides along in
`meta.host` for the audit table. The `token_id` prefix is capped at 60 chars so
a long hostname never crowds out the random suffix (which would collapse dedup).

## Wire

```
POST {audit_url}/api/audit-ingest
  Authorization: VT-HMAC b64u(HMAC-SHA256(host_token_secret, rawBody))
  body = { timestamp_ms, agent_id, hostname, entry }
    entry = { op_kind, outcome, salts, latency_ms, ts_ms, token_id, meta,
              peer_exe, key_fp, dest, scope_family, scope_label, grant_ttl_s,
              relayed }
      meta = ChallengeMeta wire shape (op_kind, command, host, user, pwd,
             project — '' from the agent, ppid_cmd, reason) — NO `ip` (the
             Worker forces it from CF-Connecting-IP).
```

The seven trailing fields are agent-authoritative context
(docs/approval-transparency.md §B): kernel-verified peer executable, sign key
fingerprint, verified session-bind destination, and the reuse-scope
family/label/TTL the Touch ID prompt displayed, plus the relay flag. The agent
always sends them (`''`/`0`/`false` = not applicable); the Worker stores an
*absent* field (old agent) as SQL NULL — the two stay distinguishable.

Worker `/api/audit-ingest`:
1. reject body > 64 KB (Content-Length + streamed length) → 413
2. parse `agent_id` (unverified — only selects the token); not `t:<token_id>` → 401
3. replay-window check on `timestamp_ms` → 400 on skew
4. `capChallengeMeta(entry.meta, CF-Connecting-IP)` (reuses the ceremony sanitizer)
5. forward to `AccountDO /op/audit-ingest` with the raw bytes and the MAC
6. DO: derive the token secret from the root key, verify `VT-HMAC` (ctEq) →
   401 on mismatch; refuse a revoked/lapsed token → 401 `token_unknown`

DO `auditAgent`: `INSERT … ON CONFLICT(token_id) DO NOTHING` with
`source='agent'`, `created_ms = finalized_ms = ts_ms`. The `token_id`
(`a_<agent_id>_<8 random bytes b64u>`) is the retry-dedup key, structurally
disjoint from the 16-char ceremony tokens and `c_`-prefixed cache rows.

### Retry policy

Per-decision POST, **5 s timeout**, **1 retry only on transport error or 5xx —
never on 4xx** (a 4xx is a permanent rejection; retrying just doubles load). A
5 s budget keeps a single row from ever blocking longer than ~10 s, and it runs
off the decision path regardless.

## `source` column

`audit.source` is `'ceremony'` (default), `'cache'` or `'agent'`;
`auditCreate` and `auditCacheEvent` set theirs explicitly rather than relying
on the default. The admin audit page has a `source` filter and column.

The 90-day retention sweep (`AUDIT_RETENTION_MS`, by `created_ms`) covers agent
rows for free.

The table has no migrations: `AccountAudit.initialize()` compares the existing
column set with `AUDIT_SELECT_COLS` and, on any difference, drops and recreates
the table (one `audit.schema_rebuilt` log line). Retention already bounds what
a rebuild discards; a schema change therefore costs one account's audit history,
never an ALTER path.

## Provisioning

```bash
vt ssh agent --run-allow zed,code \
  --audit-url https://vt.example.com \
  --audit-key "$VT_PASSKEY_TOKEN"      # this Mac's host token (vt1.…, from `vt enroll`)
```

`--audit-key` is the Mac's own host token ([host-token.md](host-token.md)):
its secret is the HMAC key and `agent_id = t:<token_id>`, so the Worker
re-derives the same secret and refuses rows once the token is revoked or has
lapsed. Anything else disables audit push with a warning. The Worker needs
**no new secret**. Audit push is fully opt-in: with `--audit-url` unset (or
`--no-audit-push`, or an empty `--audit-key`, or a non-`https://` URL) the
agent's `spawn_push` is a no-op.

## Deferred

- Local write-ahead buffer for offline durability (jsonl + cursor + compaction).
- Batch ingest (N entries/POST) if volume proves high.
