# Agent audit push (fire-and-forget)

The macOS SSH agent (`src/server_macos/ssh_agent.rs`) historically wrote **no
durable audit** — every Touch ID approve/reject and every silent auth-cache hit
went only to `tracing` on stderr and was lost. The Cloudflare passkey ceremony,
by contrast, writes a rich `audit` table inside the `AccountDO` Durable Object.

This feature gives the agent path the **same admin-audit visibility**: it emits
one record per decision and POSTs it to the Worker, which inserts it into the
existing `audit` table marked `source='agent'`, queryable from the Access-gated
admin page at `/<ADMIN_SEG>/audit`.

## Scope — simplified fire-and-forget

- **No local persistence.** After a decision is returned to the caller, the
  agent spawns a one-shot background POST (`audit::spawn_push`). It is never
  awaited → **zero added latency** on the decision path.
- **Loss semantics = net add.** If the agent has no network at decision time the
  record is dropped — exactly what `tracing::info!` did before, just with a
  cloud sink. Online → now queryable; offline → same as before. A local
  write-ahead buffer is explicitly out of scope (deferred).

## What is audited

All five agent decision points, each with `outcome ∈ {approved, rejected,
unavailable, cache_hit, spawn_failed}`:

| op_kind   | source                              | notes |
|-----------|-------------------------------------|-------|
| `encrypt` | `handle_encrypt`                    | no Touch ID gate → always `approved` ("minted N DEKs"); EncryptReq carries no client meta |
| `decrypt` | `handle_decrypt`                    | emits `cache_hit` on a decrypt-cache hit; `salts` = batch size |
| `auth`    | `handle_auth` (auth@vt)             | always prompts |
| `run`     | `handle_run` (run@vt)               | `approved` at the human tap, **plus** a second `spawn_failed` row if the launch fails (two events, two rows) |
| `sign`    | `Session::sign` (standard SSH auth) | distinct from `auth@vt`; carries no vt ClientMeta, so the prompt label is the audit `command` |

`latency_ms` measures prompt-shown → decision; cache hits are `0`. `ppid` is the
**socket peer PID** (`get_peer_pid`), `0`/absent for forwarded sessions — NOT the
agent's own ppid.

## HMAC key scheme

```
agent_audit_key = HKDF-SHA256(
    ikm  = VT_AUTH_CF (worker master, == VT_PASSKEY_TOKEN),
    salt = agent_id   (= the machine hostname, UTF-8 bytes),
    info = "vt-agent-audit-v1",
    L    = 32)
```

- The **agent** is given the master `VT_AUTH_CF` via `--audit-key` and derives
  its per-host subkey `agent_audit_key = HKDF(VT_AUTH_CF, hostname, …)` ONCE at
  startup, keeping only the 32-byte subkey in memory (the raw master is dropped
  after derivation, though it remains visible in `ps` via the flag).
- The **Worker** holds `VT_AUTH_CF`. On each ingest it reads `agent_id` (the
  hostname) from the (still-unverified) body, re-derives the same subkey, then
  verifies the `VT-HMAC` over the raw body. Parsing `agent_id` before
  verification is safe — it only selects which key to derive; a forged value
  yields a key that won't verify. One HKDF per request is negligible; the 64 KB
  body cap + 401-on-bad-HMAC bound abuse.
- Derivation is shared and golden-vector-pinned across implementations:
  Rust `derive_agent_audit_key` (`src/audit.rs`) ⇔ TS `hkdfSha256`
  (`cf-worker/src/crypto.ts`).

### Security tradeoff (accepted)

This is the zero-token design: no pre-derivation, no per-agent secret file —
just `--audit-url` + `--audit-key`. The cost is that the worker master
`VT_AUTH_CF` is present on the agent host. A compromised agent can therefore:

- forge audit rows for **any** hostname;
- make authenticated `/api/challenge` requests — still gated by a phone approval;
- make authenticated `/api/dek-cache` requests — these return cached DEKs with
  **no phone in the loop** for the same egress IP within the TTL window (the
  same IP binding the CLI already relies on, see `docs/dek-cache.md`).

It does **not** by itself decrypt secrets that aren't currently cached — the
vault master never leaves the phone. On a Mac that already sets
`VT_PASSKEY_TOKEN` for the ceremony fallback the master is present anyway, so
`--audit-key` adds no new exposure.

The per-hostname HKDF is retained (rather than signing with the raw master) so
the Worker stays unchanged and the wire is per-host-keyed — making it trivial to
move back to an off-agent pre-derivation model later if the tradeoff stops being
acceptable.

### `agent_id`

The machine hostname (`hostname::get()`). Stable and unique enough for a small
fleet; carried in the body and used as the HKDF salt. (If two hosts ever share a
hostname they'd share a key — fine for single-Mac use.) `get_hostname()` falls
back to the literal `"unknown"` if the lookup fails, so such a host still pushes
(rows labelled `unknown`, sharing one key) — a monitoring blind spot, not a
security gap. The `token_id` prefix is capped at 60 chars so a long hostname
never crowds out the random suffix (which would collapse dedup).

## Wire

```
POST {audit_url}/api/audit-ingest
  Authorization: VT-HMAC b64u(HMAC-SHA256(agent_audit_key, rawBody))
  body = { timestamp_ms, agent_id, hostname, entry }
    entry = { op_kind, outcome, salts, latency_ms, ts_ms, token_id, meta }
      meta = ChallengeMeta wire shape (op_kind, command, host, user, pwd, tty,
             ppid_cmd, ppid, ssh_client, reason) — NO `ip` (the Worker forces it
             from CF-Connecting-IP).
```

Worker `/api/audit-ingest`:
1. reject body > 64 KB (Content-Length + arrayBuffer length) → 413
2. parse `agent_id` (unverified — only selects the key)
3. derive key = HKDF-SHA256(VT_AUTH_CF, agent_id, "vt-agent-audit-v1", 32)
4. verify `VT-HMAC` over raw body (ctEq) → 401 on mismatch
5. replay-window check on `timestamp_ms` → 400 on skew
6. `capChallengeMeta(entry.meta, CF-Connecting-IP)` (reuses the ceremony sanitizer)
7. forward to `AccountDO /op/audit-ingest`

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

Added to the `audit` table via a guarded `ALTER TABLE audit ADD COLUMN source
TEXT NOT NULL DEFAULT 'ceremony'` (SQLite backfills existing rows from the
literal default). `auditCreate` sets `'ceremony'` and `auditCacheEvent` sets
`'cache'` explicitly (not relying on the default) so a future schema change
can't silently mis-categorize. The admin audit page gains a `source` filter
(all / ceremony / cache / agent) and column.

The 90-day retention sweep (`AUDIT_RETENTION_MS`, by `created_ms`) covers agent
rows for free.

## Provisioning

```bash
vt ssh agent --run-allow zed,code \
  --audit-url https://vt.example.com \
  --audit-key "$VT_PASSKEY_TOKEN"      # the worker master (== VT_AUTH_CF)
```

No pre-derivation, no per-agent file: the agent derives its per-host subkey from
`--audit-key` + its hostname at startup. The Worker needs **no new secret** — it
reuses `VT_AUTH_CF`. Audit push is fully opt-in: with `--audit-url` unset (or
`--no-audit-push`, or an empty `--audit-key`, or a non-`https://` URL) the
agent's `spawn_push` is a no-op.

## Deferred

- Local write-ahead buffer for offline durability (jsonl + cursor + compaction).
- Batch ingest (N entries/POST) if volume proves high.
