# Host tokens — per-host `VT_PASSKEY_TOKEN` via `vt enroll`

Status: implemented. Owns the credential a host presents to the Worker, how it
is issued, how long it lives, and what the approval surfaces may trust because
of it. Verify against `cf-worker/src/host_token.ts`, `account_tokens.ts`,
`do_account.ts` (`opEnrollCreate`, `commitEnroll`, `tokens.touch` call sites),
`src/cf.rs` (`WorkerAuth`, `enroll`) and `src/client/commands.rs` (`enroll`).

## 1. Problem

Every host used to hold the Worker master (`VT_PASSKEY_TOKEN == VT_AUTH_CF`).
One leaked config meant rotating the master everywhere, nothing on the approval
page distinguished hosts except a client-typed hostname, and there was no way
to cut a single host off.

## 2. Token model

```
token      = vt1.<token_id>.<secret_b64u>
token_id   = b64u(12 random bytes)                                 (public)
secret     = HKDF-SHA256(ikm = VT_AUTH_CF, salt = token_id,
                         info = "vt-host-token-v1", L = 32)
```

- **Stateless verification at the edge.** The daemon sends
  `Authorization: VT-HMAC <mac>` plus `VT-Token-Id: <token_id>`; the Worker
  re-derives the secret from the master and checks the HMAC before any
  Durable Object round-trip (`readAuthenticatedDaemonBody`). A host only ever
  holds its derived secret; the master never leaves the Worker.
- **Two master generations, so rotation rolls.** When `VT_AUTH_CF_PREV` is
  non-empty and the HMAC does not verify under `VT_AUTH_CF`, the same
  constant-time check runs once more against a secret derived from the previous
  master. Host-token paths only (`/api/challenge`, `/api/dek-cache`, and the
  `t:<token_id>` form of `/api/audit-ingest`): the legacy bare-master and
  hostname-salted branches never fall back, they are being deleted. The
  ordering is unchanged — syntactic `token_id` check before any KDF, body cap
  before crypto. A `prev` verification is logged `auth.prev_master` (path +
  token_id, never key material) and stamped on the row as `last_key_gen`, which
  is what the admin tab reads. See §7.
- **Stateful liveness in the DO.** `host_token` (SQLite,
  `account_tokens.ts`) records `host, user, enroll_ip, origin, created_ms,
  expires_ms, last_used_ms, last_ip, revoked_ms, last_key_gen`. Every authenticated
  `/api/challenge` and `/api/dek-cache` calls `AccountTokens.touch`: unknown /
  revoked / expired → structured `401 {error: token_unknown|token_revoked|
  token_expired}` (the CLI prints "run `vt enroll`"); otherwise
  `expires_ms = now + 7 d` — a **sliding window**, never an accumulating
  budget and never a revival. There is deliberately no hard lifetime cap; the
  admin 主机令牌 tab plus the IP-change hint are the controls.
- **Host/user become verified fields.** On the token path the DO overwrites
  `meta.host` / `meta.user` from the record and sets `meta.ip_prev` when the
  token's previous use came from a different IP. The approval page labels them
  已验证 and `ApprovePageData.host_verified` says which path produced them.
- **Legacy master, migration window only.** A request without `VT-Token-Id`
  is verified against the bare master and logged `auth.legacy_master`; host/user
  stay client-claimed there. Remove this branch once every host has enrolled.

## 3. Enrollment (`vt enroll [--url]`)

1. CLI `POST /api/enroll {host, user, timestamp_ms}` — **unauthenticated**.
   Three independent bounds because this route can page the phone:
   per-IP Workers Rate Limiting (`ENROLL_LIMITER`, 3/min; absent → 503, never
   unthrottled), `ENROLL_PENDING_MAX = 5` concurrently pending enrollments in
   the DO (429), and the normal 5-minute ceremony TTL.
2. The DO mints a ceremony with an immutable `EnrollIntent` (claimed host/user,
   verified `CF-Connecting-IP` and `request.cf` country · AS org, and a
   six-digit **pairing code**). `op_kind='enroll'`, no salts, discarded daemon
   key, `uv: 'required'` regardless of policy — this approval hands out a
   credential. Notifications fan out like any approval.
3. The CLI prints the approve URL and the pairing code; the approval page shows
   the same code (`enroll_pair_code`). Approve only when they match — that is
   what separates this terminal's request from a stranger's concurrent one.
4. On a verified Passkey assertion `commitEnroll` mints the `token_id` and
   inserts the record in the **same synchronous step** as the `approved` put
   (single-use follows from the not-pending guard). The `vt1.…` string is
   re-derived — never stored — and delivered on the poll socket
   (`WsMessage.host_token`), including on reconnect.
5. The CLI writes `VT_PASSKEY_URL` + `VT_PASSKEY_TOKEN` into `$VT_CONFIG` /
   `~/.config/vt/config.toml` (`config::upsert_config_values`: line-based, keeps
   comments, creates mode 600, temp+rename). The token value is never printed.
   Everything after that is the ordinary passkey path.

## 4. Admin

`/<ADMIN_SEG>/tokens` lists every token (no secret material) with host, user,
issue IP · origin, last use / IP (plus a 旧主密钥 marker when `last_key_gen`
is `prev`, counted in the status line), remaining window, and a 吊销 button.
Revocation is authority-reducing, so Cloudflare Access alone suffices (same
rule as cache clears); it is immediate and idempotent. Revoked/lapsed rows stay
listed for 30 days, then the alarm sweep drops them.

## 5. Agent audit push

`vt ssh agent --audit-key vt1.…` uses the Mac's own host token: the secret is
the HMAC key and `agent_id = t:<token_id>`. The Worker derives the same secret,
and the DO refuses rows from a revoked/expired token (`isLive`, no sliding — a
background push is not a use). A bare master still works as before
(`HKDF(master, hostname)`); see [agent-audit.md](agent-audit.md).

## 6. Approval-context trim

Because host/user now come from the token, the ceremony wire meta shrank to
`op_kind, command, pwd, ppid_cmd, reason` (+ Worker `ip`). Dropped: `tty`,
`ppid`, `ssh_client` (never verified, rarely read). Audit columns remain and
read NULL for new rows. Decision record: [approval-transparency.md §2b](approval-transparency.md#2b-host-token-trim).

## 7. Rollout

1. Deploy the Worker with the `ENROLL_LIMITER` binding
   ([cf-worker-deploy.md](cf-worker-deploy.md)). Existing hosts keep working
   on the master (logged as `auth.legacy_master`).
2. On each host: upgrade `vt`, run `vt enroll` (pass `--url` if the file has
   no `VT_PASSKEY_URL` yet), approve on the phone after comparing the pairing
   code. Unset any `VT_PASSKEY_TOKEN` in the environment — env wins over the
   file.
3. Macs running the agent with audit push: switch `--audit-key` to the host
   token written by `vt enroll`.
4. When `auth.legacy_master` stops appearing, delete the legacy branch in
   `readAuthenticatedDaemonBody` and the hostname-keyed audit derivation.

### Rotating the master (rolling, no flag day)

Every host token secret is `HKDF(VT_AUTH_CF, token_id)`, so replacing the master
invalidates them all at once. `VT_AUTH_CF_PREV` makes that a rolling change
instead: the old master keeps verifying while hosts re-enroll one at a time.

1. `wrangler secret put VT_AUTH_CF_PREV` — the value is the **current** master.
2. `wrangler secret put VT_AUTH_CF` — the new master. Deploy is not required;
   secrets take effect on their own. From here a host verifies under either
   generation, and each authenticated use stamps `last_key_gen`.
3. Re-enroll each host (`vt enroll`, phone approval, pairing code) and switch
   any `vt ssh agent --audit-key` to the token it writes. The admin 主机令牌 tab
   marks every host still verifying under the old master 旧主密钥 · 需重新 enroll
   and counts them in the status line; `auth.prev_master` in Workers Logs is the
   same signal.
4. **Set a deadline** and hold to it — two accepted masters is a wider surface
   than one, and a host that never re-enrolls silently keeps an old credential
   alive. At the deadline: `wrangler secret delete VT_AUTH_CF_PREV`. Anything
   still on `prev` breaks immediately and must `vt enroll`; revoke the row on
   the tokens tab if the host is gone. A token minted during the window is
   always derived from the current master, so it starts at `cur`.

The fast path is unchanged when `VT_AUTH_CF_PREV` is empty or absent (the
default): one derivation, one comparison, no fallback.

## 8. Tests

- Worker: `test/host_token.test.ts` (derivation golden vector, token shape,
  pairing code), `test/do_account.host_token.test.ts` (enroll → approve →
  token; challenge/dek-cache auth with sliding expiry and structured refusals;
  legacy path; meta trim; audit ingest with `t:`; admin list/revoke; limiter
  absent → 503; pending cap → 429; the `VT_AUTH_CF_PREV` rotation window —
  cur/prev/neither, PREV absent or empty, `last_key_gen`, and both legacy
  branches refusing the fallback).
- Rust: `cf::tests::worker_auth_parses_host_token_and_legacy_master`,
  `http_post_sends_token_id_header_only_when_given`,
  `config::tests::upsert_*`, `audit::tests::host_token_audit_key_only_for_host_tokens`.
