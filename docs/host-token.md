# Host tokens — per-host `VT_PASSKEY_TOKEN` via `vt enroll`

Status: implemented. Owns the credential a host presents to the Worker, how it
is issued, how long it lives, and what the approval surfaces may trust because
of it. Verify against `cf-worker/src/host_token.ts`, `account_tokens.ts`,
`account_admin.ts` (`hostTokenSecret`, `verifyHostMac`), `do_account.ts`
(`authenticateDaemon`, `opEnrollCreate`, `commitEnroll`), `src/cf.rs`
(`WorkerAuth`, `enroll`) and `src/client/commands.rs` (`enroll`).

## 1. Problem

Every host used to hold the Worker master. One leaked config meant rotating
the master everywhere, nothing on the approval page distinguished hosts except
a client-typed hostname, and there was no way to cut a single host off.

## 2. Token model

```
token      = vt1.<token_id>.<secret_b64u>
token_id   = b64u(12 random bytes)                                 (public)
secret     = HKDF-SHA256(ikm = R, salt = token_id,
                         info = "vt-host-token-v1", L = 32)
```

`R` is the Worker's root key: 32 random bytes generated at bootstrap, stored
wrapped under `SECRET` and unwrapped only into Durable Object memory
([worker-slim.md](worker-slim.md) §2). Nothing else derives host tokens.

- **Shape at the edge, MAC in the DO.** The daemon sends
  `Authorization: VT-HMAC <mac>` plus `VT-Token-Id: <token_id>`. The edge
  checks the header shapes, refuses a missing `VT-Token-Id` before reading the
  body with the same structured `401 {error: token_missing}` a dead token gets,
  caps and reads the body (`readDaemonBody`), and forwards the exact bytes and
  the MAC with the op. The DO — the only holder of `R` — derives the secret,
  compares in constant time (`verifyHostMac`), then checks liveness
  (`authenticateDaemon`); nothing is stored or pushed before both pass, and an
  op body without `auth` fails closed (400). A host only ever holds its own
  derived secret. Cost of the split: a request with a bad MAC reaches the DO
  once; the JSON parse and salt validation at the edge run on capped,
  unauthenticated input. The `/api/audit-ingest` route follows the same path.
- **One root, one derivation.** There is no previous-generation fallback: a
  factory reset (new `R`) invalidates every token at once (§7); rotating
  `SECRET` through the console keeps `R` and every token.
- **Stateful liveness in the DO.** `host_token` (SQLite,
  `account_tokens.ts`) records `host, user, enroll_ip, origin, created_ms,
  expires_ms, last_used_ms, last_ip, revoked_ms`. Every authenticated
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
## 3. Enrollment (`vt enroll [--url]`)

1. CLI `POST /api/enroll {host, user, timestamp_ms}` — **unauthenticated**.
   Three independent bounds because this route can page the phone:
   per-IP Workers Rate Limiting (`LIMITER`, key `enroll:<ip>`, 3/min; absent →
   503, never unthrottled), `ENROLL_PENDING_MAX = 5` concurrently pending
   enrollments in the DO (429), and the normal 5-minute ceremony TTL.
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

The admin shell's 主机令牌 tab (`/admin#tokens`, passkey login —
[worker-slim.md](worker-slim.md) §3) lists every token (no secret material)
with host, user, issue IP · origin, last use / IP, remaining window, and a
吊销 button. Revocation is authority-reducing, so the admin session alone
suffices (same rule as cache clears); it is immediate and idempotent.
Revoked/lapsed rows stay listed for 30 days, then the alarm sweep drops them.

## 5. Agent audit push

`vt ssh agent --audit-key vt1.…` uses the Mac's own host token: the secret is
the HMAC key and `agent_id = t:<token_id>`. The DO derives the same secret and
refuses rows from a revoked/expired token (`isLive`, no sliding — a background
push is not a use). Nothing else is accepted as an audit key; see
[agent-audit.md](agent-audit.md).

## 6. Approval-context trim

Because host/user now come from the token, the ceremony wire meta shrank to
`op_kind, command, pwd, ppid_cmd, reason` (+ Worker `ip`). Dropped: `tty`,
`ppid`, `ssh_client` (never verified, rarely read). Audit columns remain and
read NULL for new rows. Decision record: [approval-transparency.md §2b](approval-transparency.md#2b-host-token-trim).

## 7. Rollout

1. Deploy the Worker with the `LIMITER` binding and bootstrap it
   ([cf-worker-deploy.md](cf-worker-deploy.md)). A host holding a token from a
   previous root (the `VT_AUTH_CF` build, or a reset) is refused with
   `hmac mismatch`; one without a token with `token_missing`.
2. On each host: upgrade `vt`, run `vt enroll` (pass `--url` if the file has
   no `VT_PASSKEY_URL` yet), approve on the phone after comparing the pairing
   code. Unset any `VT_PASSKEY_TOKEN` in the environment — env wins over the
   file.
3. Macs running the agent with audit push: `--audit-key` is the host token
   written by `vt enroll`; nothing else is accepted.

### Rotation and reset

Rotating `SECRET` (设置 → 轮换 SECRET, then `wrangler secret put SECRET`)
keeps `R`, so every token keeps verifying. A **factory reset** — a fresh
`SECRET` without that rotation, then bootstrap again — mints a new `R` and
invalidates every token at once; there is deliberately no second accepted
generation (two roots is a wider surface, and a host that never re-enrolls
would keep an old credential alive). The same day, on each host: `vt enroll`
(phone approval, pairing code) and switch any `vt ssh agent --audit-key` to the
token it writes. Revoke the rows of hosts that are gone on the tokens tab; the
rest lapse in 7 days.

## 8. Tests

- Worker: `test/host_token.test.ts` (derivation golden vector, token shape,
  pairing code), `test/do_account.host_token.test.ts` (enroll → approve →
  token; challenge/dek-cache auth with sliding expiry and structured refusals;
  token-less signatures and auth-less DO bodies refused; meta trim; audit
  ingest with `t:` and the hostname form rejected; admin list/revoke; limiter
  absent → 503; pending cap → 429; `SECRET` rotation keeping every token and
  retiring the old wrap; reset refusing old-root tokens on every route).
- Rust: `cf::tests::worker_auth_parses_host_token_and_rejects_bare_master`,
  `http_post_sends_token_id_header_only_when_given`,
  `config::tests::upsert_*`, `audit::tests::host_token_audit_key_only_for_host_tokens`.
