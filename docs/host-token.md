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
  holds its derived secret; the master never leaves the Worker. A request
  without `VT-Token-Id` is refused before its body is read with the same
  structured `401 {error: token_missing}` a dead token gets: the master is
  never accepted as a daemon key, and the DO likewise fails closed (400) on an
  op body without a `token_id`.
- **One master, one derivation.** There is no previous-generation fallback:
  rotating `VT_AUTH_CF` invalidates every token at once (§7). Ordering:
  syntactic `token_id` check before any KDF, body cap before crypto, one
  constant-time comparison.
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
issue IP · origin, last use / IP, remaining window, and a 吊销 button.
Revocation is authority-reducing, so Cloudflare Access alone suffices (same
rule as cache clears); it is immediate and idempotent. Revoked/lapsed rows stay
listed for 30 days, then the alarm sweep drops them.

## 5. Agent audit push

`vt ssh agent --audit-key vt1.…` uses the Mac's own host token: the secret is
the HMAC key and `agent_id = t:<token_id>`. The Worker derives the same secret,
and the DO refuses rows from a revoked/expired token (`isLive`, no sliding — a
background push is not a use). `--audit-key` alone still accepts the master
(`HKDF(master, hostname)`); see [agent-audit.md](agent-audit.md).

## 6. Approval-context trim

Because host/user now come from the token, the ceremony wire meta shrank to
`op_kind, command, pwd, ppid_cmd, reason` (+ Worker `ip`). Dropped: `tty`,
`ppid`, `ssh_client` (never verified, rarely read). Audit columns remain and
read NULL for new rows. Decision record: [approval-transparency.md §2b](approval-transparency.md#2b-host-token-trim).

## 7. Rollout

1. Deploy the Worker with the `ENROLL_LIMITER` binding
   ([cf-worker-deploy.md](cf-worker-deploy.md)). A host still holding the bare
   master is refused with `token_missing` until it enrolls.
2. On each host: upgrade `vt`, run `vt enroll` (pass `--url` if the file has
   no `VT_PASSKEY_URL` yet), approve on the phone after comparing the pairing
   code. Unset any `VT_PASSKEY_TOKEN` in the environment — env wins over the
   file.
3. Macs running the agent with audit push: switch `--audit-key` to the host
   token written by `vt enroll`; the hostname-keyed audit derivation is the
   one legacy branch left.

### Rotating the master (flag day)

Every host token secret is `HKDF(VT_AUTH_CF, token_id)`, so replacing the master
invalidates them all at once; there is deliberately no second accepted
generation (two masters is a wider surface, and a host that never re-enrolls
would keep an old credential alive).

1. `wrangler secret put VT_AUTH_CF` — the new master. Deploy is not required;
   secrets take effect on their own. From here every existing token fails with
   `hmac mismatch` and the agent audit push is refused the same way.
2. The same day, on each host: `vt enroll` (phone approval, pairing code) and
   switch any `vt ssh agent --audit-key` to the token it writes. Revoke the
   rows of hosts that are gone on the tokens tab; the rest lapse in 7 days.

## 8. Tests

- Worker: `test/host_token.test.ts` (derivation golden vector, token shape,
  pairing code), `test/do_account.host_token.test.ts` (enroll → approve →
  token; challenge/dek-cache auth with sliding expiry and structured refusals;
  bare master and token-less DO bodies refused; meta trim; audit ingest with
  `t:`; admin list/revoke; limiter absent → 503; pending cap → 429; master
  rotation refusing old-master tokens on every route).
- Rust: `cf::tests::worker_auth_parses_host_token_and_rejects_bare_master`,
  `http_post_sends_token_id_header_only_when_given`,
  `config::tests::upsert_*`, `audit::tests::host_token_audit_key_only_for_host_tokens`.
