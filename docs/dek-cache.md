# DEK cache

Status: **implemented**. This is the current behavior reference for the
approval-time cache. The cache is an explicit security tradeoff: during its
TTL, a caller can decrypt the approved records without another phone tap.

## Current contract

- Approve-time TTL choices are `0`, `20m`, `2h`, and `8h`. `0` is the default and
  means no cache write. This ladder is deliberately short: the tap happens on a
  phone, in a hurry, and a mis-tap widens the window for the whole batch.
- The admin extension ladder is a superset — `20m`, `2h`, `8h`, `1d`, `2d`, `1w`,
  plus a 100-year rung that is permanent in practice —
  because an extension is a deliberate, desk-bound act on named live entries,
  reviewed on the approval page before the tap. The multi-day rungs also make the
  feature useful at all: with the ceiling pinned to `8h`, an `8h` grant sat at its
  ceiling from birth and every extension of it was a no-op.
- The cap is **per operation, not per lifetime**: one extension sets each
  selected entry's expiry to `now + chosen TTL`, and an entry may be renewed
  indefinitely — one Passkey-approved hop at a time. The longest single hop
  is the top rung of `EXTEND_TTL_WHITELIST`; trimming the ladder shortens it.
- What bounds renewal is **liveness, not a budget**: an extension can only continue
  a window that has not yet lapsed. Once a cache expires it is gone for good and
  only a fresh phone approval can arm a new one.
- The 100-year rung deliberately gives up that bound for the records it is applied
  to. It is a FINITE far-future expiry (year ~2126), not a null/Infinity sentinel,
  so `opDekCache`'s read check, the alarm sweep, `audit.cache_expires_ms`, and the
  admin countdown all stay on their normal code path — expiry logic is where a
  missed special case becomes a cache that outlives its revocation. Nothing revokes
  such an entry but an explicit admin clear or a factory reset, it is never
  swept, and there is no expiry to prompt a future review; pair it with
  缓存命中时推送通知 (`cache_hit_notify`) so each no-tap decrypt stays visible
  somewhere. The UI
  renders it with the ordinary duration formatter (`36500 天`) rather than a special
  "permanent" label, so no reader has to trust a word over a number.
- There is no cache switch. Every approval page with DEKs to cache offers the
  ladder; the first option, `0` = `不缓存`, is the default and IS the no-cache
  path (the phone seals nothing to the cache key, so the Worker has nothing to
  store). The X25519 scalar entries are sealed to is
  `HKDF(R, "vt-cache-seckey-v1")` of the Durable Object's root key
  (`AccountAdmin.cacheSeckey`); nothing rotates it but a factory reset. There is
  no `VT_DEK_CACHE` environment variable and no separate client-side no-cache
  flag; 清除全部 on the DEK 缓存 tab is the emergency off.
- **Record names** are operator-owned display labels keyed by a record's
  16-byte salt — the only identity of a record the Worker ever sees. The DO
  table `names(salt_b64u PRIMARY KEY, name, source, ms)`
  (`cf-worker/src/account_names.ts`) has no expiry; a name is ≤ 40 characters
  and not unique. The CLI MAY send `meta.names` (one per salt, `""` when
  unknown — `inject` sends the env var name or the file's basename, `vt read`
  of a bare URL sends `""`) on challenge and dek-cache requests; the edge
  refuses a miscounted or oversize array (400). A suggestion is shown as
  自报; an unnamed record gets a name input on the approval page, the
  suggestion a one-tap chip that fills it. Non-empty inputs post with the
  approval as `adopt_names: [{index, name}]` (≤ 40 chars, control characters
  stripped; an out-of-range, duplicate or oversize entry is a 400 and nothing
  is stored) and are written after the assertion verifies, never over an
  owned name, `source='client'` when the name equals the suggestion, else
  `'manual'`; or the console renames the record
  (`PUT /api/admin/names {salt_b64u, name}`, session-gated, `""` deletes,
  `source='manual'`). Audit rows store `[salt, claimed]` pairs and resolve
  them on every read, so a rename retitles history; cache entries keep the
  claim and the `project`; the cache listing, the extension summary, the hit
  audit row and the hit push show the resolved name, else the claim tagged 自报, else the salt's
  first 8 characters (`K0g8nyJ5…`, the same handle on every surface, in
  `code` on the console). Audit rows also carry the challenge's `project`
  (NULL when the challenge carried none): its directory name sits beside the host,
  the full path in the detail sheet.
- A cache key is `dek:{token_id}:{project_h}:{salt_b64u}`. `token_id` is the
  host token the edge verified on the request ([host-token.md](host-token.md))
  and the **hard boundary**: a grant serves only the host that earned it, from
  any egress IP. `project_h = b64u(SHA-256("vt-dek-ctx-v5" ‖ project)[0..16])`,
  where `project` is client-reported and **advisory**: a same-host blast-radius
  reducer, never a trust boundary. The Worker-derived IP, `pwd`, and `ppid_cmd`
  are audit metadata only.
- `project` is what the CLI sends in `ChallengeMeta` ([`src/cf.rs`](../src/cf.rs)
  `project_dir`): `git rev-parse --git-common-dir`, resolved to an absolute
  path, when the cwd is inside a repository; otherwise the cwd. Git absent or
  failing falls back to the cwd silently. Every worktree of one repository
  therefore shares one cache scope, and two unrelated trees on one host do not.
  `meta.pwd` keeps the literal directory in the approval page, notifications,
  audit rows, and the admin listing; the approval page states the scope it would
  arm (`缓存范围（项目）`, from `metadata.project`) directly above the duration
  radios, next to the literal `目录` row.
- The key is derived inside `cacheCtx`
  ([`cf-worker/src/account_cache.ts`](../cf-worker/src/account_cache.ts)), never
  at a call site, so a write and a read can never key on different rules, and
  it refuses a missing or malformed `token_id` (the DO ops already reject such
  bodies; the seam fails closed on its own). The ctx tag is `vt-dek-ctx-v5`; a
  change to the derivation bumps it, so entries under an older tag (v4:
  `dek:{ctx}:{salt}`, ctx = IP + normalized `pwd`) are unreachable and simply
  lapse or are cleared from the admin tab. There is no dual-read.
- Reads are all-or-nothing for a batch of salts. A partial or expired batch is
  a miss and falls back to the normal phone ceremony. Opened DEK buffers are wiped
  on full hits, partial misses, and failure exits; this minimizes their lifetime,
  but does not protect against a compromised Worker or guarantee erasure of
  JavaScript-engine copies.
- A hit re-seals the DEKs to the current CLI request's ephemeral public key.
  The Worker never sends a cached DEK in the form stored at rest.
- Cache hits, write failures, and approved extensions are recorded in the
  unified `audit` table. Routine misses are logged and then followed by the
  normal ceremony audit. Extension effect counts and projected expiry reflect
  only storage batches whose writes succeeded. A failed batch stops the commit;
  the batches already acknowledged stay recorded, and the effect row says
  `error=1`.
- **The unit is one entry.** Each write stamps every entry with an immutable
  `created_ms`, the chosen `ttl_s`, the token record's `host`/`user`, the
  client's `project` and name claim, the Worker-derived `ip`, and the approval's
  `origin_token_id`. There is no group: the console addresses an entry by
  `{token_id, project, salt_b64u}` (`CacheEntryRef`) and the DO re-derives its
  key in `cacheCtx`, so a clear or an extension can only ever reach what a read
  would. Entries written before `host`/`ttl_s` existed list with those blank.
- A hit sends a best-effort Web Push notice (`cache_hit_notify`, 设置 tab) to
  every phone subscribed there — tag `cache:<host>`, TTL 1 h, opening the audit
  tab. Notifications never block DEK delivery and contain no approval URL.

## Data flow

```text
phone approval with TTL > 0
  PWA seals each DEK to the Worker cache public key
  Worker validates and stores dek:{token_id}:{project_h}:{salt}

later vt read/inject
  CLI POSTs /api/dek-cache with salts + meta + ephemeral public key
  Worker keys on (token_id, sha256(project)), loads the whole batch, checks expiry
    miss  -> CLI starts the normal /api/challenge phone ceremony
    hit   -> Worker opens, concatenates, and re-seals DEKs to the CLI key
             CLI verifies source=cache and decrypts locally
```

The cache public key is derived at runtime from the root-key scalar. The
Worker uses `tweetnacl` + `blakejs` for the sealed-box compatibility layer; the
Rust client opens the result with the existing sealed-box implementation.

## Client network bounds

- `/api/dek-cache` probe: one 3-second budget covering connection setup and
  the full response body. Timeout,
  transport, HTTP, and JSON failures are misses (fall through to the phone
  ceremony); a `source=cache` response with bad base64 or a bad sealed box is a
  hard error, never a fallback.
- Worker POSTs share one process-wide reqwest client. Authorization and
  timeout are set per request (30 s default, 5 s for agent audit pushes),
  covering the body read. Proxy settings are sampled when the client is first
  built, so a long-running agent must restart to pick up proxy changes.
- `/api/dek` WebSocket handshake (DNS, TCP, TLS, upgrade): 10 s, then the
  existing 6-minute approval wait. Failures report fixed messages that exclude
  the poll-token URL and server-controlled error text.

## Admin surface: the DEK 缓存 tab

The admin shell's DEK 缓存 tab (`/admin#cache`) lists what is **actually
cached and live right now**, one row per entry — 记录 (operator name, else the
自报 claim, else the salt handle; renameable in place) · 剩余 · 到期 · 创建于 —
grouped client-side under collapsible **主机 · 项目** headers (`vt.projectName`
of the project; the full path, user and token in the header's hovercard and
the row's sheet, with IP, TTL and origin approval). The DO filters
`expires_ms <= now` before answering: an expired entry is already a miss on the
read path and the 5-minute alarm sweep's to delete, so the console never shows
one and has no 已过期 filter. Extending never changes `created_ms`.
It is the only view of the real entry set — the audit tab can merely show which
approvals *armed* a cache, which is an inference, not an inventory.

The listing deliberately carries no secret material: no sealed DEK and **no
storage key**. The key holds `SHA-256(tag ‖ project)`, so publishing it would
turn the page into an offline oracle for the client-reported `project` path.
An entry is addressed by its literal `token_id`, `project` and salt (public in
every `vt://` URL); the DO re-derives the key. Entries scanned per request are
capped; the response reports `truncated` and the UI says so rather than
implying a complete view.

Selection drives every mutation: a header's checkbox selects its whole
project, the bulk bar appears once anything is selected. Two classes of
action, with deliberately different gates:

| Action | Gate | Why |
|---|---|---|
| List | Admin session (passkey login, [worker-slim.md](worker-slim.md) §3) | Read-only |
| 撤销 (selected entries) / 清除全部 | Admin session | Authority-**reducing**: worst case is "decrypts re-prompt" |
| 延长 (selected entries, one 主机 · 项目) | Session **+ a fresh phone Passkey approval** | Authority-**granting**: prolongs no-human-in-the-loop decrypts |

The scan cap above applies to the LISTING only. 撤销 deletes the exact keys of
the named entries (`cache-clear-entries`, ≤ 512 per request), so there is no
scan to fall past; 清除全部 streams the `dek:` prefix to its end through
`sweepCacheEntries`, deleting matches as they are found so memory stays bounded
without bounding the work. The `cleared` count both return is what storage
actually removed, not what the request intended to remove, and the UI reports
that number. A clear that cannot finish must fail loudly — never quietly.
Regression cover: `cf-worker/test/do_account.cache_list.test.ts`. The audit
tab revokes nothing and deletes nothing: its only deletion is the 90-day
retention sweep (the former 清空审计 op is gone).

### Extension contract

An admin selects entries of one 主机 · 项目 and a TTL and presses 延长; the
Worker then only **mints a pending ceremony**. Nothing expires later until a
Passkey approves it, and every one of these holds:

1. **Passkey required.** The intent (`token_id`, `project`, the salts, TTL,
   plus the host and record names the admin saw) is written onto the challenge
   at request time and never mutated, so the approval finalizes exactly what was
   proposed. The ceremony is single-use, expires in 5 minutes if untouched, and
   rechecks that deadline after assertion verification, immediately before
   approval commits. It is **not pushed to any notification channel** — the flow
   is console-resident (select on the DEK 缓存 tab, approve in the sheet that
   opens on the same page), so a card would only notify the person already
   watching the result. Observability stays where it belongs: the audit tab
   receives the request row (`op_kind='cache-extend'`) and the effect row
   (`status='extended'`) over its real-time stream, and permanently in the
   90-day audit table afterwards.
2. **One project per ceremony.** The request names entries of exactly one
   `token_id` + `project`; a mixed selection is a 400 (`one project per
   ceremony`), so the approver reads one host · project line. Up to 256 entries
   — what one approval can write — per ceremony.
3. **Laddered TTLs only** (`20m` / `2h` / `8h` / `1d` / `2d` / `1w` / 100 years). No arbitrary
   deltas. The multi-day rungs are extension-only: `writeCache` validates against
   the shorter approve ladder, so a tampered approve body cannot arm a multi-day
   cache without going through this ceremony.
4. **Never resurrects.** An entry already past `expires_ms` is refused at request
   time (`expired`) and skipped at commit time if it lapsed in between — the
   commit re-reads every entry under the DO gate with no await before the write.
   Only a new phone approval can bring a lapsed capability back.
5. **Never shortens.** An entry the TTL would not move forward is refused at
   request time (`no_gain`) and skipped at commit; a request with no movable
   entry is a 409. The UI disables 延长 and names the smallest rung that works.
6. **Measured from the approval, every time.** New expiry is `now + TTL`, where
   `now` is the moment of the tap — not an offset from creation, and not additive
   with whatever remains. `created_ms` is forensic metadata only. Total lifetime
   is unbounded by design; the price is a Passkey approval per hop, so a human is
   in the loop every single time instead of once at the start.

   This replaced an absolute `created_ms + 1w` ceiling, which failed twice over: it
   made the feature inert for the common case (operators cache for `8h`, so an
   entry sat at its ceiling from birth and every extension was a silent no-op), and
   it only ever constrained the legitimate operator — the ceiling binds nobody who
   can already complete a WebAuthn ceremony.
7. **Audited twice.** The ceremony row records the authorization (host
   `admin`, the requesting browser's IP); a second `op_kind='cache'`,
   `status='extended'` row records the effect — how many entries moved, to when,
   and what was skipped (`expired=`, `no_gain=`, `gone=`, `error=`). Each origin
   approval whose entries moved gets its `cache_expires_ms` bumped. Clears
   remain CF-logs-only: they reduce authority.
8. `audit.cache_ttl_s` keeps its original meaning (the TTL the approver chose)
   and is never rewritten. `audit.cache_expires_ms` tracks the live expiry, so
   the audit tab shows real liveness instead of an inference that an extension
   would falsify.

Residual gap, stated plainly: the approver reads the intent as rendered by the
Worker, and the assertion covers the challenge rather than a hash of the
displayed text. A compromised Worker could therefore show one intent and hold
another — but a compromised Worker already holds the cache scalar and can read
cached DEKs outright, so this adds no new capability to that adversary. Against
the adversary the gate is actually for — someone holding only an admin session
cookie — the Passkey requirement is decisive.

## Security boundary

The cache scalar is derived from `R` in the Durable Object and protects cached
entries if Durable Object storage is copied without `SECRET` (the entries are
sealed boxes; `R` at rest is wrapped under `SECRET`). It does not protect
against a compromised Worker. `VT_PASSKEY_TOKEN` is the request
credential and the cache key's hard half; when a cache entry is live,
possession of that token and the same reported `project` is sufficient to
obtain the cached DEK, from any egress IP. Since tokens are per host
([host-token.md](host-token.md)), another enrolled host never hits a grant it
did not earn, whatever its IP. Revoking a host's token stops its probes at
authentication, before the cache is consulted, and orphans its entries.

Keep the default TTL at `0` for high-assurance or unattended workloads. Use
short TTLs for automation that needs repeated decrypts. The multi-day extension
rungs (`1d`/`2d`/`1w`) are for long-running attended or CI sessions, and since
renewal is unbounded in total, a cache can in principle be kept alive for as long
as someone keeps approving it: for each window, possession of `VT_PASSKEY_TOKEN`
and the same reported `project` decrypts with no phone tap. Every hop takes an
explicit request plus a Passkey approval whose page states the new expiry, and the
audit table records each one — treat a long chain of `缓存已延长` rows on one
record as a signal worth reviewing. `8h` is a
workday-session choice for an attended desktop only: for its whole window,
possession of `VT_PASSKEY_TOKEN` and the same reported `project` decrypts the
approved records with no phone tap, so do not select it on shared, unattended,
or CI hosts. Use the admin clear-cache action for emergency invalidation (a
factory reset also orphans every entry). The cache does not re-key existing
`vt://` records.

## Implementation map

| Concern | Source |
|---|---|
| TTL ladders, per-hop cap, extension arithmetic | `cf-worker/src/cache_policy.ts` (+ `test/cache_policy.test.ts`) |
| Cache key binding (`cacheCtx`), writes/reads, live listing, exact-key and exhaustive clears, extension storage batches | `cf-worker/src/account_cache.ts` (`AccountCache`, same DO storage/input gate) |
| Cache request validation, Passkey authorization, ceremony transitions, audit/notification orchestration | `cf-worker/src/do_account.ts` (`AccountDO`) |
| Audit persistence and notification lifecycle | `cf-worker/src/account_audit.ts`, `cf-worker/src/account_notifications.ts` |
| Sealed-box cache crypto | `cf-worker/src/cache_crypto.ts` |
| PWA TTL selection and sealing | `cf-worker/pwa/approve.js` |
| CLI cache request, `project` collection, and source check | `src/cf.rs`, `src/client.rs` |
| Admin cache inventory / 撤销 / 延长 UI | `cf-worker/src/index.ts`, `cf-worker/pwa/admin/cache.js` |
| Admin audit cache column | `cf-worker/pwa/admin/audit.js` |
| Hit-notify switch, root-key scalar | `cf-worker/src/account_admin.ts` (`Config`, `cacheSeckey`), 设置 tab in `cf-worker/pwa/admin/settings.js` |
| Record names: table, adopt / rename gates, resolution on read | `cf-worker/src/account_names.ts`, `do_account.ts` (`opApprove`, `opNamesSet`), `account_audit.ts` (`records`), `pwa/admin/admin.js` (`vt.recordList`) |
| Deployment, secret rotation, reset | [`cf-worker-deploy.md`](cf-worker-deploy.md) |

## Verification

1. Deploy and bootstrap a Worker.
2. Read a `vt://` record and select `20m` on the approval page; tap its
   `客户端称 X` chip or type a name (or rename it later from the audit dialog).
3. Read the same record again from the same host inside the same repository
   (any worktree, any egress IP); the second read should not open a phone
   ceremony.
4. Check the admin audit page for the cache grant and hit.
5. Open the admin `DEK 缓存` tab: the entry appears under its 主机 · 项目
   header with its remaining time.
6. Tick the entry (or the header) and pick a duration SHORTER than the time
   remaining: 延长 is disabled and the note names a usable rung — extension is
   absolute, so a shorter rung is a no-op by definition. Pick a longer one,
   press 延长, approve on a Passkey, and confirm the remaining time jumps to
   `批准时刻 + 时长` and two audit rows appear (`cache-extend` approved +
   `缓存已延长`). Tick entries of two projects: 延长 is disabled, 撤销 is not.
   Let a cache lapse and confirm it leaves the tab and cannot be extended —
   only a fresh phone approval arms a new one.
7. Tick the entry and press 撤销 (or 清除全部), then confirm the next read
   returns to the phone ceremony.

For implementation changes, run the focused Rust/Worker tests and then the
repository gates from [`docs/README.md`](README.md).
