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
- The cap is **per operation, not per lifetime**: one extension sets expiry to
  `now + chosen TTL`, and an entry may be renewed indefinitely — one
  Passkey-approved hop at a time. `MAX_EXTEND_TTL_MS` follows the ladder, so
  trimming `EXTEND_TTL_WHITELIST` shortens the longest single hop.
- What bounds renewal is **liveness, not a budget**: an extension can only continue
  a window that has not yet lapsed. Once a cache expires it is gone for good and
  only a fresh phone approval can arm a new one.
- The 100-year rung deliberately gives up that bound for the records it is applied
  to. It is a FINITE far-future expiry (year ~2126), not a null/Infinity sentinel,
  so `opDekCache`'s read check, the alarm sweep, `audit.cache_expires_ms`, and the
  admin countdown all stay on their normal code path — expiry logic is where a
  missed special case becomes a cache that outlives its revocation. Nothing revokes
  such an entry but an explicit admin clear or rotating `CACHE_SECKEY`, it is never
  swept, and there is no expiry to prompt a future review; pair it with
  `CACHE_HIT_NOTIFY = "1"` so each no-tap decrypt stays visible somewhere. The UI
  renders it with the ordinary duration formatter (`36500 天`) rather than a special
  "permanent" label, so no reader has to trust a word over a number.
- Caching is enabled only when the Worker secret `CACHE_SECKEY` is configured.
  There is no `VT_DEK_CACHE` environment variable and no separate client-side
  no-cache flag.
- A cache key binds the Worker-derived source IP and the client-reported
  working directory `pwd`. IP is the hard boundary; `pwd` is an advisory
  same-host blast-radius reducer. `ppid` is forensic metadata only.
- Reads are all-or-nothing for a batch of salts. A partial or expired batch is
  a miss and falls back to the normal phone ceremony.
- A hit re-seals the DEKs to the current CLI request's ephemeral public key.
  The Worker never sends a cached DEK in the form stored at rest.
- Cache hits, write failures, and approved extensions are recorded in the
  unified `audit` table. Routine misses are logged and then followed by the
  normal ceremony audit.
- Each write mints one `cache_group_id` (all entries from one approval under one
  binding ctx) and stamps an immutable `created_ms`. The group id is the handle
  the admin surface lists, clears, and extends by.
- A hit sends a best-effort notification through configured Pushover, Slack
  Webhook, Slack App, or Feishu channels. Notifications never block DEK
  delivery and contain no approval URL.

## Data flow

```text
phone approval with TTL > 0
  PWA seals each DEK to the Worker cache public key
  Worker validates and stores dek:{ctx}:{salt}

later vt read/inject
  CLI POSTs /api/dek-cache with salts + meta + ephemeral public key
  Worker derives ctx(IP + pwd), loads the whole batch, and checks expiry
    miss  -> CLI starts the normal /api/challenge phone ceremony
    hit   -> Worker opens, concatenates, and re-seals DEKs to the CLI key
             CLI verifies source=cache and decrypts locally
```

The cache public key is derived at runtime from `CACHE_SECKEY`. The Worker
uses `tweetnacl` + `blakejs` for the sealed-box compatibility layer; the Rust
client opens the result with the existing sealed-box implementation.

## Admin surface: the DEK 缓存 tab

`/<ADMIN_SEG>/cache` lists what is **actually cached right now**, one row per
cache group, joined with the approval that armed it (host, user, directory,
command). It is the only view of the real entry set — the audit tab can merely
show which approvals *armed* a cache, which is an inference, not an inventory.

The listing deliberately carries no secret material: no sealed DEK, no salts, and
**no binding ctx digest**. The ctx is `SHA-256(tag ‖ ip ‖ pwd)`, so publishing it
next to an already-visible IP would turn the page into an offline oracle for the
client-reported `pwd`. Entries scanned per request are capped; the response
reports `truncated` and the UI says so rather than implying a complete view.

Two classes of action, with deliberately different gates:

| Action | Gate | Why |
|---|---|---|
| List | Cloudflare Access | Read-only |
| Clear (row / selected / all) | Cloudflare Access | Authority-**reducing**: worst case is "decrypts re-prompt" |
| Extend | Access **+ a fresh phone Passkey approval** | Authority-**granting**: prolongs no-human-in-the-loop decrypts |

### Extension contract

Extension is off by default (`CACHE_ADMIN_EXTEND`, a kill switch — not an
authorization). When enabled, an admin selects groups and a TTL and presses
延长; the Worker then only **mints a pending ceremony**. Nothing expires later
until a Passkey approves it, and every one of these holds:

1. **Passkey required.** The intent (group ids, TTL, requester) is written onto
   the challenge at request time and never mutated, so the approval finalizes
   exactly what was proposed. The ceremony is single-use, expires in 5 minutes if
   untouched, is pushed to every configured notification channel, and appears on
   the audit tab as `cache-extend` — an unexpected extension request is visible
   to the operator who did not initiate it.
2. **Laddered TTLs only** (`20m` / `2h` / `8h` / `1d` / `2d` / `1w`). No arbitrary
   deltas. The multi-day rungs are extension-only: `writeCache` validates against
   the shorter approve ladder, so a tampered approve body cannot arm a multi-day
   cache without going through this ceremony.
3. **Never resurrects.** An entry already past `expires_ms` is skipped. Only a
   new phone approval can bring a lapsed capability back.
4. **Never shortens.** A request that would not move expiry forward is a no-op.
5. **Measured from the approval, every time.** New expiry is `now + TTL`, where
   `now` is the moment of the tap — not an offset from creation, and not additive
   with whatever remains. `created_ms` is forensic metadata only, which is exactly
   what lets pre-migration entries be renewed like any other. Total lifetime is
   unbounded by design; the price is a Passkey approval per hop, so a human is in
   the loop every single time instead of once at the start.

   This replaced an absolute `created_ms + 1w` ceiling, which failed twice over: it
   made the feature inert for the common case (operators cache for `8h`, so an
   entry sat at its ceiling from birth and every extension was a silent no-op), and
   it only ever constrained the legitimate operator — the ceiling binds nobody who
   can already complete a WebAuthn ceremony.
6. **Drifted groups are never extendable.** A group whose entries disagree on
   origin/creation/IP is refused outright rather than guessed at; it stays listable
   and clearable. Pre-`created_ms` entries ARE extendable (their `legacy:` handle
   rests on a full 96-bit origin token), so nothing already cached is stranded.
7. **Audited twice.** The ceremony row records the authorization (with the
   verified Cloudflare Access email); a second `op_kind='cache'`,
   `status='extended'` row records the effect — how many entries moved, to when,
   and what was skipped. Clears remain CF-logs-only: they reduce authority.
8. `audit.cache_ttl_s` keeps its original meaning (the TTL the approver chose)
   and is never rewritten. The new `audit.cache_expires_ms` column tracks the
   live expiry, so the audit tab shows real liveness instead of an inference that
   an extension would falsify.

Residual gap, stated plainly: the approver reads the intent as rendered by the
Worker, and the assertion covers the challenge rather than a hash of the
displayed text. A compromised Worker could therefore show one intent and hold
another — but a compromised Worker already holds `CACHE_SECKEY` and can read
cached DEKs outright, so this adds no new capability to that adversary. Against
the adversary the gate is actually for — someone holding only a Cloudflare Access
session — the Passkey requirement is decisive.

## Security boundary

`CACHE_SECKEY` is present in the Worker process and protects cached entries if
Durable Object storage is copied without the running Worker. It does not
protect against a compromised Worker. `VT_PASSKEY_TOKEN` is the request
credential; when a cache entry is live, possession of that token from the same
egress IP and matching `pwd` is sufficient to obtain the cached DEK.

Keep the default TTL at `0` for high-assurance or unattended workloads. Use
short TTLs for automation that needs repeated decrypts. The multi-day extension
rungs (`1d`/`2d`/`1w`) are for long-running attended or CI sessions, and since
renewal is unbounded in total, a cache can in principle be kept alive for as long
as someone keeps approving it: for each window, possession of `VT_PASSKEY_TOKEN`
from the same egress IP and `pwd` decrypts with no phone tap. Every hop takes an
explicit request plus a Passkey approval whose page states the new expiry, and the
audit table records each one — treat a long chain of `缓存已延长` rows on one
record as a signal worth reviewing. `8h` is a
workday-session choice for an attended desktop only: for its whole window,
possession of `VT_PASSKEY_TOKEN` from the same egress IP and `pwd` decrypts the
approved records with no phone tap, so do not select it on shared, unattended,
or CI hosts. Rotate
`CACHE_SECKEY` or use the admin clear-cache action for emergency invalidation.
The cache does not re-key existing `vt://` records.

## Implementation map

| Concern | Source |
|---|---|
| TTL whitelist, lifetime ceiling, extension arithmetic | `cf-worker/src/cache_policy.ts` (+ `test/cache_policy.test.ts`) |
| Cache writes/reads, listing, extension commit, audit, notifications | `cf-worker/src/do_account.ts` |
| Sealed-box cache crypto | `cf-worker/src/cache_crypto.ts` |
| PWA TTL selection and sealing | `cf-worker/pwa/approve.js` |
| CLI cache request and source check | `src/cf.rs`, `src/client.rs` |
| Admin cache inventory / clear / extend UI | `cf-worker/src/index.ts`, `cf-worker/pwa/admin/cache.js` |
| Admin audit cache column + per-row clear | `cf-worker/pwa/admin/audit.js` |
| Deployment secret and rotation | [`cf-worker-deploy.md`](cf-worker-deploy.md) |

## Verification

1. Deploy a Worker with `CACHE_SECKEY` configured.
2. Read a `vt://` record and select `20m` on the approval page.
3. Read the same record again from the same egress IP and working directory;
   the second read should not open a phone ceremony.
4. Check the admin audit page for the cache grant and hit.
5. Open the admin `DEK 缓存` tab: the entry group appears with its remaining time
   and its extendable ceiling.
6. With `CACHE_ADMIN_EXTEND = "1"`, select the group, press 延长, and approve on a
   Passkey. Confirm the remaining time moves, the ceiling does not, and two audit
   rows appear (`cache-extend` approved + `缓存已延长`). Repeat past the 8h mark
   and confirm the request is refused rather than clamped silently.
7. Rotate `CACHE_SECKEY` or clear the cache, then confirm the next read returns
   to the phone ceremony.

For implementation changes, run the focused Rust/Worker tests and then the
repository gates from [`docs/README.md`](README.md).
