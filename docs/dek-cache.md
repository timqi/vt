# DEK cache

Status: **implemented**. This is the current behavior reference for the
approval-time cache. The cache is an explicit security tradeoff: during its
TTL, a caller can decrypt the approved records without another phone tap.

## Current contract

- TTL choices are `0`, `20m`, `2h`, and `8h`. `0` is the default and means no
  cache write.
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
- Cache hits and write failures are recorded in the unified `audit` table.
  Routine misses are logged and then followed by the normal ceremony audit.
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

## Security boundary

`CACHE_SECKEY` is present in the Worker process and protects cached entries if
Durable Object storage is copied without the running Worker. It does not
protect against a compromised Worker. `VT_PASSKEY_TOKEN` is the request
credential; when a cache entry is live, possession of that token from the same
egress IP and matching `pwd` is sufficient to obtain the cached DEK.

Keep the default TTL at `0` for high-assurance or unattended workloads. Use
short TTLs for automation that needs repeated decrypts. `8h` is a
workday-session choice for an attended desktop only: for its whole window,
possession of `VT_PASSKEY_TOKEN` from the same egress IP and `pwd` decrypts the
approved records with no phone tap, so do not select it on shared, unattended,
or CI hosts. Rotate
`CACHE_SECKEY` or use the admin clear-cache action for emergency invalidation.
The cache does not re-key existing `vt://` records.

## Implementation map

| Concern | Source |
|---|---|
| TTL whitelist, cache writes/reads, audit, notifications | `cf-worker/src/do_account.ts` |
| Sealed-box cache crypto | `cf-worker/src/cache_crypto.ts` |
| PWA TTL selection and sealing | `cf-worker/pwa/approve.js` |
| CLI cache request and source check | `src/cf.rs`, `src/client.rs` |
| Admin cache clear/filter UI | `cf-worker/src/index.ts`, `cf-worker/pwa/admin/audit.js` |
| Deployment secret and rotation | [`cf-worker-deploy.md`](cf-worker-deploy.md) |

## Verification

1. Deploy a Worker with `CACHE_SECKEY` configured.
2. Read a `vt://` record and select `20m` on the approval page.
3. Read the same record again from the same egress IP and working directory;
   the second read should not open a phone ceremony.
4. Check the admin audit page for the cache grant and hit.
5. Rotate `CACHE_SECKEY` or clear the cache, then confirm the next read returns
   to the phone ceremony.

For implementation changes, run the focused Rust/Worker tests and then the
repository gates from [`docs/README.md`](README.md).
