# Worker trust model

This document defines the authority held by the Worker, enrolled hosts, and
administrator sessions. Deployment and recovery commands belong to
[cf-worker-deploy.md](cf-worker-deploy.md).

## Root key and custody

`SECRET` is the only Wrangler secret and is a key-encryption key. A random root
`R` is generated at bootstrap and stored wrapped under it; host-token secrets,
admin-session authentication, encrypted configuration, and the cache key derive
from `R`. Derivations live in [account_admin.ts](../cf-worker/src/account_admin.ts).

| Attacker holds | Exposure |
|---|---|
| `SECRET` without DO storage | Can derive the KEK, but has no wrapped root to decrypt |
| A DO storage copy without `SECRET` | Can read plaintext audit, token metadata, and record names; cannot unwrap `R` or open encrypted configuration/cached DEKs |
| `SECRET` and a DO storage copy | Can unwrap `R`, decrypt configuration and copied cached DEKs, derive host-token secrets, and forge admin sessions; online use remains subject to current token liveness and session epoch |
| Access to the running Worker's unwrapped keys | Has the same derived-key authority without needing the stored KEK wrap |

These keys do not by themselves unwrap the phone's PRF-protected master or
produce a verified Passkey assertion. A compromised service that can alter the
approval page is outside that key-only limit; the browser trusts delivered code.

- Rotating `SECRET` preserves `R` and existing authority. At most two wraps may
  coexist while the operator installs the new secret.
- Factory reset replaces `R`, invalidating derived credentials and orphaning
  cached material. An unreadable root/config fails closed as unconfigured.
- Real secrets never belong in TOML examples, browser assets, or logs.

## Administrator authority

Admin authentication and authorization happen in the Durable Object. The edge
limits input and request rates; Cloudflare Access headers grant no authority.

### Sessions

A Passkey login grants an eight-hour absolute session bound to configuration
epoch. Mutations and audit-stream upgrades also require the configured Origin.
Revoking a Passkey or all sessions advances the epoch; logging out one browser
only discards its cookie. The last Passkey cannot be revoked.

An audit-stream socket carries the epoch and expiry of the session that opened
it; an epoch bump closes it, and a socket past either check receives no
broadcast.

A session permits configuration, credential management, record renaming,
listing, and authority-reducing revocation. It cannot approve a protected
ceremony or extend a cache entry without a verified Passkey assertion.

### Bootstrap

The first bootstrap establishes the root, Passkey, and immutable origin. It
is open only while unconfigured; the first successful registration owns the
account, so operators must bootstrap promptly on the canonical hostname.

Bootstrap and login-challenge requests are rate-limited; an absent limiter
fails with 503. Login consumes a single-use challenge. Unconfigured state
allows only the admin shell, bootstrap, and public assets; protected operations
must not fall back to permissive defaults.

The public PWA shells carry no account data. Data arrives through session-aware
shell responses or gated APIs, with HTML-safe JSON and strict CSP/security headers.

## Approval policy

Operator settings live in encrypted DO configuration, not Wrangler variables.
The mutable policy settings are `uv_policy` and `cache_hit_notify`; the bootstrap
origin cannot change without reset.

- UV is decided in the DO against the verified host. Host and command requests
  may raise verification requirements, never lower them.
- Enrollment, admin login, and cache extension require user verification;
  ordinary approval follows the configured floor.
- User presence remains mandatory even when UV is discouraged.
- Malformed policy must not silently become a weaker policy.

WebAuthn PRF custody stays on the phone; host authentication requests approval
but does not replace it. Cached DEKs are the deliberate exception described
in [dek-cache.md](dek-cache.md).

## Web Push

Web Push is the only notification channel. Delivery is best-effort and runs
after the ceremony write; it never blocks or fails protected operations.
Notifications cannot create authority and are not a durable audit ledger.

Approval and enrollment requests can notify subscribed phones. Cache-hit notices
are separately enabled and off by default. Extension approval remains in the
admin page; notification failure never becomes a CLI warning.

### Delivery limits

Dead subscriptions are removed; transient failures keep them for later events.
There is no durable delivery queue. Subscription credentials are confidential
configuration. Lock-screen notification previews may expose request metadata.

### Installed app

On iOS, Web Push requires an installed home-screen app. The service worker
handles notifications without caching authenticated pages or API responses.
Setup steps and browser requirements belong to the deployment guide.

The service worker holds the approval a notification points at for three minutes
and hands it to a page that asks on load; the page navigates itself, because an
iOS home-screen app answers a tap by showing its start page. Approval and
enrollment pushes hand it to an already-open window immediately; cache-hit
notices never navigate, and a page already showing an approval is never
navigated away — that would abort its WebAuthn prompt. A tap focuses that window, and opens one only when the
app has none — an opened window is an auxiliary context that iOS presents as an
in-app browser. Each hand-off fires once, and after a decision the page leaves
for the admin console: the spent token would only render as 410.

## Host tokens

Each host enrolls for its own token; there is no master daemon credential.
The edge checks request shape and size, then the DO verifies the MAC over the
original bytes and checks token liveness before protected state is accessed.
The token secret is derived when needed, never stored in the token record.

- Enrollment is unauthenticated and can page a phone, so it requires per-IP rate
  limiting, a pending set bounded per IP and globally, and a short-lived ceremony;
  no limiter means 503.
- Compare the terminal and phone pairing codes before approval. Host/user are
  self-reported at enrollment and become the approved record's labels afterward.
- Issue a token only through verified Passkey approval; reconnecting may recover
  the same result, never mint a second authority from the ceremony.
- Challenge and cache use slide expiry to seven days from use; revoked or expired
  tokens never revive. Background audit push checks liveness without extending it.
- The host/user shown on token-authenticated requests come from the record,
  never the request body. This authenticates a credential, not the physical host.
- Token possession can request approvals and retrieve that token's live cached
  DEKs; theft therefore exposes those cache windows without another phone tap.
- Admin revocation immediately blocks further token use. A new root invalidates
  every token; rotating only the KEK does not.

Token lifecycle and tests: [account_tokens.ts](../cf-worker/src/account_tokens.ts)
and [host_token.ts](../cf-worker/src/host_token.ts). Enrollment and reset
procedures belong to [cf-worker-deploy.md](cf-worker-deploy.md).
