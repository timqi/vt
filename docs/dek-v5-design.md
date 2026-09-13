# DEK cache v5 + record naming (design)

Status: proposal, revision 3. Nothing here is implemented. `dek-cache.md`
remains the current contract until this lands.

Revision 2 folds in two rounds of review. Changes from revision 1 are marked
**[r2]** and the rejected alternatives are kept, with their reasons, so the same
ground is not re-argued.

Two changes that touch the same surfaces (approval page, cache tab, audit tab):

- **A. Cache binding v4 → v5** — the key stops carrying the requester's IP; the
  IP becomes an allowlist on the host token instead.
- **B. Record naming** — a record may carry a name, bound into its DEK
  derivation, so the approval page can say *which* secret is being decrypted.

A and B are independent and can be built in parallel; their approval-page edits
merge A-then-B.

## 1. Why

### 1.1 The IP half of the key

Today `ctx = SHA-256("vt-dek-ctx-v4" ‖ len(ip) ‖ ip ‖ cacheScopePwd(pwd))`
([`account_cache.ts`](../cf-worker/src/account_cache.ts), `cacheCtx`), and the
worker-derived IP is the documented hard boundary.

The operator's egress IPv4 changes (ISP reassignment). Every change silently
evicts that host's whole cache and turns approval-free decrypts back into phone
taps. Dual-stack flapping is *not* part of this — [`src/cf.rs`](../src/cf.rs)
(`cf_post`) already pins egress to IPv4 with a v6 fallback precisely so the
challenge write and the cache probe agree on `CF-Connecting-IP`.

IP was chosen when every host shared `VT_AUTH_CF` and there was no other
verified identity. Since [`host-token.md`](host-token.md) shipped there is one:
`token_id`, per host, revocable, sliding expiry
([`account_tokens.ts`](../cf-worker/src/account_tokens.ts)). IP is both weaker
(everyone behind one NAT shares it) and less stable than that.

### 1.2 Nameless DEKs

The approval page shows an op kind, a command string, and `记录数 N 条`. A batch
of five secrets is one number. A record is `vt://{type}{b64(salt ‖ ct)}` and its
DEK is `HKDF(master, salt=salt, info=DEK_HKDF_INFO)`
([`src/core/crypto.rs`](../src/core/crypto.rs) `derive_dek`; PWA side
`vt.deriveDek`, `cf-worker/pwa/common.js`). Nothing carries a name.

## 2. A. Cache binding v5

### 2.1 Key

```
dek:{token_id}:{salt_b64u}:{scope_h}:{name_h}
```

- `token_id` — the verified host identity the edge resolved while authenticating.
- `salt` — identifies the record.
- `scope_h` — `sha256(cacheScopePwd(pwd))` truncated. **[r2]** Revision 1 moved
  the scope onto the entry as a `scopes[]` list; that is withdrawn, see §3.
- `name_h` — `sha256(name)` truncated, empty-name reserved. **[r2]** Required:
  on the CF path the *client* chooses the salt
  ([`src/cf.rs`](../src/cf.rs)), so the same salt under two names is two
  different DEKs and would otherwise overwrite one another.

A caller with no `token_id` (the legacy bare-master path, logged
`auth.legacy_master`) keeps the v4 IP-bound derivation and must not gain a wider
cache by being older. **[r2]** If the `VT_AUTH_CF_PREV` rotation work lands first
(see §6) the legacy branch is deleted and this case disappears entirely — which
is why rotation is sequenced ahead of A.

### 2.2 IP moves onto the host token

Rejected (revision 1): "hit anyway on a new IP, flag the audit row, push a
notification". The notification is fire-and-forget *after* the DEKs return,
revocation is a human action minutes later, and the permanent rung in
`EXTEND_TTL_WHITELIST` ([`cache_policy.ts`](../cf-worker/src/cache_policy.ts))
makes a leaked token an indefinite unattended-decrypt capability.

Instead a new table `host_token_ip(token_id, ip, added_ms, last_hit_ms)`,
synchronous SQL in the DO like `account_tokens.ts`:

- **Admission — exactly these paths [r2]:**
  - A decrypt/encrypt ceremony, **only when the approver picked TTL > 0**, in the
    same synchronous step as `writeCache`. TTL = 0 means "do not cache" and must
    not quietly register an IP. Auth-only ceremonies (no salts) never register.
  - The IP registered is the **challenge-creation** edge IP (`opCreate`), never
    the IP of the phone's approve request.
  - `commitEnroll` seeds the list with `enroll_ip`.
  - The cache-extend ceremony must **not** touch the list: its `meta.ip` is the
    admin browser's, and it carries no host token.
  - `audit-ingest` never admits (it has no IP semantics).
- **Bounds:** 8 per token; evict oldest `last_hit_ms`; independent ageing at
  7 days with no hit, reusing the `HOST_TOKEN_TTL_MS` constant.
- **Enforcement:** a probe whose `CF-Connecting-IP` is absent is a uniform miss.
  **[r2]** The check runs *after* the batched entry read
  (`getKeysBatched`, [`account_cache.ts`](../cf-worker/src/account_cache.ts)) so
  "unknown IP" and "no entry" stay timing-indistinguishable; the response shape
  `{miss:true}` is unchanged.
- **[r2]** An unknown-IP probe must use `isLive`, not `tokens.touch` — otherwise a
  stranger's probe slides the token's 7-day expiry and overwrites `last_ip`. A
  legitimate host that changed network raises a ceremony immediately afterwards,
  and `opCreate` touches there.

Cost to the operator: one phone tap per new IP, not one per IP × record batch.
Gain over today: a stolen token used from an unfamiliar network cannot hit the
cache at all — it must raise a ceremony that shows the verified host name and
the new IP.

**[r3] Accepted residual risk — admission is retroactive.** The allowlist is per
token, so approving *any* cache-arming ceremony from a new network also makes
every entry that token already holds readable from there, including long-lived
ones armed elsewhere, and the new IP's 7-day ageing is unrelated to the TTL that
admitted it. Today's v4 has no such widening: each entry is bound to the IP it
was created under.

The safer shape — keep IP in the key, add the token, and make moving a cache to
a new network its own ceremony that lists the groups it moves — was considered
and rejected as too complex for the benefit. It remains the upgrade path if the
residual risk stops being acceptable.

The mitigation is informed consent, not architecture: when the requesting IP is
not yet in `known_ips`, the approval page must say so explicitly and list what
admission opens — the number of existing live groups for this token, their
scopes and their latest expiry — above the TTL controls. "批准将登记本 IP" alone
is not enough. Because this changes what an approval means, the approval page
needs its own version gate (§4.5 covers only the named-record case); an old
cached PWA must not render a new-IP ceremony with the old promise text.

### 2.3 Consequences in the same change

- **[r2]** Revocation clearing is orchestrated by `AccountDO.opTokensRevoke`, not
  by `AccountTokens` (which holds only a `SqlStorage` handle). With the key
  prefixed by `token_id` it is a prefix scan and delete of `dek:{token_id}:`.
  Without it, permanent-rung entries outlive the token that armed them.
- **[r2]** The alarm sweep should also drop entries whose token is dead;
  otherwise they sit in storage and in the admin listing forever.
- **[r2]** Revision 1 claimed that removing IP from the key makes cross-IP groups
  read as `inconsistent`. That was wrong: one group = one `writeCache` = one
  ceremony = one `ch.meta.ip`, so the predicate is unaffected. It was `scopes[]`
  that would have broken it, and `scopes[]` is withdrawn.
- `dek-cache.md`'s rule that listings must not expose the ctx digest (offline
  brute force of `pwd`) disappears with the digest; the key is never listed.
- **[r2]** Today a *different* already-enrolled host behind the same NAT can hit
  the cache (`dek-cache.md`). v5 closes that; say so in the doc.
- `AGENTS.md`'s red line "Worker-derived IP is the hard cache boundary" is
  rewritten to name the token, and the approval page's `同一来源 IP（已验证）`
  sentence with it. The TTL radio group gains "批准将登记本 IP".

## 3. Scope stays in the key [r2]

Revision 1 moved the normalized scope onto the entry as `scopes:
[{scope, expires_ms}]` so a second approval in another directory could not
destroy a running grant. Withdrawn:

- The bound + eviction rule reproduces the very regression it was meant to
  prevent: with the list full, a fresh 20-minute approval evicts a long-lived
  one. Refusing instead of evicting turns a full list into a silent denial.
- One entry carrying several approvals splits `cache_group_id`,
  `origin_token_id` and `created_ms` from per-entry to per-scope, rewriting
  grouping, `commitExtend` and `clearByOrigin`, and turning `writeCache` into a
  read-modify-write — against the "re-read with no await before the write" rule
  and the "group ids and creation stamps are immutable" red line in `AGENTS.md`.

Keeping `scope_h` in the key preserves today's behaviour exactly: two
directories are two entries, as they are now. The entry additionally stores the
scope in clear for the admin page (no new exposure: the cache tab already joins
`origin_token_id` to the audit row and shows the literal `pwd`, retained 90
days).

The only thing given up is prefix/subtree matching, and §3.2 of revision 1
already required that to be an approver-visible choice on the approval page — a
separate feature, to be designed when it is actually wanted.

Matching stays one pure function beside `cacheScopePwd`
([`cache_policy.ts`](../cf-worker/src/cache_policy.ts)) with tests, never
inlined, so a read and a write cannot disagree.

## 4. B. Record naming

### 4.1 The name is an HKDF `info` term

```
info = DEK_HKDF_INFO                       (name empty — today's value, unchanged)
info = DEK_HKDF_INFO ‖ 0x00 ‖ name_ascii   (named record)
```

An empty name is **not** a third derivation: empty ≡ unnamed ≡ today's `info`
exactly. `salt` stays 16 random bytes, so the `salt[..12]` GCM nonce and the
collision argument in `derive_dek`'s comment are untouched.

Misreporting a name yields a different DEK and an AES-GCM tag failure — no
disclosure, only a failed decrypt for the liar. Submitting the same salt with an
empty name likewise yields the unnamed DEK, which does not open a named record.

### 4.2 Why not a Worker-side `salt → name` table

The first proposal registered `(salt → name)` with the Worker at creation time.
Rejected in review: the Worker cannot distinguish a create from a decrypt
(`op_kind` is client-reported) and the salt is client-generated on the CF path,
so a compromised host could register a misleading name for a salt it does not
own. It would also need a cap, an enumeration guard, a rename ceremony and a
squatting rule. With the name in `info`, none of that exists.

### 4.3 Name validation — reject, never sanitize [r2]

`name` matches `^[A-Za-z0-9_-]{1,64}$`, enforced identically in Rust and in the
Worker, with a cross-implementation golden vector. Anything else is a 400.

This is load-bearing, not hygiene:

- `capMeta` truncates and appends `…` (`index.ts`) — a *sanitized* name would
  make the displayed string differ from the derived one, destroying the whole
  property this design rests on.
- The ASCII allowlist removes homograph, NFC/NFKC and bidi-override tricks as a
  class, rather than filtering them one at a time.
- It matches the URL body alphabet (§4.4), so a name never needs escaping.

The approval page renders the name in full and must not CSS-ellipsize it.

### 4.4 Record format [r2]

Revision 1 put the name in clear beside the salt. That breaks the record
scanner: `is_vt_body_byte` accepts only `[A-Za-z0-9_-]`
([`src/core.rs`](../src/core.rs)) and `VtUrl::parse` rejects `/`, and
hook / inject / redact / rewrap all depend on it. Any separator truncates the
URL.

Instead the name goes **inside** the base64 blob under new type bytes:

```
vt://0{b64(salt ‖ ct)}                  unnamed RAW   (unchanged)
vt://1{b64(salt ‖ ct)}                  unnamed TOTP  (unchanged)
vt://2{b64(len ‖ name ‖ salt ‖ ct)}     named RAW
vt://3{b64(len ‖ name ‖ salt ‖ ct)}     named TOTP
```

The type byte is already the trailing AAD term (`v2_aad`, `src/core.rs`), so a
downgrade from `2` to `0` fails on both the AAD and the DEK. The scanner,
`iter_vt_urls` and `inject` need no change.

### 4.5 Wire protocol and version gates [r2] — blocking

Both derivation sites must learn the name *and* old peers must be unable to
half-participate. Two paths derive DEKs, and the Worker is absent from one:

**SSH agent.** `derive_dek(&mac_key, &salt)` is called in
`src/server_macos/ssh_agent/handlers.rs` for both encrypt and decrypt, and
neither `EncryptReq` nor `DecryptInput::V2` carries a name
([`src/core.rs`](../src/core.rs)). Note the agent *generates* the salt on
encrypt (`EncryptResItem`). So:

- `EncryptReq`, `EncryptResItem` and `DecryptInput::V2` gain the name.
- The agent **echoes** the name it derived with; the client refuses to assemble
  a URL if it asked for a name and the echo is absent or different.
- `WIRE_VERSION` (`src/core/wire.rs`) is bumped, so an old agent's `ok` is
  rejected outright rather than believed.

Without this an old agent mints an unnamed DEK while the client writes a *named*
URL — a record that can never be decrypted again. That is data loss, not a
security weakness, and it is the reason this is a blocker.

**PWA.** `approve.js` derives from `salts_b64u` alone. A phone holding a cached
old `approve.js` would do the same thing. Gate it by folding the names into the
WebAuthn effective challenge when `names` is non-empty:

```
effective = SHA-256(approve_challenge_hash ‖ pwa_pk ‖ names_hash)
```

An old PWA cannot compute it, so `verifyAssertion` returns 401 and the ceremony
fails closed. The daemon's `compute_approve_challenge_hash` and `verify_binding`
([`src/cf.rs`](../src/cf.rs)) do not change, and `challengeHash` needs no v3.

**[r3] The challenge gate alone is not sufficient — mixed asset versions.** The
HKDF actually lives in `cf-worker/pwa/common.js` (`vt.deriveDek`), and
`approve.js` is asset-versioned while `common.js` is not everywhere it is
loaded. A browser holding an old cached `common.js` beside a new `approve.js`
silently ignores the extra name argument and derives an unnamed DEK *after*
passing the names challenge gate. Fix: named derivation gets its own function
name, so an old `common.js` fails with a missing symbol rather than degrading;
every approval entry point versions the whole dependency set.

**[r2]** Note what this does *not* buy: it cannot stop a malicious Worker from
displaying a false name. `approve.js` takes `data.approve_challenge_b64u`
verbatim and never recomputes it from the salts, so the Worker controls what is
shown either way. The phone still *derives* with the name it was given, so a
false name only produces a useless DEK — a failure, never a disclosure.

### 4.5b Agent authorization identity [r3] — blocking

The reusable-grant resource digest for decrypt is
`(domain, root_path, secret_type, salt)` — it does **not** include the name
([`src/core/authorization.rs`](../src/core/authorization.rs),
`decrypt_workspace` / `decrypt_app` / `decrypt_cwd`, and `decrypt_v2` for the
relay). Derivation binding alone therefore does not close the loop on the agent
path:

1. ask for the target salt under a harmless name, obtain a reusable grant;
2. ask again for the same salt and type under the real name — the resource
   digest is identical, the grant is reused, and a usable DEK is derived with
   no second prompt.

Step 1 does not even need valid ciphertext: the agent returns the DEK and
commits the grant without waiting for the client's AES-GCM verification.

Fix: all four decrypt scope families take the full name into their resource
digest, with the digest domain string bumped so pre-existing grants cannot be
reinterpreted. The test that matters is "grant approved under name A, then
request name B, must prompt again" — not merely that two HKDF outputs differ.

### 4.6 Approval surface

One row per record: the name, or `SHA-256(salt)[0..8]` as a fingerprint for
unnamed ones, plus `上次批准于 …` and a prominent **首次出现** flag. The
client-reported provenance (env var name, `file:line`, argv position) sits on a
secondary line marked untrusted, beside the existing verified/self-reported
split. `记录数 N 条` goes away.

**[r2]** `first_seen` is stamped at **approval**, not at challenge creation —
otherwise a compromised host can create and abandon a challenge to burn the
"first seen" flag before the decrypt it actually wants.

**[r3]** The history table is indexed by the full `(salt, name)` identity, not by
the salt alone — otherwise an attacker who approves a harmless name for a salt
first burns the "first seen" flag for the real name on that same salt. The short
fingerprint stays display-only.

The `fp → {first_seen_ms, last_approved_ms}` table carries no security weight
(it is display memory) and can land last.

### 4.7 Costs

- Naming an existing record, or renaming one, means re-encrypting it: the name
  is part of the record's identity. **[r2]** `vt rewrap` cannot be reused —
  `find_legacy_urls` matches only `vt://mac/` (`src/client/rewrap.rs`). A named
  re-encryption is a new "decrypt v2 → encrypt named" flow.
- TOTP needs nothing beyond the extra type byte: the type is in the AAD, the
  name is in the key, and `client_decrypt_v2` is unaffected.
- **[r2]** The agent's Touch ID prompt must show the name too, and state that it
  is client-supplied but derivation-bound — the "agent-derived truth lines
  precede client-reported lines" rule in `AGENTS.md` applies.

## 5. Cache key and naming interact [r2]

`name_h` is part of the cache key (§2.1). The `(salt, name)` pair is the DEK's
identity, so it must be the cache entry's identity too. The name is additionally
stored on the entry for the audit row and the admin listing — and a cache-hit
audit must display **the name stored at write time**, never the one the probing
caller reported.

## 6. Order

1. `VT_AUTH_CF_PREV` dual-accept at the Worker, then delete the bare-master
   branch. This is a prerequisite, not a preference: it removes the legacy
   no-token case from §2.1 so v5 never needs a v4 read path.
2. **A** — v5 key, `host_token_ip`, revoke/alarm clearing, page and doc rewrites.
3. **B1** — derivation `info`, URL type bytes, agent wire + `WIRE_VERSION`, agent
   authorization digests (§4.5b), PWA challenge gate and asset-version gate,
   name validation with golden vectors. **[r3]** A minimal name display ships
   *with* B1, not in B2: releasing named derivation while the approval page still
   shows only a record count would mean approving a named DEK without ever seeing
   the name. The record list must be a mandatory region, not behind the existing
   `showMeta` flag (the audit tab's inline ceremony passes `showMeta:false`).
4. **B2** — full per-record layout and history.
5. **B3** — fingerprint table (optional).

**[r3] Test floor.** The existing Worker cache tests seal a fake DEK
(`cf-worker/test/do_account.write_cache.test.ts`), so they can go green while
named encryption cannot round-trip. B1 needs a real HKDF → encrypt → decrypt
test across both transports, and a version matrix (old/new client × agent ×
Worker × PWA) in which every incompatible combination fails *before* a URL is
assembled.

## 7. Still open

- `host_token_ip` ageing: 7 days reusing `HOST_TOKEN_TTL_MS` is proposed; is a
  separate constant clearer?
- Whether a named re-encryption flow (`vt name <record>`) ships with B1 or later.
