# Sealed box v1

Status: **implemented**. The one asymmetric envelope VT uses between the
phone, the Worker and the CLI: the PWA seals the ceremony's DEKs to the CLI's
ephemeral key and, when a TTL is chosen, each DEK to the Worker's cache key;
the Worker opens cache entries and re-seals a hit to the CLI key; the CLI opens
both. It replaced libsodium `crypto_box_seal` (X25519 + XSalsa20-Poly1305 +
BLAKE2b nonce) so that every implementation is WebCrypto or an already-present
Rust crate: no 1.9 MB `libsodium.js` asset, no `tweetnacl`/`blakejs` in the
Worker, no `dryoc` in the binary. Three implementations, one construction,
byte-identical output: `cf-worker/pwa/common.js` (`vt.sealBox`),
`cf-worker/src/cache_crypto.ts` (`seal`, `openToCache`),
`src/cf.rs` (`open_sealed_deks`).

## Construction

```text
seal(m, rpk):
  (esk, epk) = fresh X25519 key pair             one per message, never reused
  ss   = X25519(esk, rpk)                         reject if ss == 0^32
  key  = HKDF-SHA256(ikm = ss, salt = epk ‖ rpk, info = "vt-sealed-box-v1", L = 32)
  ct   = AES-256-GCM(key, nonce = 0^12, m, aad = epk ‖ rpk)     ct includes the 16-byte tag
  out  = epk(32) ‖ ct

open(out, rsk, rpk):
  epk  = out[0..32], ct = out[32..]               refuse len(out) < 48
  ss   = X25519(rsk, epk)                         reject if ss == 0^32
  key, aad as above; AES-256-GCM-Decrypt; any failure is one opaque error
```

Byte layout: `epk` (32) ‖ AES-GCM ciphertext (len(m)) ‖ GCM tag (16). A
32-byte DEK seals to 80 bytes, `n` DEKs to `32·n + 48` — the same overhead as
the libsodium box it replaced, so every length check on the three sides is
unchanged.

- **Domain separation.** `info = "vt-sealed-box-v1"` names the construction;
  nothing else in VT derives from an X25519 shared secret with that label (the
  binding tag below uses `vt-sealed-deks-bind-v1`). The HKDF salt `epk ‖ rpk`
  binds the key to both parties' public keys, so a box moved to another
  recipient's key or given another ephemeral header derives a different key.
- **AAD** `epk ‖ rpk` binds the ciphertext to the header a second time, at the
  AEAD: a swapped `epk` fails authentication before any key confusion could
  matter. Redundant with the salt by design; it is one concatenation.
- **Nonce.** 12 zero bytes. The key is derived from a fresh ephemeral key per
  message, so each AES-GCM key encrypts exactly one message and the nonce
  carries no information; deriving one (a second HKDF output) would add code
  and a second test vector for no security gain. libsodium's
  `BLAKE2b(epk ‖ rpk)` nonce was likewise a deterministic function of the
  header. Never seal two messages under one ephemeral key.
- **All-zero shared secret.** A low-order peer point yields `ss = 0^32`;
  every implementation refuses it explicitly (WebCrypto also throws
  `OperationError` on it; the Rust side checks `SharedSecret::was_contributory`).
  The binding ECDH keeps its own check.
- **Failure.** Open returns one opaque failure (Worker: `null`, treated as a
  dead entry; CLI: `sealed_box open failed`), never which step failed.

## Binding ECDH (unchanged)

The approval's binding tag is a separate X25519 exchange between the PWA's
committed key pair and the CLI's ephemeral key:
`HMAC-SHA256(HKDF(ss, info = "vt-sealed-deks-bind-v1"), "vt-bind-v1" ‖ …)`
(`src/cf.rs` `verify_binding`). Only the primitive moved (WebCrypto
`deriveBits` / `x25519-dalek`); the wire format did not.

## WebCrypto notes

- **Private scalar import.** WebCrypto cannot import a raw X25519 private
  scalar (`importKey('raw', …)` is public-key only). The Worker's cache key is
  the scalar `HKDF(R, "vt-cache-seckey-v1")`, so `cache_crypto.ts` wraps it in
  the fixed 16-byte PKCS#8 prefix
  `30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20` (RFC 8410 `OneAsymmetricKey`,
  OID 1.3.101.110) and imports `pkcs8`. The public point comes from the same
  key exported as JWK (`x`); this is how `cachePublicKey(scalar)` still works
  with no scalar-multiplication code of our own. Verified in workerd and Node.
- **Discarded recipient.** `discardedBoxPublicKey()` (extension and enrollment
  ceremonies, which deliver no key material) is the public half of a
  `generateKey` pair whose private `CryptoKey` is never referenced again, so
  the PWA's placeholder seal is undecryptable by construction and stays on the
  normal seal path.
- **Key material lifetime.** Both JS sides derive the AES key with
  `deriveKey` (HKDF → non-extractable `AES-GCM` key), so no raw AES key bytes
  surface in JavaScript. The shared secret and every opened plaintext are
  `fill(0)`-ed as before; JavaScript-engine copies are out of reach either way.

## Browser floor

X25519 in `SubtleCrypto` (`importKey` / `deriveKey`; `deriveBits` ships with
it): **Safari 17.0** (macOS and iOS), **Firefox 130**, **Chrome 133**,
Edge 133, Samsung Internet 29 — per caniuse
(`mdn-api_subtlecrypto_derivekey_x25519`, retrieved 2026-09-14; the Igalia
write-up on Secure Curves in Chrome 133 agrees). The WebAuthn PRF extension
the page already depends on arrived later than X25519 on Safari (18) and
Firefox (135); Chrome's effective floor moves from PRF's 116 to 133.

The page never falls back: on a browser without X25519, `vt.x25519Keypair`
throws before the WebAuthn prompt and the status line reads
`此浏览器不支持 X25519（需 Safari 17 / Chrome 133 / Firefox 130 及以上）`. There is no
libsodium path to fall back to, by design.

## Rollout

- **CLI and Worker/PWA ship together.** A CLI opening a box with the previous
  primitive fails hard on a new Worker, and vice versa: `sealed_box open
  failed` on the ceremony path, and on the cache path a `source=cache`
  response with a bad box is a hard error, never a fallback
  ([dek-cache.md](dek-cache.md), client network bounds). Deploy the Worker
  (`just bump-assets`, `just deploy-worker`) and install the matching `vt` on
  every enrolled host in the same window.
- **Operator step: 清除全部 DEK 缓存** on the admin DEK 缓存 tab, before or
  after the deploy. Stored `dek:` entries are the only ciphertexts in the old
  format. One left behind is not a hard error: the read path fails closed for
  that request (a miss, so the phone ceremony runs) and deletes the entry as
  dead — never a silent open under the old algorithm, never a wedged cache.
  Persistent `vt://` records are untouched: PRF → `kWrap` → master → DEK was
  already WebCrypto HKDF/AES-GCM.
- `session-bind`, host tokens, the config blob and the admin session do not
  involve this envelope.

## Test vectors

Shared by the three implementations (`cf-worker/test/cache_crypto.test.ts`,
`src/cf.rs` tests). All b64url, no padding.

Deterministic vector (fixed ephemeral key; cross-checked with an independent
X25519/HKDF/AES-GCM implementation):

```text
rsk  ERERERERERERERERERERERERERERERERERERERERERE          (32 × 0x11)
rpk  e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM
esk  IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI          (32 × 0x22)
epk  D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyA
m    00 01 02 … 1f                                          (32 bytes)
box  D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyAXd0g_gjeoLbDGIQ2LVzEYHI8va2j8W808kbRSATfGUrDZFYbWuED_lkx7WVYQ6RQ
```

Two-DEK vector, same recipient, `esk = 32 × 0x33`, `m = 32 × 0xaa ‖ 32 × 0xbb`:

```text
box  ew1H2TQn-DERYHgcfHM_2J-IlwrvSQ2KoO4ZpMuKGxSXlmdFkev5R4nHJPIRmjXxGQdFQ-EGDFB48wLpysDwX7HUNqLVWN3JvVscbJ5oum4eKqAPi7jAR3ZV-37Y2_jNfk6rXmjkpUum2vvzfSn-TQ
```

Rejected input — the libsodium box the previous release's test used
(`crypto_box_seal` of `m` above to `rpk`), which every side must now refuse:

```text
box  JEYfUWAkbFlSTgjZD-GXcSHkANGFWCT637UiLWtBRUu-uQjaKW_GFnZplKkhLMm3h0-ch65fczHafJozQnVbdv4F-eyFxUbJuJoIzb9Anvw
```

Cross-implementation: the Rust tests open a box produced by the Worker's
`seal` and the Worker tests open a box produced by the Rust test-only sealer,
both committed as literals beside the deterministic vector.
