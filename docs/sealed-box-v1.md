# Sealed box v1

This document specifies interoperable key delivery between the phone, Worker,
and CLI. It protects DEKs for one recipient without introducing another key
custody. Persistent `vt://` records use a separate format.

## Construction

```text
seal(m, rpk):
  (esk, epk) = fresh X25519 key pair
  ss  = X25519(esk, rpk)                         reject ss == 0^32
  key = HKDF-SHA256(ikm=ss, salt=epk || rpk, info="vt-sealed-box-v1", L=32)
  ct  = AES-256-GCM(key, nonce=0^12, plaintext=m, aad=epk || rpk)
  out = epk(32) || ct                            ct includes the 16-byte tag

open(out, rsk, rpk):
  reject len(out) < 48
  epk = out[0..32]; ct = out[32..]
  ss  = X25519(rsk, epk)                         reject ss == 0^32
  derive key and AAD as above; authenticate and decrypt ct
```

A message of `n` bytes produces `n + 48` bytes. A 32-byte DEK produces 80 bytes.

- Each message uses a fresh ephemeral pair; never reuse it. The fixed nonce is
  safe only because each derived AES key encrypts exactly one message.
- Both public keys bind derivation and authentication; changing the recipient
  or ephemeral header must fail.
- The HKDF label separates this construction from other key derivations.
- Every implementation rejects an all-zero shared secret, including when the
  platform already rejects the low-order point.
- Opening returns one opaque failure rather than exposing which step failed.
- JavaScript buffer wiping does not guarantee erasure of engine-managed copies.

## Approval binding

The approval binding tag uses a separate X25519 exchange between the PWA's
committed pair and the CLI's ephemeral key, with the distinct
`vt-sealed-deks-bind-v1` derivation label. It must not be conflated with sealed-box
recipient binding. The authenticated transcript is defined by `verify_binding`
in [src/cf.rs](../src/cf.rs).

## Interoperability

The PWA seals to the CLI key and optional Worker cache key. The Worker opens
cached entries and re-seals hits to the requesting CLI; the CLI opens either
source with this same construction.

Implementations and shared vectors are in
[common.js](../cf-worker/pwa/common.js),
[cache_crypto.ts](../cf-worker/src/cache_crypto.ts),
[src/cf.rs](../src/cf.rs), and
[cache_crypto.test.ts](../cf-worker/test/cache_crypto.test.ts).
Keep deterministic cross-implementation vectors and rejected-input tests there.

The browser must support WebCrypto X25519 and WebAuthn PRF; there is no alternate
crypto fallback. Browser requirements and the current coordinated upgrade step
belong to [cf-worker-deploy.md](cf-worker-deploy.md).
