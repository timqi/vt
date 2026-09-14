// Sealed box v1 (docs/sealed-box-v1.md) for the opt-in DEK cache, on
// WebCrypto only: X25519 → HKDF-SHA256 → AES-256-GCM.
//
//   seal(m, rpk):  (esk, epk) fresh X25519 pair
//                  ss  = X25519(esk, rpk)                 refuse 0^32
//                  key = HKDF(ss, salt = epk‖rpk, info = "vt-sealed-box-v1")
//                  out = epk(32) ‖ AES-256-GCM(key, nonce 0^12, m, aad = epk‖rpk)
//
// The PWA (pwa/common.js vt.sealBox) seals with the same construction to the
// cache public key → openToCache here; seal here re-seals a hit to the CLI's
// ephemeral key → src/cf.rs open_sealed_deks. Byte-identical on all three
// sides, pinned by the shared vectors in test/cache_crypto.test.ts.
//
// Threat note: the cache scalar (HKDF of the root key, account_admin.ts) and
// the opened plaintext DEKs live in the Worker process for the duration of a
// cache op. This layer protects only against a raw DO-storage dump (entries
// are sealed to the cache public key); it does NOT protect against Worker
// compromise. See docs/dek-cache.md (Security boundary).

import { b64uDec, b64uEnc } from './crypto';

const X25519_KEYBYTES = 32;
const GCM_TAGBYTES = 16;
const X25519 = { name: 'X25519' } as const;
const INFO = new TextEncoder().encode('vt-sealed-box-v1');
// One ephemeral key per message, so the AES key is used exactly once and the
// nonce is a constant (docs/sealed-box-v1.md, Nonce).
const NONCE = new Uint8Array(12);
// RFC 8410 OneAsymmetricKey header for an X25519 scalar: WebCrypto imports a
// private key only as pkcs8 (raw is public-key only), so the HKDF-derived
// cache scalar is wrapped in this fixed prefix.
const PKCS8_X25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** The scalar as a private CryptoKey plus its public point (JWK `x`). */
async function importScalar(sk: Uint8Array): Promise<{ priv: CryptoKey; pk: Uint8Array }> {
  if (sk.length !== X25519_KEYBYTES) throw new Error('cache scalar: wrong length');
  const der = concat(PKCS8_X25519_PREFIX, sk);
  try {
    const priv = await crypto.subtle.importKey('pkcs8', der, X25519, true, ['deriveBits']);
    const jwk = await crypto.subtle.exportKey('jwk', priv) as JsonWebKey;
    if (typeof jwk.x !== 'string') throw new Error('cache scalar: no public point');
    return { priv, pk: b64uDec(jwk.x) };
  } finally {
    der.fill(0);
  }
}

/** X25519(priv, pub) as the AES-GCM key of one box; the shared secret never
 *  leaves this function and the AES key is never extractable. */
async function boxKey(
  priv: CryptoKey, peerPk: Uint8Array, epk: Uint8Array, rpk: Uint8Array, usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  const pub = await crypto.subtle.importKey('raw', peerPk, X25519, false, []);
  // workers-types spell X25519's `public` as `$public`, as for ECDH (webpush.ts).
  const ss = new Uint8Array(await crypto.subtle.deriveBits(
    { ...X25519, public: pub } as SubtleCryptoDeriveKeyAlgorithm, priv, 256));
  try {
    if (ss.every(b => b === 0)) throw new Error('sealed box: all-zero shared secret');
    const ikm = await crypto.subtle.importKey('raw', ss, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: concat(epk, rpk), info: INFO },
      ikm, { name: 'AES-GCM', length: 256 }, false, [usage]);
  } finally {
    ss.fill(0);
  }
}

/** The cache X25519 public key for a 32-byte scalar. */
export async function cachePublicKey(sk: Uint8Array): Promise<Uint8Array> {
  return (await importScalar(sk)).pk;
}

/** A one-shot X25519 public key whose private half is never referenced again,
 *  so NOTHING can ever open a box sealed to it.
 *
 *  Used as the `daemon_pubkey` of an enrollment or cache-extension ceremony:
 *  those flows reuse the standard approval PWA (one code path, no forked
 *  ceremony logic), and the PWA unconditionally seals its placeholder DEK block
 *  to the challenge's daemon_pubkey. There is no daemon on the far side — such
 *  a ceremony delivers no key material — so the sealed blob must be
 *  undecryptable by construction rather than merely unused. Returning a real
 *  curve point (not random bytes) keeps the PWA's seal on its normal path. */
export async function discardedBoxPublicKey(): Promise<Uint8Array> {
  const kp = await crypto.subtle.generateKey(X25519, false, ['deriveBits']) as CryptoKeyPair;
  return new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey) as ArrayBuffer);
}

/** seal(plaintext, recipientPk) → b64u. recipientPk is 32 bytes. */
export async function seal(plaintext: Uint8Array, recipientPk: Uint8Array): Promise<string> {
  if (recipientPk.length !== X25519_KEYBYTES) throw new Error('sealed box: recipient key wrong length');
  const eph = await crypto.subtle.generateKey(X25519, false, ['deriveBits']) as CryptoKeyPair;
  const epk = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey) as ArrayBuffer);
  const key = await boxKey(eph.privateKey, recipientPk, epk, recipientPk, 'encrypt');
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: NONCE, additionalData: concat(epk, recipientPk) }, key, plaintext));
  return b64uEnc(concat(epk, ct));
}

/** Open a box sealed to the cache public key. Returns null on any failure (a
 *  previous root key, the pre-v1 libsodium format, tamper, malformed) so the
 *  caller treats the entry as dead — a miss that sweeps it, never a 500 and
 *  never a second algorithm (docs/dek-cache.md M3, docs/sealed-box-v1.md). */
export async function openToCache(sealedB64u: string, sk: Uint8Array): Promise<Uint8Array | null> {
  try {
    const { priv, pk } = await importScalar(sk);
    const c = b64uDec(sealedB64u);
    if (c.length < X25519_KEYBYTES + GCM_TAGBYTES) return null;
    const epk = c.subarray(0, X25519_KEYBYTES);
    const ct = c.subarray(X25519_KEYBYTES);
    const key = await boxKey(priv, epk, epk, pk, 'decrypt');
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: NONCE, additionalData: concat(epk, pk) }, key, ct));
  } catch {
    return null;
  }
}
