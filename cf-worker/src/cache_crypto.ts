// Sealed-box helpers for the opt-in DEK cache.
//
// We reproduce libsodium's `crypto_box_seal` / `crypto_box_seal_open` exactly,
// using pure-JS primitives that bundle cleanly under wrangler/esbuild:
//   • tweetnacl — X25519 + NaCl box (curve25519-xsalsa20-poly1305), the same
//     construction as libsodium crypto_box_easy.
//   • blakejs   — BLAKE2b, used only for the sealed-box nonce.
//
// libsodium crypto_box_seal(m, pk):
//   ephemeral (epk, esk) = box keypair
//   nonce = BLAKE2b-24(epk || pk)            (no key — standard generichash)
//   c     = box(m, nonce, pk, esk)           (32-byte epk prepended below)
//   out   = epk(32) || c
// open is the symmetric inverse. The output is byte-compatible with the Rust
// client's dryoc crypto_box_seal_open AND with the PWA's libsodium
// crypto_box_seal, so: PWA seals to CACHE_PUBKEY → Worker opens here; Worker
// seals to the daemon pubkey → cf.rs opens. (Chosen over libsodium-wrappers,
// whose ESM build fails to bundle under esbuild.)
//
// Threat note: CACHE_SECKEY and the opened plaintext DEKs live in the Worker
// process for the duration of a cache op. This layer protects only against a
// raw DO-storage dump (entries are sealed to CACHE_PUBKEY); it does NOT protect
// against Worker compromise. See docs/dek-cache.md §2/§3.

import nacl from 'tweetnacl';
import { blake2b } from 'blakejs';
import { b64uDec, b64uEnc } from './crypto';

const X25519_KEYBYTES = 32;       // crypto_box public/secret key length
const BOX_MACBYTES = 16;          // crypto_box_MACBYTES
const BOX_NONCEBYTES = 24;        // crypto_box_NONCEBYTES

// nonce = BLAKE2b(ephemeral_pk || recipient_pk), 24-byte output, unkeyed.
function sealNonce(epk: Uint8Array, recipientPk: Uint8Array): Uint8Array {
  const input = new Uint8Array(epk.length + recipientPk.length);
  input.set(epk, 0);
  input.set(recipientPk, epk.length);
  return blake2b(input, undefined, BOX_NONCEBYTES);
}

/** Derive the cache X25519 public key from the 32-byte secret key (b64u).
 *  Throws if the secret is missing or malformed — callers treat that as
 *  "caching disabled". */
export function cachePublicKey(secKeyB64u: string): Uint8Array {
  const sk = b64uDec(secKeyB64u);
  if (sk.length !== X25519_KEYBYTES) throw new Error('CACHE_SECKEY: wrong length');
  return nacl.scalarMult.base(sk);
}

/** A one-shot X25519 public key whose secret is destroyed before returning, so
 *  NOTHING can ever open a box sealed to it.
 *
 *  Used as the `daemon_pubkey` of a cache-extension ceremony: that flow reuses the
 *  standard approval PWA (one code path, no forked ceremony logic), and the PWA
 *  unconditionally seals its placeholder DEK block to the challenge's
 *  daemon_pubkey. There is no daemon on the far side — an extension delivers no
 *  key material — so the sealed blob must be undecryptable by construction rather
 *  than merely unused. Returning a real curve point (not random bytes) keeps the
 *  PWA's seal on the normal libsodium path. */
export function discardedBoxPublicKey(): Uint8Array {
  const sk = new Uint8Array(X25519_KEYBYTES);
  crypto.getRandomValues(sk);
  try {
    return nacl.scalarMult.base(sk);
  } finally {
    sk.fill(0);
  }
}

/** crypto_box_seal(plaintext, recipientPk) → b64u. recipientPk is 32 bytes. */
export function seal(plaintext: Uint8Array, recipientPk: Uint8Array): string {
  const eph = nacl.box.keyPair();
  try {
    const nonce = sealNonce(eph.publicKey, recipientPk);
    const ct = nacl.box(plaintext, nonce, recipientPk, eph.secretKey);
    const out = new Uint8Array(X25519_KEYBYTES + ct.length);
    out.set(eph.publicKey, 0);
    out.set(ct, X25519_KEYBYTES);
    return b64uEnc(out);
  } finally {
    eph.secretKey.fill(0);
  }
}

/** Open a crypto_box_seal produced for CACHE_PUBKEY. Returns null on any
 *  failure (wrong/rotated key, tamper, malformed) so callers treat it as a
 *  cache miss rather than a 500 — REQUIRED so rotating CACHE_SECKEY mid-window
 *  degrades to misses, not an error storm (docs/dek-cache.md M3). */
export function openToCache(sealedB64u: string, secKeyB64u: string): Uint8Array | null {
  try {
    const sk = b64uDec(secKeyB64u);
    if (sk.length !== X25519_KEYBYTES) return null;
    const pk = nacl.scalarMult.base(sk);
    const c = b64uDec(sealedB64u);
    if (c.length < X25519_KEYBYTES + BOX_MACBYTES) return null;
    const epk = c.subarray(0, X25519_KEYBYTES);
    const ct = c.subarray(X25519_KEYBYTES);
    const nonce = sealNonce(epk, pk);
    const m = nacl.box.open(ct, nonce, epk, sk);
    return m ?? null;
  } catch {
    return null;
  }
}
