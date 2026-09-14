// Sealed box v1 (docs/sealed-box-v1.md): the shared vectors every
// implementation pins, plus the rejected pre-v1 libsodium input. Plain vitest
// (Node's WebCrypto has X25519); no workerd needed.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { b64uDec, b64uEnc } from '../src/crypto';
import { seal, openToCache, cachePublicKey, discardedBoxPublicKey } from '../src/cache_crypto';

// docs/sealed-box-v1.md "Test vectors": recipient scalar 32 × 0x11.
const RSK = new Uint8Array(32).fill(0x11);
const RPK_B64U = 'e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM';
const M = new Uint8Array(32).map((_, i) => i);
// Ephemeral 32 × 0x22, sealing M to RPK.
const BOX_B64U = 'D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyAXd0g_gjeoLbDGIQ2LVzEYHI8va2j8W808kbRSATfGUrDZFYbWuED_lkx7WVYQ6RQ';
// Ephemeral 32 × 0x33, sealing 32 × 0xaa ‖ 32 × 0xbb to RPK.
const BOX2_B64U = 'ew1H2TQn-DERYHgcfHM_2J-IlwrvSQ2KoO4ZpMuKGxSXlmdFkev5R4nHJPIRmjXxGQdFQ-EGDFB48wLpysDwX7HUNqLVWN3JvVscbJ5oum4eKqAPi7jAR3ZV-37Y2_jNfk6rXmjkpUum2vvzfSn-TQ';
// The previous release's libsodium crypto_box_seal of M to RPK.
const LIBSODIUM_BOX_B64U = 'JEYfUWAkbFlSTgjZD-GXcSHkANGFWCT637UiLWtBRUu-uQjaKW_GFnZplKkhLMm3h0-ch65fczHafJozQnVbdv4F-eyFxUbJuJoIzb9Anvw';

describe('sealed box v1', () => {
  it('derives the cache public key from the scalar', async () => {
    expect(b64uEnc(await cachePublicKey(RSK))).toBe(RPK_B64U);
    await expect(cachePublicKey(new Uint8Array(31))).rejects.toThrow(/wrong length/);
  });

  it('opens the deterministic vectors', async () => {
    expect(Array.from((await openToCache(BOX_B64U, RSK))!)).toEqual(Array.from(M));
    const two = (await openToCache(BOX2_B64U, RSK))!;
    expect(two.length).toBe(64);
    expect(two.subarray(0, 32).every(b => b === 0xaa)).toBe(true);
    expect(two.subarray(32).every(b => b === 0xbb)).toBe(true);
  });

  it('round-trips with a fresh ephemeral key per box', async () => {
    const rpk = b64uDec(RPK_B64U);
    const a = await seal(M, rpk);
    const b = await seal(M, rpk);
    expect(b64uDec(a).length).toBe(80);
    expect(a).not.toBe(b);
    expect(Array.from((await openToCache(a, RSK))!)).toEqual(Array.from(M));
    expect(Array.from((await openToCache(b, RSK))!)).toEqual(Array.from(M));
  });

  it('refuses the pre-v1 libsodium box, tamper, truncation and the wrong key', async () => {
    expect(await openToCache(LIBSODIUM_BOX_B64U, RSK)).toBeNull();
    const box = b64uDec(BOX_B64U);
    for (const i of [0, 31, 32, 79]) {
      const t = new Uint8Array(box);
      t[i]! ^= 0x01;
      expect(await openToCache(b64uEnc(t), RSK)).toBeNull();
    }
    expect(await openToCache(b64uEnc(box.subarray(0, 47)), RSK)).toBeNull();
    expect(await openToCache('!', RSK)).toBeNull();
    expect(await openToCache(BOX_B64U, new Uint8Array(32).fill(0x12))).toBeNull();
    expect(await openToCache(BOX_B64U, new Uint8Array(31))).toBeNull();
  });

  it('refuses the all-zero shared secret', async () => {
    await expect(seal(M, new Uint8Array(32))).rejects.toThrow();
    const lowOrder = new Uint8Array(b64uDec(BOX_B64U));
    lowOrder.fill(0, 0, 32);
    expect(await openToCache(b64uEnc(lowOrder), RSK)).toBeNull();
  });

  it('gives a discarded recipient no box can reach', async () => {
    const pk = await discardedBoxPublicKey();
    expect(pk.length).toBe(32);
    const sealed = await seal(M, pk);
    expect(b64uDec(sealed).length).toBe(80);
    expect(await openToCache(sealed, RSK)).toBeNull();
  });
});

// The PWA's implementation (pwa/common.js vt.sealBox) is the third copy of
// the construction; it is plain browser script, so evaluate it here with a
// `window` shim and prove its boxes open with the Worker's openToCache. A
// real browser's X25519 is still only verified on a real phone.
describe('pwa/common.js vt.sealBox', () => {
  const src = readFileSync(new URL('../pwa/common.js', import.meta.url), 'utf8');
  const win: { vt?: Record<string, (...a: never[]) => unknown> } = {};
  new Function('window', src)(win);
  const pwa = win.vt as unknown as {
    sealBox(m: Uint8Array, rpk: Uint8Array): Promise<Uint8Array>;
    x25519Keypair(): Promise<{ privateKey: CryptoKey; pk: Uint8Array }>;
    x25519(k: CryptoKey, pk: Uint8Array): Promise<Uint8Array>;
  };

  it('seals what openToCache opens, 80 bytes per DEK', async () => {
    const box = await pwa.sealBox(M, b64uDec(RPK_B64U));
    expect(box.length).toBe(80);
    expect(Array.from((await openToCache(b64uEnc(box), RSK))!)).toEqual(Array.from(M));
    const two = await pwa.sealBox(new Uint8Array(64).fill(0xcd), b64uDec(RPK_B64U));
    expect(two.length).toBe(112);
    expect((await openToCache(b64uEnc(two), RSK))!.every(b => b === 0xcd)).toBe(true);
  });

  it('refuses the all-zero shared secret in the binding exchange', async () => {
    const kp = await pwa.x25519Keypair();
    expect(kp.pk.length).toBe(32);
    await expect(pwa.x25519(kp.privateKey, new Uint8Array(32))).rejects.toThrow();
    await expect(pwa.sealBox(M, new Uint8Array(32))).rejects.toThrow();
  });
});
