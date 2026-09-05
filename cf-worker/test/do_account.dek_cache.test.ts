// AccountDO — opDekCache, the read side of the DEK cache.
//
// The cache is armed for every salt of a ceremony, and `writeCache` already
// chunks its put() at STORAGE_BATCH because "a ceremony may carry up to 256
// salts". The READ did not: it handed the whole key array to a single
// storage.get(), which the platform caps at 128 keys per call. A decrypt batch
// larger than that turned what should be a `{miss:true}` (or a hit) into a
// thrown 500 on the hot path.
//
// Note the local-runtime caveat: workerd/miniflare does NOT enforce the 128-key
// batch caps, so these tests would pass against the unbatched read too. They are
// a contract regression guard (the read must survive a >STORAGE_BATCH salt set
// and must still be all-or-nothing across chunk boundaries), not a reproduction
// of the production throw.

import { describe, it, expect, beforeEach } from 'vitest';
import { b64uEnc } from '../src/crypto';
import {
  inDO, setDoVar, doPost, approve, makeChallenge, makeMeta,
  sealFakeDek, nextSalt, allDekKeys, testEnv,
} from './do_helpers';

const TTL_8H = 8 * 3600;

// Any 32 bytes: the response is sealed TO this key, and nothing here opens it.
const DAEMON_PK_B64U = b64uEnc(new Uint8Array(32).fill(11));

beforeEach(async () => {
  await setDoVar('CACHE_SECKEY', testEnv.CACHE_SECKEY);
});

/** Run a real ceremony over `n` salts and approve it with an 8h cache. */
async function armCache(n: number): Promise<string[]> {
  const salts = Array.from({ length: n }, () => nextSalt());
  const ch = makeChallenge({ salts_b64u: salts });
  expect((await doPost('create', { challenge: ch })).status).toBe(200);
  const res = await approve(ch, {
    cache_ttl_s: TTL_8H,
    cache_sealed_deks_b64u: salts.map((_, i) => sealFakeDek((i % 251) + 1)),
  });
  expect(res.status).toBe(200);
  expect(await inDO(allDekKeys)).toHaveLength(n);
  return salts;
}

/** The read the Rust client performs. `meta` must carry the same ip + pwd the
 *  ceremony did — they ARE the binding ctx. */
function read(salts: string[], over = {}) {
  return doPost('dek-cache', {
    daemon_pubkey_b64u: DAEMON_PK_B64U,
    salts_b64u: salts,
    meta: makeMeta(over),
  });
}

describe('opDekCache — batched reads', () => {
  it('serves a hit for a salt set smaller than one storage batch', async () => {
    const salts = await armCache(4);
    const res = await read(salts);
    expect(res.status).toBe(200);
    expect(res.json).toMatchObject({ source: 'cache' });
    expect(typeof (res.json as { sealed_deks_b64u: string }).sealed_deks_b64u).toBe('string');
  });

  // 150 > STORAGE_BATCH (128) and < the 256 salt ceiling: the read spans two
  // get() calls. Before the fix this was one 150-key get(). The generous
  // timeout is for arming, not reading — approving 150 salts runs 150 real
  // seal/open round-trips through the ceremony.
  it('serves a hit for a salt set larger than one storage batch', { timeout: 60_000 }, async () => {
    const salts = await armCache(150);
    const res = await read(salts);
    expect(res.status).toBe(200);
    expect(res.json).toMatchObject({ source: 'cache' });
  });

  it('stays all-or-nothing across a chunk boundary', { timeout: 60_000 }, async () => {
    const salts = await armCache(150);
    // Replace a salt in the SECOND chunk (index 140 > 128) with one that was
    // never cached: a chunked read must not report a hit for the chunk that
    // did resolve.
    const probed = [...salts];
    probed[140] = nextSalt();
    const res = await read(probed);
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
  });

  it('misses (never throws) on a salt set at the 256 ceiling with nothing armed', async () => {
    const res = await read(Array.from({ length: 256 }, () => nextSalt()));
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
  });

  it('misses on a set over the 256 ceiling', async () => {
    const res = await read(Array.from({ length: 257 }, () => nextSalt()));
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
  });

  // Binding is per-ctx, not per-chunk, so this one needs no large salt set.
  it('misses when the binding pwd differs, even for armed salts', async () => {
    const salts = await armCache(4);
    const res = await read(salts, { pwd: '/home/tester/elsewhere' });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
  });
});
