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
  inDO, setDoVar, doPost, approve, makeChallenge, makeMeta, makeEntry, FAKE_CTX,
  sealFakeDek, nextSalt, allDekKeys, auditRows, testEnv, liveTokenId,
} from './do_helpers';

const TTL_8H = 8 * 3600;

// Any 32 bytes: the response is sealed TO this key, and nothing here opens it.
const DAEMON_PK_B64U = b64uEnc(new Uint8Array(32).fill(11));

// The host token is the cache key's hard half, so one test = one token: the
// ceremony that arms and the probe that reads must present the same one.
let tokenId: string;

beforeEach(async () => {
  await setDoVar('CACHE_SECKEY', testEnv.CACHE_SECKEY);
  tokenId = await liveTokenId();
});

/** Run a real ceremony over `n` salts and approve it with an 8h cache. */
async function armCache(n: number, meta = makeMeta()): Promise<string[]> {
  const salts = Array.from({ length: n }, () => nextSalt());
  const ch = makeChallenge({ salts_b64u: salts, meta });
  expect((await doPost('create', { challenge: ch, token_id: tokenId })).status).toBe(200);
  const res = await approve(ch, {
    cache_ttl_s: TTL_8H,
    cache_sealed_deks_b64u: salts.map((_, i) => sealFakeDek((i % 251) + 1)),
  });
  expect(res.status).toBe(200);
  expect(await inDO(allDekKeys)).toHaveLength(n);
  return salts;
}

/** The read the Rust client performs. `meta.project` must match the ceremony's
 *  — it is the advisory half of the key; the token is the hard half. */
async function read(salts: string[], over = {}, token = tokenId) {
  return doPost('dek-cache', {
    daemon_pubkey_b64u: DAEMON_PK_B64U,
    salts_b64u: salts,
    meta: makeMeta(over),
    token_id: token,
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

  // Binding is per-key, not per-chunk, so these need no large salt set.
  it('misses when the reported project differs, even for armed salts', async () => {
    const salts = await armCache(4);
    const res = await read(salts, { project: '/home/tester/elsewhere/.git' });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
  });

  it('misses for another live host token on the same project, IP and directory', async () => {
    const salts = await armCache(4);
    expect((await read(salts, {}, await liveTokenId())).json).toEqual({ miss: true });
    expect((await read(salts)).json).toMatchObject({ source: 'cache' });
  });

  it('hits across egress IP and cwd within one project; pwd/ip stay literal in audit and listing', async () => {
    const writtenPwd = '/home/tester/repo.feature';
    const readPwd = '/home/tester/repo.main';
    const salts = await armCache(2, makeMeta({ pwd: writtenPwd }));
    expect((await read(salts, { pwd: readPwd, ip: '198.51.100.4' })).json).toMatchObject({ source: 'cache' });
    await inDO(({ state }) => {
      expect(state.storage.sql.exec('SELECT pwd, ip FROM audit ORDER BY id').toArray())
        .toEqual([{ pwd: writtenPwd, ip: '203.0.113.9' }, { pwd: readPwd, ip: '198.51.100.4' }]);
    });
    const listing = await doPost('cache-list', {});
    const g = (listing.json as { groups: Array<{ pwd: string; ip: string }> }).groups[0]!;
    expect(g.pwd).toBe(writtenPwd);
    expect(g.ip).toBe('203.0.113.9');
  });

  // Rejected input: the v4 layout `dek:{ctx}:{salt}` (ctx = IP + normalized pwd)
  // has no token half. Such entries are never read — no dual-read — but they
  // stay listable and clearable until they lapse.
  it('never serves a v4-shaped entry, which stays listable and clearable', async () => {
    const salt = nextSalt();
    await inDO(h => h.state.storage.put(`dek:${FAKE_CTX}:${salt}`, makeEntry()));
    expect((await read([salt])).json).toEqual({ miss: true });
    const listing = await doPost('cache-list', {});
    expect((listing.json as { groups: unknown[] }).groups).toHaveLength(1);
    expect((await doPost('clear-cache', {})).json).toEqual({ cleared: 1 });
  });
});

describe('opDekCache / writeCache — token_id is the hard half', () => {
  it('refuses a probe without a token before touching the cache', async () => {
    const salts = await armCache(2);
    const res = await doPost('dek-cache', {
      daemon_pubkey_b64u: DAEMON_PK_B64U, salts_b64u: salts, meta: makeMeta(),
    });
    expect(res.status).toBe(400);
  });

  it('records write_failed instead of arming a key without a token half', async () => {
    const salts = [nextSalt(), nextSalt()];
    await inDO(async ({ inst }) => {
      await inst.writeCache(makeChallenge({ salts_b64u: salts }), TTL_8H, salts.map(() => sealFakeDek()));
    });
    expect(await inDO(allDekKeys)).toEqual([]);
    expect((await inDO(auditRows)).map(r => r.status)).toEqual(['write_failed']);
  });
});
