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
// batch caps, so the batch sizes themselves are pinned by a storage spy in
// do_account.safety.test.ts; here the read must stay all-or-nothing across a
// chunk boundary.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { b64uEnc } from '../src/crypto';
import { cacheCtx } from '../src/account_cache';
import {
  inDO, doPost, doGet, approve, makeChallenge, makeMeta, makeEntry, FAKE_CTX,
  sealFakeDek, nextSalt, allDekKeys, auditRows, liveTokenId, daemonAuth,
  bootstrap,
} from './do_helpers';

const TTL_8H = 8 * 3600;

// Any 32 bytes: the response is sealed TO this key, and nothing here opens it.
const DAEMON_PK_B64U = b64uEnc(new Uint8Array(32).fill(11));

// The host token is the cache key's hard half, so one test = one token: the
// ceremony that arms and the probe that reads must present the same one.
let tokenId: string;

beforeEach(async () => {
  await bootstrap();
  tokenId = await liveTokenId();
});

/** Run a real ceremony over `n` salts and approve it with an 8h cache,
 *  host-wide unless `bindProject` (the approver's "Restrict to this project"). */
async function armCache(n: number, meta = makeMeta(), bindProject?: boolean): Promise<string[]> {
  const salts = Array.from({ length: n }, () => nextSalt());
  const ch = makeChallenge({ salts_b64u: salts, meta });
  expect((await doPost('create', { challenge: ch, auth: await daemonAuth(tokenId) })).status).toBe(200);
  const before = (await inDO(allDekKeys)).length;
  const res = await approve(ch, {
    cache_ttl_s: TTL_8H,
    cache_sealed_deks_b64u: await Promise.all(salts.map((_, i) => sealFakeDek((i % 251) + 1))),
    ...(bindProject === undefined ? {} : { cache_bind_project: bindProject }),
  });
  expect(res.status).toBe(200);
  expect(await inDO(allDekKeys)).toHaveLength(before + n);
  return salts;
}

/** The read the Rust client performs. The token is the key's hard half; a
 *  project-restricted entry also needs `meta.project` to match the ceremony's. */
async function read(salts: string[], over = {}, token = tokenId) {
  return doPost('dek-cache', {
    daemon_pubkey_b64u: DAEMON_PK_B64U,
    salts_b64u: salts,
    meta: makeMeta(over),
    auth: await daemonAuth(token),
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
  // get() calls. The generous timeout is for arming, not reading — approving
  // 150 salts runs 150 real seal/open round-trips through the ceremony.
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

  // Every salt is live under the probing token, so only the ceiling refuses it.
  it('misses on a set over the 256 ceiling even when every salt is armed', async () => {
    const salts = Array.from({ length: 257 }, () => nextSalt());
    await inDO(async h => {
      const entry = await makeEntry();
      const ctx = await cacheCtx(tokenId, entry.project);
      for (const s of salts) await h.state.storage.put(`dek:${ctx}:${s}`, entry);
    });
    const res = await read(salts);
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
  });

  // Read-time expiry is authoritative: a lapsed entry the sweep has not reached
  // yet is a miss, and a miss writes no hit row.
  it('misses on a lapsed entry before the sweep removes it', async () => {
    const salts = await armCache(2);
    await inDO(async h => {
      const [first] = await allDekKeys(h);
      const e = (await h.state.storage.get<Record<string, unknown>>(first!))!;
      await h.state.storage.put(first!, { ...e, expires_ms: Date.now() - 1 });
    });
    const rowsBefore = (await inDO(auditRows)).length;
    const res = await read(salts);
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
    expect(await inDO(allDekKeys)).toHaveLength(2);
    expect(await inDO(auditRows)).toHaveLength(rowsBefore);
  });

  // Binding is per-key, not per-chunk, so these need no large salt set.
  it('misses when the reported project differs from a restricted entry, even for armed salts', async () => {
    const salts = await armCache(4, makeMeta(), true);
    const res = await read(salts, { project: '/home/tester/elsewhere/.git' });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
    expect((await read(salts)).json).toMatchObject({ source: 'cache' });
  });

  it('hits a host-wide entry (the default) from any project and cwd on the same token', async () => {
    const salts = await armCache(4, makeMeta(), false);
    for (const over of [{ project: '/home/tester/elsewhere/.git', pwd: '/tmp' }, { project: '' }, {}]) {
      expect((await read(salts, over)).json).toMatchObject({ source: 'cache' });
    }
    expect((await read(salts, {}, await liveTokenId())).json).toEqual({ miss: true });
  });

  // Entries written before host-wide scope all carry a project: same key, same
  // rule, until they expire.
  it('keeps serving an existing project entry only for its project', async () => {
    const salts = [nextSalt(), nextSalt()];
    await inDO(async h => {
      const entry = await makeEntry({ project: makeMeta().project });
      const ctx = await cacheCtx(tokenId, makeMeta().project);
      for (const s of salts) await h.state.storage.put(`dek:${ctx}:${s}`, entry);
    });
    expect((await read(salts, { project: '/home/tester/elsewhere/.git' })).json).toEqual({ miss: true });
    expect((await read(salts)).json).toMatchObject({ source: 'cache' });
  });

  // All-or-nothing is per salt across scopes: each salt may hit under either.
  it('hits a set whose salts are armed under different scopes', async () => {
    const hostWide = await armCache(1, makeMeta(), false);
    const bound = await armCache(1, makeMeta(), true);
    expect((await read([...hostWide, ...bound])).json).toMatchObject({ source: 'cache' });
    expect((await read([...hostWide, ...bound], { project: '/elsewhere' })).json).toEqual({ miss: true });
  });

  it('refuses a non-boolean restriction instead of guessing a scope', async () => {
    const salts = [nextSalt()];
    const ch = makeChallenge({ salts_b64u: salts });
    expect((await doPost('create', { challenge: ch, auth: await daemonAuth(tokenId) })).status).toBe(200);
    const res = await approve(ch, {
      cache_ttl_s: TTL_8H, cache_sealed_deks_b64u: [await sealFakeDek()], cache_bind_project: 'yes',
    });
    expect(res.status).toBe(400);
    expect(await inDO(allDekKeys)).toEqual([]);
  });

  it('records the armed scope on the approval row and in the listing', async () => {
    const meta = makeMeta();
    await armCache(1, meta, false);
    await armCache(1, meta, true);
    const rows = await inDO(({ state }) => state.storage.sql
      .exec(`SELECT scope_family, scope_label FROM audit WHERE cache_ttl_s > 0 ORDER BY id`).toArray());
    expect(rows).toEqual([
      { scope_family: 'host', scope_label: 'any project (host-wide)' },
      { scope_family: 'project', scope_label: `project ${meta.project} only` },
    ]);
    const listing = (await doPost('cache-list', {})).json as { entries: Array<{ project: string | null }> };
    expect(listing.entries.map(e => e.project).sort()).toEqual([meta.project, null].sort());
    // Host-wide entries store no project.
    const stored = await inDO(async h => Promise.all((await allDekKeys(h)).map(k => h.state.storage.get<{ project?: string }>(k))));
    expect(stored.map(e => e!.project).sort()).toEqual([meta.project, undefined].sort());
  });

  it('misses for another live host token on the same project, IP and directory', async () => {
    const salts = await armCache(4);
    expect((await read(salts, {}, await liveTokenId())).json).toEqual({ miss: true });
    expect((await read(salts)).json).toMatchObject({ source: 'cache' });
  });

  it('hits across egress IP and cwd within one project; pwd/ip stay literal in audit, ip in the listing', async () => {
    const writtenPwd = '/home/tester/repo.feature';
    const readPwd = '/home/tester/repo.main';
    const salts = await armCache(2, makeMeta({ pwd: writtenPwd }), true);
    expect((await read(salts, { pwd: readPwd, ip: '198.51.100.4' })).json).toMatchObject({ source: 'cache' });
    await inDO(({ state }) => {
      expect(state.storage.sql.exec('SELECT pwd, ip FROM audit ORDER BY id').toArray())
        .toEqual([{ pwd: writtenPwd, ip: '203.0.113.9' }, { pwd: readPwd, ip: '198.51.100.4' }]);
    });
    const listing = await doPost('cache-list', {});
    const e = (listing.json as { entries: Array<{ project: string; ip: string }> }).entries[0]!;
    expect(e.project).toBe(makeMeta().project);
    expect(e.ip).toBe('203.0.113.9');
  });

  // Rejected input: the v4 layout `dek:{ctx}:{salt}` (ctx = IP + normalized pwd)
  // has no token half. Such entries are never read — no dual-read — but they
  // stay listable and clearable until they lapse.
  it('never serves an entry with no created_ms', async () => {
    const salts = await armCache(2);
    await inDO(async h => {
      for (const k of await allDekKeys(h)) {
        const { created_ms: _dropped, ...rest } = (await h.state.storage.get<Record<string, unknown>>(k))!;
        await h.state.storage.put(k, rest);
      }
    });
    expect((await read(salts)).json).toEqual({ miss: true });
  });

  // Rejected input: an entry sealed by the previous release's libsodium
  // crypto_box_seal (docs/sealed-box-v1.md, Rollout). The operator step is
  // Clear all DEK caches; one left behind must be a miss that removes itself, never
  // an open under the old algorithm and never a 500.
  it('misses on a pre-v1 libsodium entry and sweeps it', async () => {
    const salts = await armCache(2);
    const LIBSODIUM_BOX = 'JEYfUWAkbFlSTgjZD-GXcSHkANGFWCT637UiLWtBRUu-uQjaKW_GFnZplKkhLMm3h0-ch65fczHafJozQnVbdv4F-eyFxUbJuJoIzb9Anvw';
    const [first] = await inDO(async h => {
      const keys = await allDekKeys(h);
      const entry = (await h.state.storage.get<Record<string, unknown>>(keys[0]!))!;
      await h.state.storage.put(keys[0]!, { ...entry, sealed_to_cache_b64u: LIBSODIUM_BOX });
      return keys;
    });
    const res = await read(salts);
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
    expect(await inDO(allDekKeys)).not.toContain(first);
    expect(await inDO(allDekKeys)).toHaveLength(1);
  });

  it('never serves a v4-shaped entry, which stays listable and clearable', async () => {
    const salt = nextSalt();
    await inDO(async h => h.state.storage.put(`dek:${FAKE_CTX}:${salt}`, await makeEntry()));
    expect((await read([salt])).json).toEqual({ miss: true });
    const listing = await doPost('cache-list', {});
    expect((listing.json as { entries: unknown[] }).entries).toHaveLength(1);
    expect((await doPost('clear-cache', {})).json).toEqual({ cleared: 1 });
  });
});

// W-11: a salt of the wrong length is a uniform miss decided before any
// storage read — an over-long one would otherwise become an oversize storage
// key and surface as a 500.
it('misses on a malformed or over-long salt without touching storage', async () => {
  const salts = await armCache(1);
  const get = await inDO(({ state }) => vi.spyOn(state.storage, 'get'));
  try {
    for (const bad of ['A'.repeat(21), 'A'.repeat(23), 'A'.repeat(3000), 'not/b64u!']) {
      const res = await read([...salts, bad]);
      expect(res.status).toBe(200);
      expect(res.json).toEqual({ miss: true });
    }
    expect(get.mock.calls.filter(([k]) => Array.isArray(k) && k.some(x => String(x).startsWith('dek:')))).toHaveLength(0);
  } finally {
    get.mockRestore();
  }
});

describe('opDekCache / writeCache — token_id is the hard half', () => {
  it('refuses a probe without a token or with a bad MAC before touching the cache', async () => {
    const salts = await armCache(2);
    const res = await doPost('dek-cache', {
      daemon_pubkey_b64u: DAEMON_PK_B64U, salts_b64u: salts, meta: makeMeta(),
    });
    expect(res.status).toBe(400);
    const auth = await daemonAuth(tokenId);
    const forged = await doPost('dek-cache', {
      daemon_pubkey_b64u: DAEMON_PK_B64U, salts_b64u: salts, meta: makeMeta(),
      auth: { ...auth, signed_b64u: b64uEnc(new TextEncoder().encode('{"x":1}')) },
    });
    expect(forged.status).toBe(401);
    expect(forged.text).toBe('hmac mismatch');
  });

  // There is no cache switch: option 0 (the default) is the no-cache path, and
  // an auth-only ceremony has nothing to offer.
  it('offers the ladder for a salted ceremony, only [0] for an auth-only one', async () => {
    const ch = makeChallenge({ salts_b64u: [nextSalt()] });
    expect((await doPost('create', { challenge: ch, auth: await daemonAuth(tokenId) })).status).toBe(200);
    const page = await doGet(`page?approve_token=${ch.approve_token}`);
    expect(page.json.cache_options_s[0]).toBe(0);
    expect(page.json.cache_options_s.length).toBeGreaterThan(1);
    expect(page.json.cache_pubkey_b64u).not.toBe('');
    const auth = makeChallenge({ salts_b64u: [] });
    expect((await doPost('create', { challenge: auth, auth: await daemonAuth(tokenId) })).status).toBe(200);
    const authPage = await doGet(`page?approve_token=${auth.approve_token}`);
    expect(authPage.json.cache_options_s).toEqual([0]);
    expect(authPage.json.cache_pubkey_b64u).toBe('');
  });

  it('records write_failed instead of arming a key without a token half', async () => {
    const salts = [nextSalt(), nextSalt()];
    await inDO(async ({ inst }) => {
      await inst.writeCache(makeChallenge({ salts_b64u: salts }), TTL_8H, await Promise.all(salts.map(() => sealFakeDek())));
    });
    expect(await inDO(allDekKeys)).toEqual([]);
    expect((await inDO(auditRows)).map(r => r.status)).toEqual(['write_failed']);
  });
});
