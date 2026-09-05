// AccountDO — the admin cache inventory (opCacheList) and the clear paths.
//
// "Cache listings must never expose sealed material, salts, or the binding ctx
// digest (ctx + a known IP is an offline oracle for the client-reported `pwd`),
// and must report `truncated` rather than silently showing a partial view."
// (CLAUDE.md) The listing is also where the UI learns whether a row may be
// extended, so the reason projection is pinned here too.
//
// The listing may be partial as long as it SAYS so. A clear may not: see the
// second half of this file.

import { describe, it, expect, beforeEach } from 'vitest';
import type { CacheEntry, CacheListResponse } from '../src/types';
import { extendTtlOptions } from '../src/cache_policy';
import {
  inDO, seedGroup, setDoVar, doGet, doPost, makeEntry, makeMeta, FAKE_CTX, nextSalt,
  allDekKeys, DoHandle,
} from './do_helpers';

const MIN = 60_000;
const HOUR = 60 * MIN;

const GROUP = 'g_testgroup00000';

beforeEach(async () => { await setDoVar('CACHE_ADMIN_EXTEND', '0'); });

async function list(): Promise<{ body: CacheListResponse; text: string }> {
  const res = await doGet('cache-list');
  expect(res.status).toBe(200);
  return { body: res.json as CacheListResponse, text: res.text };
}

describe('opCacheList — inventory without secrets', () => {
  it('summarises a group and leaks no sealed blob, salt, or binding ctx', async () => {
    const keys = await inDO(h => seedGroup(h, 3, { expires_ms: Date.now() + HOUR }));
    const sealed = await inDO(async h =>
      (await h.state.storage.get<CacheEntry>(keys[0]!))!.sealed_to_cache_b64u);

    const { body, text } = await list();
    expect(body.groups).toHaveLength(1);
    const g = body.groups[0]!;
    expect(g.group_id).toBe(GROUP);
    expect(g.entries).toBe(3);
    expect(g.live).toBe(3);
    expect(g.ip).toBe('203.0.113.9');

    // Nothing that could rebuild a key or an offline oracle.
    expect(text).not.toContain(sealed);
    expect(text).not.toContain(FAKE_CTX);
    for (const k of keys) {
      expect(text).not.toContain(k);
      expect(text).not.toContain(k.split(':')[2]!);   // the salt
    }
    expect(text).not.toContain('sealed');
    expect(JSON.stringify(Object.keys(g))).not.toMatch(/salt|sealed|ctx/i);
  });

  it('joins the origin approval context the audit tab already shows', async () => {
    const originToken = 'listorigin000001';
    await inDO(h => {
      h.inst.audit.create({
        approve_token: originToken,
        created_ms: Date.now(),
        salts_b64u: ['s'],
        meta: makeMeta({ host: 'listbox', user: 'lister', pwd: '/srv/app' }),
      });
      h.inst.audit.finalize(originToken, 'approved', 1234);
      h.inst.audit.setCacheTtl(originToken, 20 * 60, Date.now() + 20 * MIN);
    });
    await inDO(h => seedGroup(h, 1, {
      expires_ms: Date.now() + 20 * MIN, origin_token_id: originToken,
    }));

    const { body } = await list();
    const g = body.groups[0]!;
    expect(g.host).toBe('listbox');
    expect(g.user).toBe('lister');
    expect(g.pwd).toBe('/srv/app');
    expect(g.cache_ttl_s).toBe(20 * 60);
  });

  it('reports the kill switch and the extend ladder, both straight from policy', async () => {
    await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR }));
    expect((await list()).body.extend_enabled).toBe(false);
    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    const { body } = await list();
    expect(body.extend_enabled).toBe(true);
    expect(body.ttl_options_s).toEqual(extendTtlOptions());
  });

  it('explains why a row is not extendable without hiding it', async () => {
    // A lapsed group, a drifted group, and one with no usable handle at all.
    await inDO(h => seedGroup(h, 1, {
      expires_ms: Date.now() - MIN, cache_group_id: 'g_lapsedgroup000',
    }));
    await inDO(h => seedGroup(h, 1, {
      expires_ms: Date.now() + HOUR, cache_group_id: 'g_driftgroup0000', ip: '203.0.113.9',
    }));
    await inDO(h => seedGroup(h, 1, {
      expires_ms: Date.now() + HOUR, cache_group_id: 'g_driftgroup0000', ip: '198.51.100.4',
    }));
    await inDO(h => seedGroup(h, 1, {
      expires_ms: Date.now() + HOUR, cache_group_id: undefined, origin_token_id: '',
    }));
    // …and one ordinary live group, so the contrast is in the same response.
    await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR }));

    const { body } = await list();
    const by = new Map(body.groups.map(g => [g.group_id, g]));
    expect(by.size).toBe(4);
    expect(by.get('g_lapsedgroup000')!.reason).toBe('expired');
    expect(by.get('g_lapsedgroup000')!.extendable).toBe(false);
    expect(by.get('g_driftgroup0000')!.reason).toBe('inconsistent');
    expect(by.get('legacy:')!.reason).toBe('not_extendable');
    expect(by.get(GROUP)!.extendable).toBe(true);
    expect(by.get(GROUP)!.reason).toBeNull();
    // Every row is still LISTED — the clear path must never be hidden.
    for (const g of body.groups) expect(g.entries).toBeGreaterThan(0);
  });

  it('counts lapsed-but-unswept entries as entries, not as live', async () => {
    const now = Date.now();
    await inDO(async h => {
      await h.state.storage.put(`dek:${FAKE_CTX}:${nextSalt()}`,
        makeEntry({ expires_ms: now - MIN, created_ms: now - HOUR }));
      await h.state.storage.put(`dek:${FAKE_CTX}:${nextSalt()}`,
        makeEntry({ expires_ms: now + HOUR, created_ms: now - HOUR }));
    });
    const g = (await list()).body.groups[0]!;
    expect(g.entries).toBe(2);
    expect(g.live).toBe(1);
    expect(g.max_expires_ms).toBeGreaterThan(now);
  });

  it('says `truncated` instead of passing a partial scan off as complete', async () => {
    // CACHE_LIST_SCAN_MAX is 20000 entries per listing.
    const SCAN_MAX = 20000;
    await inDO(async h => {
      const entry = makeEntry({ expires_ms: Date.now() + HOUR });
      for (let i = 0; i < SCAN_MAX; i += 128) {
        const batch: Record<string, CacheEntry> = {};
        for (let j = 0; j < 128 && i + j < SCAN_MAX; j++) {
          batch[`dek:${FAKE_CTX}:${String(i + j).padStart(8, '0')}`] = entry;
        }
        await h.state.storage.put(batch);
      }
    });

    const { body } = await list();
    expect(body.truncated).toBe(true);
    expect(body.scanned).toBeGreaterThanOrEqual(SCAN_MAX);
  }, 120_000);

  it('reports truncated=false for a scan that really did see everything', async () => {
    await inDO(h => seedGroup(h, 5, { expires_ms: Date.now() + HOUR }));
    const { body } = await list();
    expect(body.truncated).toBe(false);
    expect(body.scanned).toBe(5);
  });
});

// ── The revoke paths ───────────────────────────────────────────────────────
//
// A clear is the authority-REDUCING half of the admin surface and, per CLAUDE.md,
// "the only revoke path" a row exposes. The contract these pin is therefore
// completeness, not a flag: a clear pages the `dek:` prefix to its end, and the
// count it returns is what storage actually removed — never what it intended to.
//
// This is where the bug found by the first pass of these tests lived:
// opCacheClearGroups reused scanCacheGroups, inheriting its CACHE_LIST_SCAN_MAX
// cap without inheriting the `truncated` the listing surfaces, so a group sorting
// past the cap was never seen, never deleted, and the route still answered
// 200 {"cleared":0,"groups":0}.

/** Write `n` entries at fully controlled keys, so a test can decide exactly
 *  where a group lands in the sorted `dek:` prefix. '0…' sorts before every
 *  base64url salt; 'z…' sorts after all of them. */
async function putAt(
  h: DoHandle, prefix: string, n: number, over: Partial<CacheEntry> = {},
): Promise<string[]> {
  const entry = makeEntry({ expires_ms: Date.now() + HOUR, ...over });
  const keys: string[] = [];
  for (let i = 0; i < n; i += 128) {
    const batch: Record<string, CacheEntry> = {};
    for (let j = 0; j < 128 && i + j < n; j++) {
      const key = `dek:${FAKE_CTX}:${prefix}${String(i + j).padStart(8, '0')}`;
      keys.push(key);
      batch[key] = entry;
    }
    await h.state.storage.put(batch);
  }
  return keys;
}

async function present(h: DoHandle, keys: string[]): Promise<number> {
  let n = 0;
  for (const k of keys) if (await h.state.storage.get(k)) n++;
  return n;
}

/** 20000 entries — CACHE_LIST_SCAN_MAX — parked ahead of everything else in the
 *  sorted prefix, so anything seeded after them is only reachable by a scan that
 *  refuses to stop at the cap. */
const SCAN_MAX = 20000;
function seedPastTheCap(h: DoHandle) {
  return putAt(h, '0', SCAN_MAX, { cache_group_id: 'g_bulkfiller0000', origin_token_id: 'fillerorigin0001' });
}

describe('cache clear paths — exhaustive by contract', () => {
  it('clears a group that sorts past the listing scan cap', async () => {
    const filler = await inDO(seedPastTheCap);
    const target = await inDO(h => putAt(h, 'z', 3, { cache_group_id: 'g_targetgroup000' }));

    const res = await doPost('cache-clear-groups', { group_ids: ['g_targetgroup000'] });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ cleared: 3, groups: 1 });
    expect(await inDO(h => present(h, target))).toBe(0);
    // …and only that group: a clear must not become a wildcard.
    expect(await inDO(h => present(h, filler.slice(0, 50)))).toBe(50);
  }, 120_000);

  it('clears every entry of a group larger than one delete batch', async () => {
    // DO storage takes at most 128 keys per delete(); 300 needs three calls, and
    // an unchunked array would throw and remove nothing.
    const target = await inDO(h => putAt(h, 'z', 300, { cache_group_id: 'g_bigsingle00000' }));
    const res = await doPost('cache-clear-groups', { group_ids: ['g_bigsingle00000'] });
    expect(res.json).toEqual({ cleared: 300, groups: 1 });
    expect(await inDO(h => present(h, target))).toBe(0);
    expect(await inDO(allDekKeys)).toEqual([]);
  }, 120_000);

  it('reports only what it actually removed', async () => {
    const keep = await inDO(h => putAt(h, 'z', 4, { cache_group_id: 'g_untouched00000' }));
    const res = await doPost('cache-clear-groups', { group_ids: ['g_nosuchgroup000'] });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ cleared: 0, groups: 0 });
    expect(await inDO(h => present(h, keep))).toBe(4);
  });

  it('still clears by group when the handle is a legacy: one', async () => {
    const target = await inDO(h => putAt(h, 'z', 2, {
      cache_group_id: undefined, origin_token_id: 'legacyorigin0002',
    }));
    const res = await doPost('cache-clear-groups', { group_ids: ['legacy:legacyorigin0002'] });
    expect(res.json).toEqual({ cleared: 2, groups: 1 });
    expect(await inDO(h => present(h, target))).toBe(0);
  });

  it('clears by origin past the cap too (the audit tab per-row revoke)', async () => {
    await inDO(seedPastTheCap);
    const target = await inDO(h => putAt(h, 'z', 3, { origin_token_id: 'rowremove0000001' }));

    const res = await doPost('cache-clear-origin', { token_id: 'rowremove0000001' });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ cleared: 3 });
    expect(await inDO(h => present(h, target))).toBe(0);
  }, 120_000);

  it('clear-all removes everything, including past the cap', async () => {
    await inDO(seedPastTheCap);
    await inDO(h => putAt(h, 'z', 5, { cache_group_id: 'g_tailgroup00000' }));

    const res = await doPost('clear-cache', {});
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ cleared: SCAN_MAX + 5 });
    expect(await inDO(allDekKeys)).toEqual([]);
  }, 120_000);
});
