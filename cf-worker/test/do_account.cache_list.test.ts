// AccountDO — the admin cache inventory (opCacheList).
//
// "Cache listings must never expose sealed material, salts, or the binding ctx
// digest (ctx + a known IP is an offline oracle for the client-reported `pwd`),
// and must report `truncated` rather than silently showing a partial view."
// (CLAUDE.md) The listing is also where the UI learns whether a row may be
// extended, so the reason projection is pinned here too.

import { describe, it, expect, beforeEach } from 'vitest';
import type { CacheEntry, CacheListResponse } from '../src/types';
import { extendTtlOptions } from '../src/cache_policy';
import {
  inDO, seedGroup, setDoVar, doGet, doPost, makeEntry, makeMeta, FAKE_CTX, nextSalt,
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
      h.inst.auditCreate({
        approve_token: originToken,
        created_ms: Date.now(),
        salts_b64u: ['s'],
        meta: makeMeta({ host: 'listbox', user: 'lister', pwd: '/srv/app' }),
      });
      h.inst.auditFinalize(originToken, 'approved', 1234);
      h.inst.auditSetCacheTtl(originToken, 20 * 60, Date.now() + 20 * MIN);
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

  // BUG: opCacheClearGroups shares scanCacheGroups' CACHE_LIST_SCAN_MAX (20000
  // entries) cap but, unlike opCacheList, never surfaces `truncated`. A group
  // that sorts past the cap is therefore NOT cleared, and the route answers
  // `200 {"cleared":0,"groups":0}` — the admin tab reports a successful clear
  // and reloads, while the DEKs stay decryptable without a phone tap. This is a
  // silent PARTIAL REVOCATION on the one authority-reducing path the operator is
  // told to reach for; 清除全部 (opClearCache) and the audit tab's per-row clear
  // (opCacheClearByOrigin) both use an uncapped list() and still work.
  //
  // Left skipped and unfixed on purpose — reported, not patched. Un-skip once
  // the clear path either pages to completion or reports its truncation.
  it.skip('BUG: bulk clear silently skips a group that sorts past the scan cap', async () => {
    const SCAN_MAX = 20000;
    await inDO(async h => {
      const filler = makeEntry({ expires_ms: Date.now() + HOUR, cache_group_id: 'g_bulkfiller0000' });
      for (let i = 0; i < SCAN_MAX; i += 128) {
        const batch: Record<string, CacheEntry> = {};
        for (let j = 0; j < 128 && i + j < SCAN_MAX; j++) {
          // '0…' sorts before the b64u salts below, so the target group is the
          // part of the prefix the scan never reaches.
          batch[`dek:${FAKE_CTX}:0${String(i + j).padStart(8, '0')}`] = filler;
        }
        await h.state.storage.put(batch);
      }
    });
    const target = await inDO(h => seedGroup(h, 3, {
      expires_ms: Date.now() + HOUR, cache_group_id: 'g_targetgroup000',
    }));

    const res = await doPost('cache-clear-groups', { group_ids: ['g_targetgroup000'] });
    expect(res.status).toBe(200);
    // Observed: {"cleared":0,"groups":0} — a success the caller cannot tell from
    // a real one, with all three entries still live.
    const left = await inDO(async h => {
      let n = 0;
      for (const k of target) if (await h.state.storage.get(k)) n++;
      return n;
    });
    expect(left).toBe(0);
  }, 120_000);
});
