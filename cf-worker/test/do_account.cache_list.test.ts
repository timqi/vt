// AccountDO — the admin cache inventory (opCacheList) and the clear paths.
//
// "Cache listings must never expose sealed material or the binding ctx digest
// (ctx + a known project is an offline oracle for the client-reported path),
// and must report `truncated` rather than silently showing a partial view."
// (AGENTS.md) A record's salt — public in its vt:// URL — is the entry's
// address beside its literal token_id and project, never beside the hash.
// Expired entries are not the console's to see: the listing filters them.
//
// The listing may be partial as long as it SAYS so. A clear may not: see the
// second half of this file.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SELF } from 'cloudflare:test';
import type { CacheEntry, CacheListResponse } from '../src/types';
import { extendTtlOptions } from '../src/cache_policy';
import {
  inDO, seedEntries, doGet, doPost, makeEntry, makeMeta, FAKE_CTX, TEST_TOKEN_ID, TEST_PROJECT, TEST_ORIGIN,
  testCtx, refOf, nextSalt, bootstrap, adminHeaders, allDekKeys, DoHandle,
} from './do_helpers';

const MIN = 60_000;
const HOUR = 60 * MIN;

beforeEach(bootstrap);

async function list(): Promise<{ body: CacheListResponse; text: string }> {
  const res = await doGet('cache-list');
  expect(res.status).toBe(200);
  return { body: res.json as CacheListResponse, text: res.text };
}

describe('opCacheList — inventory without secrets', () => {
  it('lists one row per entry and leaks no sealed blob, storage key, or binding ctx', async () => {
    const keys = await inDO(h => seedEntries(h, 3, { expires_ms: Date.now() + HOUR }));
    const sealed = await inDO(async h =>
      (await h.state.storage.get<CacheEntry>(keys[0]!))!.sealed_to_cache_b64u);

    const { body, text } = await list();
    expect(body.entries).toHaveLength(3);
    const e = body.entries[0]!;
    expect(e.token_id).toBe(TEST_TOKEN_ID);
    expect(e.project).toBe(TEST_PROJECT);
    expect(e.host).toBe('testbox');
    expect(e.user).toBe('tester');
    expect(e.ip).toBe('203.0.113.9');
    expect(e.ttl_s).toBe(20 * 60);
    expect(e.origin_token_id).toBe('origin0000000000');

    // Nothing that could rebuild a key or an offline oracle: the salt appears
    // as the address and the rename key, never with its project hash.
    const ctx = await testCtx();
    expect(text).not.toContain(sealed);
    expect(text).not.toContain(ctx.split(':')[1]);
    for (const k of keys) expect(text).not.toContain(k);
    expect(text).not.toContain('sealed');
    expect(JSON.stringify(Object.keys(e))).not.toMatch(/sealed|ctx|key/i);
    expect(body.entries.map(r => r.salt_b64u).sort()).toEqual(keys.map(k => k.split(':')[3]!).sort());
    expect(body.entries.every(r => r.record.salt_b64u === r.salt_b64u && r.record.name === null)).toBe(true);
  });

  it('shows the operator name, else the claim, on each entry', async () => {
    const keys = await inDO(h => seedEntries(h, 1, { expires_ms: Date.now() + HOUR, name: 'GH_TOKEN' }));
    const salt = refOf(keys[0]!).salt_b64u;
    expect((await list()).body.entries[0]!.record).toMatchObject({ name: null, claimed: 'GH_TOKEN' });
    expect((await doPost('names-set', { salt_b64u: salt, name: 'github' })).status).toBe(200);
    expect((await list()).body.entries[0]!.record).toMatchObject({ name: 'github', claimed: 'GH_TOKEN' });
  });

  it('offers the extension ladder straight from policy', async () => {
    await inDO(h => seedEntries(h, 1, { expires_ms: Date.now() + HOUR }));
    const { body } = await list();
    expect(body.ttl_options_s).toEqual(extendTtlOptions());
  });

  it('never shows an expired entry, even before the sweep', async () => {
    const now = Date.now();
    await inDO(h => seedEntries(h, 2, { expires_ms: now - MIN }));
    const live = await inDO(h => seedEntries(h, 1, { expires_ms: now + HOUR }));
    const { body } = await list();
    expect(body.entries.map(e => e.salt_b64u)).toEqual([refOf(live[0]!).salt_b64u]);
    expect(body.scanned).toBe(3);
  });

  it('lists a v4-shaped entry (no token half) by its literal fields only', async () => {
    await inDO(async h => h.state.storage.put(`dek:${FAKE_CTX}:${nextSalt()}`,
      await makeEntry({ expires_ms: Date.now() + HOUR, host: undefined, project: undefined })));
    const e = (await list()).body.entries[0]!;
    expect(e.host).toBe('');
    expect(e.project).toBe('');
  });

  it('says `truncated` instead of passing a partial scan off as complete', async () => {
    // CACHE_LIST_SCAN_MAX is 20000 entries per listing.
    const SCAN_MAX = 20000;
    await inDO(async h => {
      const entry = await makeEntry({ expires_ms: Date.now() + HOUR });
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
    await inDO(h => seedEntries(h, 5, { expires_ms: Date.now() + HOUR }));
    const { body } = await list();
    expect(body.truncated).toBe(false);
    expect(body.scanned).toBe(5);
  });
});

// ── The revoke paths ───────────────────────────────────────────────────────
//
// A clear is the authority-REDUCING half of the admin surface. The contract:
// the count a clear returns is what storage actually removed — never what the
// request intended. cache-clear-entries addresses exact keys (no scan, so no
// cap to fall past); 清除全部 pages the `dek:` prefix to its end.

/** Write `n` entries at fully controlled keys, so a test can decide exactly
 *  where they land in the sorted `dek:` prefix. '0…' sorts before every
 *  base64url salt; 'z…' sorts after all of them. */
async function putAt(
  h: DoHandle, prefix: string, n: number, over: Partial<CacheEntry> = {},
): Promise<string[]> {
  const entry = await makeEntry({ expires_ms: Date.now() + HOUR, ...over });
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
  return putAt(h, '0', SCAN_MAX, { origin_token_id: 'fillerorigin0001' });
}

describe('cache-clear-entries — exact keys', () => {
  it('clears the named entries and only those, across delete batches', async () => {
    // DO storage takes at most 128 keys per delete(); 300 needs three calls, and
    // an unchunked array would throw and remove nothing.
    const target = await inDO(h => seedEntries(h, 300, { expires_ms: Date.now() + HOUR }));
    const keep = await inDO(h => seedEntries(h, 4, { expires_ms: Date.now() + HOUR }));
    const sizes = await inDO(async h => {
      const del = h.state.storage.delete.bind(h.state.storage);
      const seen: number[] = [];
      const spy = vi.spyOn(h.state.storage, 'delete').mockImplementation((keys: any) => { seen.push(keys.length); return del(keys); });
      try {
        const res = await h.inst.fetch(new Request('https://account.do/op/cache-clear-entries', {
          method: 'POST', headers: adminHeaders(), body: JSON.stringify({ entries: target.map(k => refOf(k)) }),
        }));
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ cleared: 300 });
      } finally { spy.mockRestore(); }
      return seen;
    });
    expect(sizes).toEqual([128, 128, 44]);
    expect(await inDO(h => present(h, target))).toBe(0);
    expect(await inDO(h => present(h, keep))).toBe(4);
  });

  it('reports only what it actually removed', async () => {
    const keep = await inDO(h => seedEntries(h, 2, { expires_ms: Date.now() + HOUR }));
    const res = await doPost('cache-clear-entries', { entries: [{ ...refOf(keep[0]!), salt_b64u: nextSalt() }] });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ cleared: 0 });
    expect(await inDO(h => present(h, keep))).toBe(2);
  });

  it('refuses a malformed, empty or oversize address list', async () => {
    const ref = refOf((await inDO(h => seedEntries(h, 1)))[0]!);
    for (const entries of [
      undefined, [], 'x', [{ ...ref, token_id: 'not-a-token' }], [{ ...ref, salt_b64u: 'short' }],
      [{ ...ref, project: 'p'.repeat(5000) }], Array.from({ length: 513 }, () => ref),
    ]) {
      expect((await doPost('cache-clear-entries', { entries })).status).toBe(400);
    }
    // A v4-shaped key has no token half, so the console cannot address it; it
    // is cleared by 清除全部 or lapses.
    expect((await doPost('cache-clear-entries', { entries: [{ ...ref, token_id: FAKE_CTX }] })).status).toBe(400);
  });
});

describe('清除全部 — exhaustive by contract', () => {
  it('continues across short nonempty pages', async () => {
    await inDO(async h => {
      const target = await putAt(h, 'z', 7);
      const list = h.state.storage.list.bind(h.state.storage);
      const pages = vi.spyOn(h.state.storage, 'list').mockImplementation((options: any) =>
        list(options?.prefix === 'dek:' ? { ...options, limit: 2 } : options));
      try {
        const response = await h.inst.fetch(new Request('https://account.do/op/clear-cache', {
          method: 'POST', headers: adminHeaders(),
        }));
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({ cleared: 7 });
        expect(pages).toHaveBeenCalledTimes(5);
      } finally {
        pages.mockRestore();
      }
      expect(await present(h, target)).toBe(0);
    });
  });

  it('fails loudly after a partially completed clear', async () => {
    await inDO(async h => {
      const keys = await putAt(h, 'z', 300);
      const del = h.state.storage.delete.bind(h.state.storage);
      let attempts = 0;
      const deletes = vi.spyOn(h.state.storage, 'delete').mockImplementation((keys: any) => {
        if (++attempts === 2) return Promise.reject(new Error('synthetic clear failure'));
        return del(keys);
      });
      try {
        await expect(h.inst.fetch(new Request('https://account.do/op/clear-cache', {
          method: 'POST', headers: adminHeaders(),
        }))).rejects.toThrow('synthetic clear failure');
      } finally {
        deletes.mockRestore();
      }
      expect(await present(h, keys)).toBe(172);
    });
  });

  it('removes everything, including past the listing cap', async () => {
    await inDO(seedPastTheCap);
    await inDO(h => putAt(h, 'z', 5));

    const res = await doPost('clear-cache', {});
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ cleared: SCAN_MAX + 5 });
    expect(await inDO(allDekKeys)).toEqual([]);
  }, 120_000);

  it('removes a malformed value under the prefix: the key is the unit, not its shape', async () => {
    await inDO(async h => {
      await putAt(h, 'z', 2);
      await h.state.storage.put({
        'dek:zz:junk:string': 'not an entry',
        'dek:zz:junk:null': null,
        'dek:zz:junk:number': 7,
        'dek:zz:junk:object': { unrelated: true },
      });
    });
    expect(await inDO(allDekKeys)).toHaveLength(6);

    const res = await doPost('clear-cache', {});
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ cleared: 6 });
    expect(await inDO(allDekKeys)).toEqual([]);
  });

  it('the expiry sweep drops a value with no numeric expires_ms and keeps the live one', async () => {
    await inDO(async h => {
      await putAt(h, 'z', 1);
      await h.state.storage.put({ 'dek:zz:junk:string': 'not an entry', 'dek:zz:junk:object': { unrelated: true } });
      expect(await h.inst.cache.sweepExpired(Date.now())).toEqual({ deleted: 2, scanned: 3 });
      expect(await allDekKeys(h)).toHaveLength(1);
    });
  });
});

// Removed surfaces (docs/refactor.md rule: a migration's test becomes a
// rejected-input test): the per-approval and per-group clears, and the audit
// wipe. Retention is the only deletion the audit table knows.
describe('removed clear ops are unknown', () => {
  it.each(['cache-clear-origin', 'cache-clear-groups', 'clear-audit'])('DO op %s → 400', async (op) => {
    await inDO(h => seedEntries(h, 1, { expires_ms: Date.now() + HOUR }));
    const res = await doPost(op, { token_id: 'origin0000000000', group_ids: ['g_x'] });
    expect(res.status).toBe(400);
    expect(res.text).toBe('unknown op');
    expect(await inDO(allDekKeys)).toHaveLength(1);
  });

  it.each(['cache-clear-origin', 'cache-clear-groups', 'clear-audit'])('edge route /api/admin/%s → 404', async (route) => {
    await inDO(h => { h.inst.audit.create({ approve_token: 'keeprow000000001', created_ms: Date.now(), salts_b64u: [], meta: makeMeta() }); });
    const resp = await SELF.fetch(`${TEST_ORIGIN}/api/admin/${route}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...adminHeaders() }, body: '{}',
    });
    await resp.text();
    expect(resp.status).toBe(404);
    expect((await doGet('audit-query')).json.rows).toHaveLength(1);
  });
});
