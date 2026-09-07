// Fault-injection regressions for the authority/effect boundary. Spies are
// installed inside the DO context and restored before isolated-storage cleanup.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import nacl from 'tweetnacl';
import { b64uEnc } from '../src/crypto';
import { seal, cachePublicKey } from '../src/cache_crypto';
import { deleteKeysBatched } from '../src/storage_batch';
import {
  inDO, setDoVar, makeChallenge, makeMeta, signApproval, seedGroup,
  readEntries, auditRows, nextSalt, sealFakeDek, testEnv,
} from './do_helpers';
import type { Challenge, CacheExtendIntent } from '../src/types';

const TTL_MS = 5 * 60_000;
const GROUP = 'g_testgroup00000';

beforeEach(async () => {
  await setDoVar('CACHE_SECKEY', testEnv.CACHE_SECKEY);
  await setDoVar('CACHE_ADMIN_EXTEND', '1');
});

it('expires a still-pending challenge when valid verification crosses its TTL', async () => {
  const ch = makeChallenge();
  const assertion = await signApproval(ch.approve_challenge_hash_b64u);
  await inDO(async ({ inst, state }) => {
    const start = Date.now();
    ch.created_ms = start - TTL_MS + 1;
    await state.storage.put(`ch:${ch.approve_token}`, ch);
    await state.storage.put(`pt:${ch.poll_token}`, ch.approve_token);
    inst.audit.create(ch);
    const clock = vi.spyOn(Date, 'now').mockReturnValue(start);
    const verify = crypto.subtle.verify.bind(crypto.subtle);
    const verification = vi.spyOn(crypto.subtle, 'verify').mockImplementation(async (...args) => {
      const valid = await verify(...args);
      expect(valid).toBe(true);
      clock.mockReturnValue(start + 1);
      return valid;
    });
    try {
      const response = await inst.fetch(new Request('https://account.do/op/approve', {
        method: 'POST', body: JSON.stringify({
          approve_token: ch.approve_token,
          sealed_deks_b64u: b64uEnc(new Uint8Array(48).fill(5)),
          binding_tag_b64u: b64uEnc(new Uint8Array(32).fill(6)),
          ...assertion,
        }),
      }));
      const text = await response.text();
      expect(verification).toHaveBeenCalledOnce();
      expect(response.status).toBe(410);
      expect(text).toBe('challenge expired');
      const stored = (await state.storage.get<Challenge>(`ch:${ch.approve_token}`))!;
      expect(stored.status).toBe('expired');
      expect(stored.sealed_deks_b64u).toBeUndefined();
      expect(await state.storage.get(`pt:${ch.poll_token}`)).toBeUndefined();
      expect((await auditRows({ inst, state }))[0]!.status).toBe('expired');
    } finally {
      verification.mockRestore();
      clock.mockRestore();
    }
  });
});

describe('shared storage deletion', () => {
  it('does not call storage for an empty key set', async () => {
    const storage = { delete: vi.fn() };
    expect(await deleteKeysBatched(storage, [])).toBe(0);
    expect(storage.delete).not.toHaveBeenCalled();
  });

  it('chunks at 128 keys and sums actual deletion counts', async () => {
    const keys = Array.from({ length: 257 }, (_, i) => `key:${i}`);
    const storage = { delete: vi.fn().mockResolvedValueOnce(100).mockResolvedValueOnce(127).mockResolvedValueOnce(0) };
    expect(await deleteKeysBatched(storage, keys)).toBe(227);
    expect(storage.delete.mock.calls).toEqual([
      [keys.slice(0, 128)], [keys.slice(128, 256)], [keys.slice(256)],
    ]);
  });

  it('rejects a partial failure without attempting later batches', async () => {
    const keys = Array.from({ length: 257 }, (_, i) => `key:${i}`);
    const storage = { delete: vi.fn().mockResolvedValueOnce(128).mockRejectedValueOnce(new Error('injected delete failure')) };
    await expect(deleteKeysBatched(storage, keys)).rejects.toThrow('injected delete failure');
    expect(storage.delete.mock.calls).toEqual([ [keys.slice(0, 128)], [keys.slice(128, 256)] ]);
  });
});

describe('challenge alarm sweep', () => {
  it('streams full and short pages through an empty page, deleting routing keys in bounded batches', async () => {
    await inDO(async ({ inst, state }) => {
      const now = Date.now();
      let batch: Record<string, Challenge | string> = {};
      for (let i = 0; i < 1100; i++) {
        const ch = makeChallenge({ status: 'approved', finalized_ms: now - 2 * TTL_MS - 1000 });
        batch[`ch:${ch.approve_token}`] = ch;
        batch[`pt:${ch.poll_token}`] = ch.approve_token;
        if (Object.keys(batch).length === 128) {
          await state.storage.put(batch);
          batch = {};
        }
      }
      if (Object.keys(batch).length) await state.storage.put(batch);
      const pending = makeChallenge();
      const recent = makeChallenge({ status: 'rejected', finalized_ms: now });
      const expired = makeChallenge({ created_ms: now - TTL_MS - 1000 });
      for (const ch of [pending, recent, expired]) {
        await state.storage.put({
          [`ch:${ch.approve_token}`]: ch, [`pt:${ch.poll_token}`]: ch.approve_token,
        });
      }
      inst.audit.create(expired);
      const list = state.storage.list.bind(state.storage);
      const del = state.storage.delete.bind(state.storage);
      const pages: string[][] = [];
      const lists = vi.spyOn(state.storage, 'list').mockImplementation(async (options) => {
        if (options?.prefix !== 'ch:') return list(options);
        expect(options.limit).toBe(1000);
        expect(options.startAfter).toBe(pages.at(-1)?.at(-1));
        // A later page must not be fetched before the preceding page is cleaned.
        if (pages.length && pages.length <= 2) {
          expect(await state.storage.get(pages.at(-1)![0]!)).toBeUndefined();
        }
        const page = await list({ ...options, limit: pages.length === 0 ? 65 : options.limit });
        pages.push([...page.keys()]);
        return page;
      });
      const deletes = vi.spyOn(state.storage, 'delete').mockImplementation((keys: any) => {
        if (Array.isArray(keys)) expect(keys.length).toBeLessThanOrEqual(128);
        return del(keys);
      });
      const channels = vi.spyOn(inst.notifications, 'channels');
      try {
        await inst.alarm();
        expect(pages.map(page => page.length)).toEqual([65, 1000, 38, 0]);
        expect(channels).toHaveBeenCalledOnce();
        expect([...await list({ prefix: 'ch:' })].map(([key]) => key)).toEqual(
          [pending, recent, expired].map(ch => `ch:${ch.approve_token}`),
        );
        expect([...await list({ prefix: 'pt:' })].map(([key]) => key)).toEqual(
          [pending, recent].map(ch => `pt:${ch.poll_token}`),
        );
        expect(await state.storage.get(`ch:${pending.approve_token}`)).toEqual(pending);
        expect(await state.storage.get(`ch:${recent.approve_token}`)).toEqual(recent);
        expect(await state.storage.get(`ch:${expired.approve_token}`)).toMatchObject({ status: 'expired' });
        expect((await auditRows({ inst, state }))[0]!.status).toBe('expired');
        const batches = deletes.mock.calls.map(([keys]) => keys).filter(Array.isArray);
        expect(Math.max(...batches.map(keys => keys.length))).toBe(128);
        expect(batches.reduce((total, keys) => total + keys.length, 0)).toBe(2200);
        expect(await state.storage.getAlarm()).toBeGreaterThanOrEqual(now + TTL_MS);
      } finally {
        lists.mockRestore();
        deletes.mockRestore();
        channels.mockRestore();
      }
    });
  });

  it('freshly rereads each pending challenge and preserves an approval committed after listing', async () => {
    await inDO(async ({ inst, state }) => {
      const now = Date.now();
      const expired = makeChallenge({ created_ms: now - TTL_MS - 1000 });
      const stale = makeChallenge({ created_ms: expired.created_ms });
      const approved: Challenge = {
        ...stale, status: 'approved', finalized_ms: now,
        sealed_deks_b64u: b64uEnc(new Uint8Array(48).fill(5)),
      };
      for (const ch of [expired, stale]) {
        await state.storage.put({
          [`ch:${ch.approve_token}`]: ch, [`pt:${ch.poll_token}`]: ch.approve_token,
        });
        inst.audit.create(ch);
      }
      const list = state.storage.list.bind(state.storage);
      const lists = vi.spyOn(state.storage, 'list').mockImplementation(async (options) => {
        const page = await list(options);
        if (options?.prefix === 'ch:' && !options.startAfter) {
          await state.storage.put(`ch:${approved.approve_token}`, approved);
          inst.audit.finalize(approved.approve_token, 'approved', now - approved.created_ms);
        }
        return page;
      });
      const edits = vi.spyOn(inst.notifications, 'edit');
      const gets = vi.spyOn(state.storage, 'get');
      try {
        await inst.alarm();
        expect(gets).toHaveBeenCalledWith(`ch:${expired.approve_token}`);
        expect(gets).toHaveBeenCalledWith(`ch:${stale.approve_token}`);
        expect(await state.storage.get(`ch:${approved.approve_token}`)).toEqual(approved);
        expect(await state.storage.get(`pt:${approved.poll_token}`)).toBe(approved.approve_token);
        expect(await state.storage.get(`pt:${expired.poll_token}`)).toBeUndefined();
        expect((await auditRows({ inst, state })).map(row => row.status)).toEqual(['expired', 'approved']);
        expect(edits).toHaveBeenCalledOnce();
        expect(edits.mock.calls[0]![0]).toMatchObject({ approve_token: expired.approve_token, status: 'expired' });
      } finally {
        lists.mockRestore();
        edits.mockRestore();
        gets.mockRestore();
      }
    });
  });

  it('isolates a later-page failure and still sweeps the cache, audit, sockets, and rearms the alarm', async () => {
    await inDO(async ({ inst, state }) => {
      const now = Date.now();
      const ch = makeChallenge({ status: 'rejected', finalized_ms: now - 2 * TTL_MS - 1000 });
      await state.storage.put({
        [`ch:${ch.approve_token}`]: ch, [`pt:${ch.poll_token}`]: ch.approve_token,
      });
      const keys = await seedGroup({ inst, state }, 1, { expires_ms: now - 1 });
      const list = state.storage.list.bind(state.storage);
      const lists = vi.spyOn(state.storage, 'list').mockImplementation((options) => {
        if (options?.prefix === 'ch:' && options.startAfter) {
          throw new Error('injected challenge pagination failure');
        }
        return list(options);
      });
      const audit = vi.spyOn(inst.audit, 'sweep');
      const sockets = vi.spyOn(state, 'getWebSockets');
      const alarm = vi.spyOn(state.storage, 'setAlarm');
      try {
        await expect(inst.alarm()).resolves.toBeUndefined();
        expect(lists).toHaveBeenCalledWith({ prefix: 'ch:', limit: 1000, startAfter: `ch:${ch.approve_token}` });
        expect(await state.storage.get(`ch:${ch.approve_token}`)).toBeUndefined();
        expect(await state.storage.get(`pt:${ch.poll_token}`)).toBeUndefined();
        expect(await readEntries({ inst, state }, keys)).toEqual([]);
        expect(audit).toHaveBeenCalledOnce();
        expect(sockets).toHaveBeenCalledWith('admin');
        expect(alarm).toHaveBeenCalledOnce();
        expect(await state.storage.getAlarm()).toBeGreaterThanOrEqual(now + TTL_MS);
      } finally {
        lists.mockRestore();
        audit.mockRestore();
        sockets.mockRestore();
        alarm.mockRestore();
      }
    });
  });
});

describe('cache read plaintext lifetime', () => {
  it.each(['missing', 'malformed', 'cleanup-failure', 'hit', 'seal-failure'])(
    'wipes every opened buffer on %s', async (outcome) => {
      await inDO(async ({ inst, state }) => {
        const meta = makeMeta();
        const salts = [nextSalt(), nextSalt()];
        await inst.writeCache(makeChallenge({ salts_b64u: salts, meta }), 20 * 60,
          salts.map(() => sealFakeDek()));
        const entries = await state.storage.list({ prefix: 'dek:' });
        const secondKey = [...entries.keys()].find(key => key.endsWith(`:${salts[1]}`))!;
        if (outcome === 'missing') {
          await state.storage.delete(secondKey);
        } else if (outcome === 'malformed' || outcome === 'cleanup-failure') {
          const sealed = seal(new Uint8Array(31).fill(8), cachePublicKey(testEnv.CACHE_SECKEY));
          await state.storage.put(secondKey, { ...entries.get(secondKey), sealed_to_cache_b64u: sealed });
        }
        const opened: Uint8Array[] = [];
        const open = nacl.box.open;
        const openSpy = vi.spyOn(nacl.box, 'open').mockImplementation((...args) => {
          const value = open(...args);
          if (value) opened.push(value);
          return value;
        });
        const cleanup = outcome === 'cleanup-failure'
          ? vi.spyOn(state.storage, 'delete').mockRejectedValue(new Error('injected cleanup failure'))
          : undefined;
        const sealing = outcome === 'seal-failure'
          ? vi.spyOn(nacl.box, 'keyPair').mockImplementation(() => { throw new Error('injected seal failure'); })
          : undefined;
        try {
          const request = new Request('https://account.do/op/dek-cache', {
            method: 'POST', body: JSON.stringify({
              daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)),
              salts_b64u: salts, meta,
            }),
          });
          if (outcome === 'seal-failure') {
            await expect(inst.opDekCache(request)).rejects.toThrow('injected seal failure');
          } else {
            const response = await inst.opDekCache(request);
            const body = await response.json();
            expect(response.status).toBe(200);
            expect(body).toMatchObject(outcome === 'hit' ? { source: 'cache' } : { miss: true });
          }
          expect(opened).toHaveLength(outcome === 'missing' ? 1 : 2);
          for (const value of opened) expect(value.every(byte => byte === 0)).toBe(true);
          if (cleanup) expect(cleanup).toHaveBeenCalledOnce();
        } finally {
          openSpy.mockRestore();
          cleanup?.mockRestore();
          sealing?.mockRestore();
        }
      });
    },
  );
});

it('keeps cache write, read, extension, and clear within every 128-key storage limit', async () => {
  await inDO(async ({ inst, state }) => {
    const get = state.storage.get.bind(state.storage);
    const put = state.storage.put.bind(state.storage);
    const del = state.storage.delete.bind(state.storage);
    const sizes = { get: [] as number[], put: [] as number[], delete: [] as number[] };
    const gets = vi.spyOn(state.storage, 'get').mockImplementation((keys: any) => {
      if (Array.isArray(keys)) {
        sizes.get.push(keys.length);
        expect(keys.length).toBeLessThanOrEqual(128);
      }
      return get(keys);
    });
    const puts = vi.spyOn(state.storage, 'put').mockImplementation((key: any, value?: any) => {
      if (typeof key === 'string') return put(key, value);
      sizes.put.push(Object.keys(key).length);
      expect(Object.keys(key).length).toBeLessThanOrEqual(128);
      return put(key);
    });
    const deletes = vi.spyOn(state.storage, 'delete').mockImplementation((keys: any) => {
      if (Array.isArray(keys)) {
        sizes.delete.push(keys.length);
        expect(keys.length).toBeLessThanOrEqual(128);
      }
      return del(keys);
    });
    const post = async (op: string, body: unknown) => {
      const response = await inst.fetch(new Request(`https://account.do/op/${op}`, {
        method: 'POST', body: JSON.stringify(body),
      }));
      const text = await response.text();
      expect(response.status).toBe(200);
      return text === 'ok' ? {} : JSON.parse(text);
    };
    const approve = async (ch: Challenge, extra = {}) => post('approve', {
      approve_token: ch.approve_token,
      sealed_deks_b64u: b64uEnc(new Uint8Array(48).fill(5)),
      binding_tag_b64u: b64uEnc(new Uint8Array(32).fill(6)),
      ...await signApproval(ch.approve_challenge_hash_b64u), ...extra,
    });
    try {
      const salts = Array.from({ length: 150 }, nextSalt);
      const ch = makeChallenge({ salts_b64u: salts });
      await post('create', { challenge: ch });
      await approve(ch, { cache_ttl_s: 1200, cache_sealed_deks_b64u: salts.map(() => sealFakeDek()) });
      expect(sizes.put).toEqual([2, 128, 22]);
      const read = await post('dek-cache', {
        daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)), salts_b64u: salts, meta: ch.meta,
      });
      expect(read.source).toBe('cache');
      expect(sizes.get).toEqual([128, 22]);
      const listing = await post('cache-list', {});
      const pending = await post('cache-extend-create', {
        group_ids: [listing.groups[0].group_id], ttl_s: 86400,
      });
      const extension = (await state.storage.get<Challenge>(`ch:${pending.approve_token}`))!;
      await approve(extension);
      expect(sizes.get).toEqual([128, 22, 128, 22]);
      expect(sizes.put).toEqual([2, 128, 22, 2, 128, 22]);
      expect(await post('clear-cache', {})).toEqual({ cleared: 150 });
      expect(sizes.delete).toEqual([128, 22]);
    } finally {
      gets.mockRestore();
      puts.mockRestore();
      deletes.mockRestore();
    }
  });
}, 60_000);

describe('extension storage failures', () => {
  it.each([1, 2])('counts only successful batches when put #%i fails', async (failedBatch) => {
    await inDO(async ({ inst, state }) => {
      const expiry = Date.now() + 60_000;
      const origin = makeChallenge();
      inst.audit.create(origin);
      inst.audit.setCacheTtl(origin.approve_token, 20 * 60, expiry);
      const keys = await seedGroup({ inst, state }, 150, {
        origin_token_id: origin.approve_token, expires_ms: expiry,
      });
      const intent: CacheExtendIntent = {
        group_ids: [GROUP], ttl_s: 24 * 3600, requested_by: 'admin@example.invalid', preview: [],
      };
      const ch = makeChallenge({ status: 'approved', extend: intent });
      const put = state.storage.put.bind(state.storage);
      const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now());
      let attempts = 0;
      const writes = vi.spyOn(state.storage, 'put').mockImplementation(async (entries) => {
        attempts++;
        // Move time between batches so a failed batch also cannot inflate the
        // projected expiry on the original approval's audit row.
        clock.mockReturnValue(Date.now() + 10);
        if (attempts === failedBatch) throw new Error('injected storage failure');
        await put(entries);
      });
      try {
        await inst.commitExtend(ch, intent);
      } finally {
        writes.mockRestore();
        clock.mockRestore();
      }
      const entries = await readEntries({ inst, state }, keys);
      const changed = entries.filter(entry => entry.expires_ms !== expiry);
      expect(changed).toHaveLength(failedBatch === 1 ? 0 : 128);
      const rows = await auditRows({ inst, state });
      const effect = rows.find(row => row.status === 'extended')!;
      expect(effect.reason).toMatch(new RegExp(`^${changed.length} `));
      expect(effect.reason).toContain('error=1');
      const original = rows.find(row => row.token_id === origin.approve_token)!;
      expect(original.cache_ttl_s).toBe(20 * 60);
      expect(original.cache_expires_ms).toBe(
        changed.length ? Math.max(...changed.map(entry => entry.expires_ms)) : expiry,
      );
    });
  });
});
