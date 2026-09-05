// Fault-injection regressions for the authority/effect boundary. Spies are
// installed inside the DO context and restored before isolated-storage cleanup.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import nacl from 'tweetnacl';
import { b64uEnc } from '../src/crypto';
import { seal, cachePublicKey } from '../src/cache_crypto';
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
          ? vi.spyOn(inst, 'deleteKeysBatched').mockRejectedValue(new Error('injected cleanup failure'))
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
        } finally {
          openSpy.mockRestore();
          cleanup?.mockRestore();
          sealing?.mockRestore();
        }
      });
    },
  );
});

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
