// AccountDO — the cache-extension ceremony.
//
// Every assertion here is quoted from CLAUDE.md / docs/dek-cache.md: the extend
// route only MINTS a ceremony, `expires_ms` moves solely in commitExtend (called
// from opApprove after a verified assertion), extension is measured from the
// approval with no lifetime ceiling, and it can neither resurrect a lapsed entry
// nor shorten a live one. A failure here is a real regression, not a stale test.

import { describe, it, expect, beforeEach } from 'vitest';
import { SELF } from 'cloudflare:test';
import type { CacheEntry, Challenge } from '../src/types';
import {
  inDO, seedGroup, readEntries, setDoVar, doPost, approve, makeMeta, sealFakeDek,
  auditRows, DoHandle, DoResult,
} from './do_helpers';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

const GROUP = 'g_testgroup00000';
const TTL_20M = 20 * 60;
const TTL_1D = 24 * 3600;
const TTL_2D = 2 * 24 * 3600;
const TTL_1W = 7 * 24 * 3600;
const TTL_PERMANENT = 100 * 365 * 24 * 3600;

// The kill switch is a per-instance env read and the DO instance outlives a
// single test, so put it back to its wrangler.test.toml default every time.
beforeEach(async () => { await setDoVar('CACHE_ADMIN_EXTEND', '0'); });

function requestExtend(groupIds: string[], ttlS: number): Promise<DoResult> {
  return doPost('cache-extend-create', {
    group_ids: groupIds,
    ttl_s: ttlS,
    admin_email: 'admin@example.invalid',
    admin_ip: '198.51.100.7',
  });
}

/** The pending ceremony a request minted, read straight out of DO storage. */
async function storedChallenge(h: DoHandle, token: string): Promise<Challenge> {
  const ch = await h.state.storage.get<Challenge>(`ch:${token}`);
  expect(ch).toBeTruthy();
  return ch!;
}

/** Seed one live group and mint a pending extension ceremony for it. */
async function armCeremony(opts: {
  entries?: number;
  leftMs?: number;
  ttlS?: number;
  over?: Partial<CacheEntry>;
  groupId?: string;
} = {}) {
  const { entries = 2, leftMs = HOUR, ttlS = TTL_1D, over = {} } = opts;
  await setDoVar('CACHE_ADMIN_EXTEND', '1');
  const keys = await inDO(h => seedGroup(h, entries, {
    expires_ms: Date.now() + leftMs, ...over,
  }));
  const res = await requestExtend([opts.groupId ?? GROUP], ttlS);
  expect(res.status).toBe(200);
  const ch = await inDO(h => storedChallenge(h, res.json.approve_token));
  return { keys, ch, res };
}

/** Overwrite one field on every entry of a seeded group — how a test simulates
 *  the world changing between the request and the tap. */
async function mutateEntries(keys: string[], patch: Partial<CacheEntry>): Promise<void> {
  await inDO(async h => {
    for (const k of keys) {
      const e = (await h.state.storage.get<CacheEntry>(k))!;
      await h.state.storage.put(k, { ...e, ...patch });
    }
  });
}

// ── The request route mints a ceremony and moves nothing ───────────────────

describe('opCacheExtendCreate — request only, no mutation', () => {
  it('mints a pending ceremony carrying an immutable intent, and moves no expiry', async () => {
    const before = Date.now();
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1D });

    // Nothing moved: the route grants authority only once a Passkey signs.
    const entries = await inDO(h => readEntries(h, keys));
    expect(entries).toHaveLength(2);
    for (const e of entries) expect(e.expires_ms).toBeLessThan(before + 2 * HOUR);

    expect(ch.status).toBe('pending');
    expect(ch.meta.op_kind).toBe('cache-extend');
    expect(ch.salts_b64u).toEqual([]);            // an extension mints no DEKs
    expect(ch.extend).toBeTruthy();
    expect(ch.extend!.ttl_s).toBe(TTL_1D);
    expect(ch.extend!.group_ids).toEqual([GROUP]);
    expect(ch.extend!.requested_by).toBe('admin@example.invalid');
  });

  it('is unreachable while CACHE_ADMIN_EXTEND is off — a kill switch, not an authorization', async () => {
    const keys = await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR }));
    const res = await requestExtend([GROUP], TTL_1D);
    expect(res.status).toBe(404);
    expect(res.text).toMatch(/disabled/);
    // And no ceremony was minted, so nothing is even approvable.
    const chs = await inDO(async h => [...(await h.state.storage.list({ prefix: 'ch:' })).keys()]);
    expect(chs).toEqual([]);
    const [e] = await inDO(h => readEntries(h, keys));
    expect(e!.expires_ms).toBeLessThan(Date.now() + 2 * HOUR);
  });

  it('refuses a TTL that is not an extend-ladder rung', async () => {
    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR }));
    for (const bad of [3 * 3600, 3 * 24 * 3600, 30 * 24 * 3600, 0, -TTL_1D]) {
      const res = await requestExtend([GROUP], bad);
      expect(res.status).toBe(400);
      expect(res.text).toMatch(/whitelisted/);
    }
  });

  it('accepts the extend-only rungs a phone approval may never arm', async () => {
    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR }));
    for (const rung of [TTL_1D, TTL_2D, TTL_1W, TTL_PERMANENT]) {
      const res = await requestExtend([GROUP], rung);
      expect(res.status).toBe(200);
      expect(res.json.targets).toHaveLength(1);
    }
  });

  it('refuses a lapsed group outright — only a fresh approval arms a new cache', async () => {
    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    await inDO(h => seedGroup(h, 2, { expires_ms: Date.now() - MIN }));
    const res = await requestExtend([GROUP], TTL_1W);
    expect(res.status).toBe(409);
    expect(res.json.error).toBe('no_extendable_targets');
    expect(res.json.rejected.map((r: { reason: string }) => r.reason)).toContain('expired');
  });

  it('refuses a request that would not move expiry forward (no_gain)', async () => {
    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + 3 * DAY }));
    const res = await requestExtend([GROUP], TTL_20M);
    expect(res.status).toBe(409);
    expect(res.json.rejected.map((r: { reason: string }) => r.reason)).toContain('no_gain');
  });

  it('is not reachable over HTTP without a Cloudflare Access session', async () => {
    // The Worker route in front of this op (ADMIN_SEG is the fixed 'kestrel'
    // segment in src/index.ts). wrangler.test.toml leaves ACCESS_TEAM_DOMAIN and
    // ACCESS_AUD empty, so the gate fails closed — Access is necessary for the
    // request, and (per the ceremony tests below) still not sufficient for the
    // effect.
    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    const keys = await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR }));
    const resp = await SELF.fetch('https://vt.test.invalid/kestrel/api/cache-extend-request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ group_ids: [GROUP], ttl_s: TTL_1W }),
    });
    expect(resp.status).toBe(403);
    expect(await resp.text()).toBe('forbidden');

    const chs = await inDO(async h => [...(await h.state.storage.list({ prefix: 'ch:' })).keys()]);
    expect(chs).toEqual([]);
    const [e] = await inDO(h => readEntries(h, keys));
    expect(e!.expires_ms).toBeLessThan(Date.now() + 2 * HOUR);
  });

  it('refuses a drifted group rather than guessing which record was meant', async () => {
    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    // Same group handle, disagreeing IPs — something wrote across a group boundary.
    await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR, ip: '203.0.113.9' }));
    await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR, ip: '198.51.100.4' }));
    const res = await requestExtend([GROUP], TTL_1W);
    expect(res.status).toBe(409);
    expect(res.json.rejected.map((r: { reason: string }) => r.reason)).toContain('inconsistent');
  });
});

// ── expires_ms moves only after a verified assertion ───────────────────────

describe('opApprove → commitExtend — the only path that moves expires_ms', () => {
  it('moves expiry to now + ttl on a verified assertion', async () => {
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1D });
    expect((await approve(ch)).status).toBe(200);

    const after = Date.now();
    const entries = await inDO(h => readEntries(h, keys));
    for (const e of entries) {
      // Measured from the APPROVAL: now + ttl, not created + ttl, and not
      // additive with the hour that was left.
      expect(Math.abs(e.expires_ms - (after + TTL_1D * 1000))).toBeLessThan(10_000);
    }
  });

  it('moves nothing when the assertion does not verify', async () => {
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1W });
    const before = await inDO(h => readEntries(h, keys));

    // Sanity: the helper really does drive the live op.
    expect((await approve({ ...ch, approve_token: 'absenttoken00000' })).status).toBe(404);

    // A tampered signature; everything else about the body is well-formed.
    const res = await approve(ch, { signature_b64u: 'MEUCIQDaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAIgWbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA' });
    expect(res.status).toBe(401);
    const after = await inDO(h => readEntries(h, keys));
    expect(after.map(e => e.expires_ms)).toEqual(before.map(e => e.expires_ms));
  });

  it('is single-use: a replayed approve cannot extend twice', async () => {
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1D });
    expect((await approve(ch)).status).toBe(200);
    const first = await inDO(h => readEntries(h, keys));

    const replay = await approve(ch);
    expect(replay.status).toBe(200);        // idempotent re-delivery of the seal
    const second = await inDO(h => readEntries(h, keys));
    expect(second.map(e => e.expires_ms)).toEqual(first.map(e => e.expires_ms));
  });

  it('never resurrects an entry that lapsed between request and approval', async () => {
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1W });
    // The window closes while the ceremony is pending — commitExtend re-reads
    // under the DO gate, so the plan made at request time is worthless.
    const lapsed = Date.now() - MIN;
    await mutateEntries(keys, { expires_ms: lapsed });

    expect((await approve(ch)).status).toBe(200);
    const after = await inDO(h => readEntries(h, keys));
    for (const e of after) expect(e.expires_ms).toBe(lapsed);

    // The effect row exists and says plainly that nothing moved.
    const effect = (await inDO(auditRows)).find(r => r.status === 'extended');
    expect(effect).toBeTruthy();
    expect(effect!.reason).toMatch(/0 条已延长/);
    expect(effect!.reason).toMatch(/expired=2/);
  });

  it('never shortens: a hop that lost its gain before the tap is a no-op', async () => {
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1D });
    // A longer grant landed while this ceremony waited. Approving the shorter
    // hop must not pull the expiry back.
    const far = Date.now() + 30 * DAY;
    await mutateEntries(keys, { expires_ms: far });

    expect((await approve(ch)).status).toBe(200);
    const after = await inDO(h => readEntries(h, keys));
    for (const e of after) expect(e.expires_ms).toBe(far);
    const effect = (await inDO(auditRows)).find(r => r.status === 'extended');
    expect(effect!.reason).toMatch(/no_gain=2/);
  });

  it('refuses a drifted group at commit time too', async () => {
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1W });
    // Drift the group after the approver saw a consistent preview.
    await mutateEntries([keys[0]!], { ip: '198.51.100.4' });
    expect((await approve(ch)).status).toBe(200);
    const after = await inDO(h => readEntries(h, keys));
    for (const e of after) expect(e.expires_ms).toBeLessThan(Date.now() + 2 * HOUR);
    const effect = (await inDO(auditRows)).find(r => r.status === 'extended');
    expect(effect!.reason).toMatch(/inconsistent=2/);
  });

  it('touches only the groups the approver was shown', async () => {
    const { keys, ch } = await armCeremony({ entries: 1, leftMs: HOUR, ttlS: TTL_1W });
    // A second, unrelated group exists and is NOT in the intent.
    const bystander = await inDO(h => seedGroup(h, 1, {
      expires_ms: Date.now() + HOUR, cache_group_id: 'g_bystander00000',
    }));
    const before = (await inDO(h => readEntries(h, bystander)))[0]!.expires_ms;

    expect((await approve(ch)).status).toBe(200);
    expect((await inDO(h => readEntries(h, keys)))[0]!.expires_ms)
      .toBeGreaterThan(Date.now() + 6 * DAY);
    expect((await inDO(h => readEntries(h, bystander)))[0]!.expires_ms).toBe(before);
  });

  it('cannot be turned into a cache WRITE: an extension ceremony carries no salts', async () => {
    const { ch } = await armCeremony({ entries: 1, leftMs: HOUR, ttlS: TTL_1W });
    const dekKeysBefore = await inDO(async h =>
      [...(await h.state.storage.list({ prefix: 'dek:' })).keys()]);

    // Approve the extension ceremony with a cache-write payload bolted on. The
    // TTL is even a legal approve-ladder rung — it must still arm nothing, since
    // the challenge mints no DEKs.
    const res = await approve(ch, {
      cache_ttl_s: TTL_20M,
      cache_sealed_deks_b64u: [sealFakeDek()],
    });
    expect(res.status).toBe(200);

    const dekKeysAfter = await inDO(async h =>
      [...(await h.state.storage.list({ prefix: 'dek:' })).keys()]);
    expect(dekKeysAfter).toEqual(dekKeysBefore);
  });

  it('re-checks the kill switch at commit: switching it off mid-ceremony stops the hop', async () => {
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1W });
    await setDoVar('CACHE_ADMIN_EXTEND', '0');
    expect((await approve(ch)).status).toBe(200);
    const after = await inDO(h => readEntries(h, keys));
    for (const e of after) expect(e.expires_ms).toBeLessThan(Date.now() + 2 * HOUR);
  });

  it('re-checks the extend ladder at commit: a doctored stored intent moves nothing', async () => {
    const { keys, ch } = await armCeremony({ leftMs: HOUR, ttlS: TTL_1D });
    // Simulate tampering between mint and approval: an off-ladder TTL must be
    // refused by commitExtend, not only by the request route.
    await inDO(async h => {
      const stored = (await h.state.storage.get<Challenge>(`ch:${ch.approve_token}`))!;
      await h.state.storage.put(`ch:${ch.approve_token}`, {
        ...stored, extend: { ...stored.extend!, ttl_s: 3 * 24 * 3600 },
      });
    });
    expect((await approve(ch)).status).toBe(200);
    const after = await inDO(h => readEntries(h, keys));
    for (const e of after) expect(e.expires_ms).toBeLessThan(Date.now() + 2 * HOUR);
  });
});

// ── No lifetime ceiling; created_ms and cache_group_id are immutable ───────

describe('extension has no total-lifetime ceiling', () => {
  it('renews the same entry repeatedly, each hop measured from its own approval', async () => {
    const first = await armCeremony({ entries: 1, leftMs: HOUR, ttlS: TTL_1D });
    expect((await approve(first.ch)).status).toBe(200);
    const afterFirst = (await inDO(h => readEntries(h, first.keys)))[0]!;
    expect(Math.abs(afterFirst.expires_ms - (Date.now() + TTL_1D * 1000))).toBeLessThan(10_000);

    // Second hop on the SAME entry — no budget is consumed, only liveness matters.
    const res = await requestExtend([GROUP], TTL_2D);
    expect(res.status).toBe(200);
    const ch2 = await inDO(h => storedChallenge(h, res.json.approve_token));
    expect((await approve(ch2)).status).toBe(200);

    const afterSecond = (await inDO(h => readEntries(h, first.keys)))[0]!;
    expect(Math.abs(afterSecond.expires_ms - (Date.now() + TTL_2D * 1000))).toBeLessThan(10_000);
    expect(afterSecond.expires_ms).toBeGreaterThan(afterFirst.expires_ms);
  });

  it('extends a very old entry exactly like a fresh one', async () => {
    const ancient = Date.now() - 400 * DAY;
    const { keys, ch } = await armCeremony({
      entries: 1, leftMs: HOUR, ttlS: TTL_1W, over: { created_ms: ancient },
    });
    expect((await approve(ch)).status).toBe(200);
    const e = (await inDO(h => readEntries(h, keys)))[0]!;
    expect(Math.abs(e.expires_ms - (Date.now() + TTL_1W * 1000))).toBeLessThan(10_000);
    expect(e.created_ms).toBe(ancient);       // forensic only, never a budget anchor
  });

  it('extends a pre-migration entry that has no created_ms and no group id', async () => {
    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    const keys = await inDO(h => seedGroup(h, 1, {
      expires_ms: Date.now() + HOUR,
      created_ms: undefined,
      cache_group_id: undefined,
      origin_token_id: 'legacyorigin0000',
    }));
    const res = await requestExtend(['legacy:legacyorigin0000'], TTL_1W);
    expect(res.status).toBe(200);
    const ch = await inDO(h => storedChallenge(h, res.json.approve_token));
    expect((await approve(ch)).status).toBe(200);

    const e = (await inDO(h => readEntries(h, keys)))[0]!;
    expect(Math.abs(e.expires_ms - (Date.now() + TTL_1W * 1000))).toBeLessThan(10_000);
    expect(e.created_ms).toBeUndefined();
  });

  it('rewrites expires_ms and nothing else — group id, created_ms, seal, binding stay put', async () => {
    const { keys, ch } = await armCeremony({ entries: 1, leftMs: HOUR, ttlS: TTL_1D });
    const before = (await inDO(h => readEntries(h, keys)))[0]!;
    expect((await approve(ch)).status).toBe(200);
    const after = (await inDO(h => readEntries(h, keys)))[0]!;

    expect(after.expires_ms).toBeGreaterThan(before.expires_ms);
    expect({ ...after, expires_ms: 0 }).toEqual({ ...before, expires_ms: 0 });
    expect(after.cache_group_id).toBe(before.cache_group_id);
    expect(after.created_ms).toBe(before.created_ms);
    expect(after.sealed_to_cache_b64u).toBe(before.sealed_to_cache_b64u);
    expect(after.origin_token_id).toBe(before.origin_token_id);
    expect(after.ip).toBe(before.ip);
  });
});

// ── The audit trail of an extension ────────────────────────────────────────

describe('extension audit', () => {
  it('records the authorization and the effect as two rows', async () => {
    const { ch } = await armCeremony({ entries: 3, leftMs: HOUR, ttlS: TTL_1D });
    expect((await approve(ch)).status).toBe(200);
    const rows = await inDO(auditRows);

    const ceremony = rows.find(r => r.op_kind === 'cache-extend');
    expect(ceremony).toBeTruthy();
    expect(ceremony!.status).toBe('approved');
    expect(ceremony!.command).toMatch(/延长 DEK 缓存有效期/);

    const effect = rows.find(r => r.status === 'extended');
    expect(effect).toBeTruthy();
    expect(effect!.op_kind).toBe('cache');
    expect(effect!.source).toBe('cache');
    expect(effect!.reason).toMatch(/3 条已延长/);
  });

  it('never rewrites cache_ttl_s (the chosen TTL) while bumping cache_expires_ms', async () => {
    // Arrange a realistic origin row: an approval that armed a 20m cache.
    const originToken = 'originrow0000001';
    const armedExpiry = Date.now() + TTL_20M * 1000;
    await inDO(h => {
      h.inst.auditCreate({
        approve_token: originToken,
        created_ms: Date.now(),
        salts_b64u: ['s'],
        meta: makeMeta(),
      });
      h.inst.auditSetCacheTtl(originToken, TTL_20M, armedExpiry);
    });

    await setDoVar('CACHE_ADMIN_EXTEND', '1');
    await inDO(h => seedGroup(h, 1, {
      expires_ms: armedExpiry, origin_token_id: originToken,
    }));
    const res = await requestExtend([GROUP], TTL_1W);
    expect(res.status).toBe(200);
    const ch = await inDO(h => storedChallenge(h, res.json.approve_token));
    expect((await approve(ch)).status).toBe(200);

    const row = (await inDO(auditRows)).find(r => r.token_id === originToken)!;
    expect(row.cache_ttl_s).toBe(TTL_20M);                     // the DECISION, untouched
    expect(row.cache_expires_ms).toBeGreaterThan(armedExpiry);  // the live state, moved
    expect(Math.abs(row.cache_expires_ms! - (Date.now() + TTL_1W * 1000)))
      .toBeLessThan(10_000);
  });
});
