// Record display names (account_names.ts): the salt is the key, the operator
// owns the name, the client only suggests one. Pins:
//   • a suggestion reaches the page as `claimed`, never as `name`;
//   • a name typed on the page lands only through a VERIFIED approval, never over an owned name;
//   • rename is a session-gated PUT; an empty name deletes;
//   • oversize / miscounted suggestions are refused at the edge (400);
//   • names flow to audit rows (ceremony + hit), the cache listing and the hit push;
//   • a record with neither name nor claim is labeled by its salt prefix, never "unnamed".

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import { b64uEnc, hmacSha256 } from '../src/crypto';
import * as webpush from '../src/webpush';
import { AccountNotifications } from '../src/account_notifications';
import {
  bootstrap, liveTokenId, hostSecret, makeMeta, makeChallenge, nextSalt, daemonAuth, configure,
  approve, signApproval, doPost, doGet, inDO, adminHeaders, sealFakeDek, TEST_ORIGIN,
} from './do_helpers';
import type { RecordName, AuditRow, CacheListResponse } from '../src/types';

let tokenId = '';
beforeEach(async () => { await bootstrap(); tokenId = await liveTokenId(); });

const DAEMON_PK = b64uEnc(new Uint8Array(32).fill(11));

/** A daemon POST through the router with a correct MAC over the exact bytes. */
async function daemonPost(path: string, body: unknown) {
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  const res = await app.fetch(new Request(`${TEST_ORIGIN}${path}`, {
    method: 'POST', body: bytes,
    headers: { Authorization: `VT-HMAC ${b64uEnc(await hmacSha256(await hostSecret(tokenId), bytes))}`, 'VT-Token-Id': tokenId },
  }), env);
  const text = await res.text();
  return { status: res.status, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}

async function rename(body: unknown, headers: Record<string, string> = adminHeaders()) {
  const res = await app.fetch(new Request(`${TEST_ORIGIN}/api/admin/names`, {
    method: 'PUT', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', ...headers },
  }), env);
  return { status: res.status, text: await res.text() };
}

async function namesTable() {
  return inDO(({ state }) => state.storage.sql.exec(`SELECT salt_b64u, name, source FROM names ORDER BY salt_b64u`).toArray());
}

/** Create a decrypt ceremony over `salts` with client suggestions `names`. */
async function createWithNames(salts: string[], names: string[] | undefined) {
  const ch = makeChallenge({ salts_b64u: salts, meta: makeMeta(names ? { names } : {}) });
  expect((await doPost('create', { challenge: ch, auth: await daemonAuth(tokenId) })).status).toBe(200);
  return ch;
}

describe('suggestions on the approval page', () => {
  it('shows a claim as claimed and never as the owned name', async () => {
    const salts = [nextSalt(), nextSalt()];
    const ch = await createWithNames(salts, ['GH_TOKEN', '']);
    const page = await doGet(`page?approve_token=${ch.approve_token}`);
    expect(page.json.records).toEqual([
      { salt_b64u: salts[0], name: null, source: null, claimed: 'GH_TOKEN' },
      { salt_b64u: salts[1], name: null, source: null, claimed: '' },
    ] satisfies RecordName[]);
    expect(await namesTable()).toEqual([]);
  });

  it('shows the owned name beside the claim once one exists', async () => {
    const salt = nextSalt();
    expect((await rename({ salt_b64u: salt, name: 'prod-db' })).status).toBe(200);
    const ch = await createWithNames([salt], ['DB_URL']);
    const page = await doGet(`page?approve_token=${ch.approve_token}`);
    expect(page.json.records[0]).toMatchObject({ name: 'prod-db', source: 'manual', claimed: 'DB_URL' });
  });
});

describe('names typed on the approval page', () => {
  it('writes them only after the assertion verifies, source by whether the claim was kept', async () => {
    const salts = [nextSalt(), nextSalt(), nextSalt()];
    const ch = await createWithNames(salts, ['A', 'B', '']);
    // A failed assertion stores nothing.
    const bad = await approve(ch, { adopt_names: [{ index: 0, name: 'A' }], signature_b64u: b64uEnc(new Uint8Array(70).fill(3)) });
    expect(bad.status).toBe(401);
    expect(await namesTable()).toEqual([]);
    // Verified, through the edge: the kept claim is 'client', a typed name is
    // 'manual' (with or without a claim), control characters are stripped as
    // for a rename.
    const res = await app.fetch(new Request(`${TEST_ORIGIN}/api/approve`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        approve_token: ch.approve_token, sealed_deks_b64u: b64uEnc(new Uint8Array(48).fill(5)),
        binding_tag_b64u: b64uEnc(new Uint8Array(32).fill(6)), ...(await signApproval(ch.approve_challenge_hash_b64u)),
        adopt_names: [{ index: 0, name: 'A' }, { index: 1, name: 'ty\u0007ped' }, { index: 2, name: 'third' }],
      }),
    }), env);
    expect(res.status).toBe(200);
    await res.text(); // consume: an open body holds the DO's isolated storage frame
    expect((await namesTable()).sort((a, b) => salts.indexOf(a.salt_b64u as string) - salts.indexOf(b.salt_b64u as string))).toEqual([
      { salt_b64u: salts[0], name: 'A', source: 'client' },
      { salt_b64u: salts[1], name: 'typed', source: 'manual' },
      { salt_b64u: salts[2], name: 'third', source: 'manual' },
    ]);
  });

  it('refuses the old index-array form and any extra, duplicate or oversize entry, storing nothing', async () => {
    const salts = [nextSalt(), nextSalt()];
    const ch = await createWithNames(salts, ['A', '']);
    for (const adopt_names of [
      [0], 'all', [{ index: 7, name: 'x' }], [{ index: -1, name: 'x' }], [{ index: 0.5, name: 'x' }],
      [{ index: 0, name: 'a' }, { index: 0, name: 'b' }], [{ index: 0, name: 'x'.repeat(41) }],
      [{ index: 0, name: 5 }], [{ index: 0, name: 'a' }, { index: 1, name: 'b' }, { index: 1, name: 'c' }], [null],
    ]) {
      expect((await approve(ch, { adopt_names })).status, JSON.stringify(adopt_names)).toBe(400);
    }
    expect(await namesTable()).toEqual([]);
    expect((await approve(ch, { adopt_names: [] })).status).toBe(200);
    expect(await namesTable()).toEqual([]);
  });

  it('never overwrites an owned name', async () => {
    const salt = nextSalt();
    expect((await rename({ salt_b64u: salt, name: 'owned' })).status).toBe(200);
    const ch = await createWithNames([salt], ['claim']);
    expect((await approve(ch, { adopt_names: [{ index: 0, name: 'claim' }] })).status).toBe(200);
    expect(await namesTable()).toEqual([{ salt_b64u: salt, name: 'owned', source: 'manual' }]);
  });
});

describe('rename (PUT /api/admin/names)', () => {
  it('needs the session cookie, caps the name, and deletes on empty', async () => {
    const salt = nextSalt();
    expect((await rename({ salt_b64u: salt, name: 'x' }, {})).status).toBe(401);
    expect((await rename({ salt_b64u: salt, name: 'x'.repeat(41) })).status).toBe(400);
    expect((await rename({ salt_b64u: salt, name: 5 })).status).toBe(400);
    expect((await rename({ salt_b64u: 'not-a-salt', name: 'x' })).status).toBe(400);
    expect((await rename({ salt_b64u: salt, name: 'a\u0000b' + '中'.repeat(37) })).status).toBe(200);
    expect(await namesTable()).toEqual([{ salt_b64u: salt, name: 'ab' + '中'.repeat(37), source: 'manual' }]);
    expect((await rename({ salt_b64u: salt, name: '' })).status).toBe(200);
    expect(await namesTable()).toEqual([]);
  });
});

describe('edge validation of client suggestions', () => {
  const salts = () => [nextSalt(), nextSalt()];
  const challengeBody = (s: string[], names: unknown) => ({
    daemon_pubkey_b64u: DAEMON_PK, timestamp_ms: Date.now(), salts_b64u: s, meta: { ...makeMeta(), names },
  });

  it('refuses a miscounted or oversize names array on /api/challenge and /api/dek-cache', async () => {
    for (const path of ['/api/challenge', '/api/dek-cache']) {
      const s = salts();
      expect((await daemonPost(path, challengeBody(s, ['one']))).status).toBe(400);
      expect((await daemonPost(path, challengeBody(s, ['a', 'x'.repeat(41)]))).status).toBe(400);
      expect((await daemonPost(path, challengeBody(s, 'GH_TOKEN'))).status).toBe(400);
      expect((await daemonPost(path, challengeBody(s, ['a', 7]))).status).toBe(400);
    }
    expect(await inDO(h => h.state.storage.list({ prefix: 'ch:' }).then(m => m.size))).toBe(0);
  });

  it('accepts absent names and strips control characters from present ones', async () => {
    const s = salts();
    expect((await daemonPost('/api/challenge', challengeBody(s, undefined))).status).toBe(200);
    const res = await daemonPost('/api/challenge', challengeBody(s, ['GH\u0007_TOKEN', '']));
    expect(res.status).toBe(200);
    const page = await doGet(`page?approve_token=${res.json.approve_token}`);
    expect(page.json.records.map((r: RecordName) => r.claimed)).toEqual(['GH_TOKEN', '']);
  });
});

describe('names on the audit, cache and push surfaces', () => {
  it('resolves ceremony and cache-hit rows against the table at read time', async () => {
    const salts = [nextSalt(), nextSalt()];
    const ch = await createWithNames(salts, ['GH_TOKEN', '']);
    const sealed = await Promise.all(salts.map((_, i) => sealFakeDek(i + 1)));
    expect((await approve(ch, { cache_ttl_s: 1200, cache_sealed_deks_b64u: sealed, adopt_names: [{ index: 0, name: 'GH_TOKEN' }] })).status).toBe(200);
    const hit = await daemonPost('/api/dek-cache', {
      daemon_pubkey_b64u: DAEMON_PK, timestamp_ms: Date.now(), salts_b64u: salts,
      meta: { ...makeMeta(), names: ['GH_TOKEN', 'late-claim'] },
    });
    expect(hit.json).toMatchObject({ source: 'cache' });
    // A later rename changes what every existing row shows: names are resolved on read.
    expect((await rename({ salt_b64u: salts[1]!, name: 'second' })).status).toBe(200);
    const rows = (await doGet('audit-query')).json.rows as AuditRow[];
    const ceremony = rows.find(r => r.token_id === ch.approve_token)!;
    expect(ceremony.records).toEqual([
      { salt_b64u: salts[0], name: 'GH_TOKEN', source: 'client', claimed: 'GH_TOKEN' },
      { salt_b64u: salts[1], name: 'second', source: 'manual', claimed: '' },
    ]);
    const hitRow = rows.find(r => r.op_kind === 'cache' && r.status === 'approved')!;
    expect(hitRow.records!.map(r => [r.name, r.claimed])).toEqual([['GH_TOKEN', 'GH_TOKEN'], ['second', 'late-claim']]);
    // Agent / auth rows carry no records.
    const authCh = await createWithNames([], undefined);
    const authRow = ((await doGet('audit-query')).json.rows as AuditRow[]).find(r => r.token_id === authCh.approve_token)!;
    expect(authRow.records).toBeNull();
    // The cache listing shows the same names plus the project the key was narrowed on.
    const list = (await doGet('cache-list')).json as CacheListResponse;
    expect(list.entries).toHaveLength(2);
    expect(list.entries.every(e => e.project === makeMeta().project)).toBe(true);
    expect(list.entries.map(e => [e.record.salt_b64u, e.record.name, e.record.claimed]).sort()).toEqual(
      [[salts[0], 'GH_TOKEN', 'GH_TOKEN'], [salts[1], 'second', '']].sort());
  });

  it('names the served records in the hit push, claims marked (claimed)', async () => {
    const send = vi.spyOn(webpush, 'sendPush').mockResolvedValue({ status: 201 });
    const tasks: Promise<unknown>[] = [];
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as CryptoKeyPair;
    expect((await doPost('push-subscribe', {
      endpoint: 'https://push.test.invalid/s/1', label: 'dev',
      p256dh: b64uEnc(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey) as ArrayBuffer)),
      auth: b64uEnc(new Uint8Array(16).fill(1)),
    })).status).toBe(200);
    await configure({ cache_hit_notify: true });
    await inDO(async ({ inst }) => {
      await inst.admin.pushOp('vapid', new Request('https://account.do/op/x'));
      inst.notifications = new AccountNotifications({ waitUntil: (t: Promise<unknown>) => { tasks.push(t); } }, inst.admin);
    });
    const salts = [nextSalt(), nextSalt(), nextSalt()];
    const ch = await createWithNames(salts, ['A', 'B', '']);
    const sealed = await Promise.all(salts.map((_, i) => sealFakeDek(i + 1)));
    expect((await approve(ch, { cache_ttl_s: 1200, cache_sealed_deks_b64u: sealed, adopt_names: [{ index: 0, name: 'A' }] })).status).toBe(200);
    const hit = await daemonPost('/api/dek-cache', {
      daemon_pubkey_b64u: DAEMON_PK, timestamp_ms: Date.now(), salts_b64u: salts, meta: { ...makeMeta(), names: ['A', 'B', ''] },
    });
    expect(hit.json).toMatchObject({ source: 'cache' });
    await inDO(() => Promise.all(tasks));
    // The approval push came first; the hit push is the last call.
    expect(send).toHaveBeenCalledTimes(2);
    const body = JSON.parse(send.mock.calls[1]![1] as string) as { kind: string; body: string };
    expect(body.kind).toBe('cache_hit');
    // A record with neither name nor claim is its salt's first 8 chars.
    expect(body.body).toContain(`records: A, B (claimed), ${salts[2]!.slice(0, 8)}…`);
    send.mockRestore();
  });
});
function accountStubPut(body: unknown) {
  return app.fetch(new Request(`${TEST_ORIGIN}/api/admin/config`, {
    method: 'PUT', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', ...adminHeaders() },
  }), env).then(async r => ({ status: r.status, text: await r.text() }));
}
