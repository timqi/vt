// Record display names (account_names.ts): the salt is the key, the operator
// owns the name, the client only suggests one. Pins:
//   • a suggestion reaches the page as `claimed`, never as `name`;
//   • adoption happens only through a VERIFIED approval, never over an owned name;
//   • rename is a session-gated PUT; an empty name deletes;
//   • oversize / miscounted suggestions are refused at the edge (400);
//   • names flow to audit rows (ceremony + hit), the cache listing and the hit push.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import { b64uEnc, hmacSha256 } from '../src/crypto';
import * as webpush from '../src/webpush';
import { AccountNotifications } from '../src/account_notifications';
import {
  bootstrap, liveTokenId, hostSecret, makeMeta, makeChallenge, nextSalt, daemonAuth, configure,
  approve, doPost, doGet, inDO, adminHeaders, sealFakeDek, TEST_ORIGIN,
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
  it('shows a claim as 自报 and never as the owned name', async () => {
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

describe('adoption', () => {
  it('writes the adopted suggestions only after the assertion verifies', async () => {
    const salts = [nextSalt(), nextSalt(), nextSalt()];
    const ch = await createWithNames(salts, ['A', 'B', '']);
    // A failed assertion adopts nothing.
    const bad = await approve(ch, { adopt_names: [0, 1], signature_b64u: b64uEnc(new Uint8Array(70).fill(3)) });
    expect(bad.status).toBe(401);
    expect(await namesTable()).toEqual([]);
    // Verified: index 0 adopted; index 2 has no claim; 7 is out of range; junk ignored.
    expect((await approve(ch, { adopt_names: [0, 2, 7, 'x', -1] })).status).toBe(200);
    expect(await namesTable()).toEqual([{ salt_b64u: salts[0], name: 'A', source: 'client' }]);
  });

  it('never overwrites an owned name and refuses a non-array adopt_names', async () => {
    const salt = nextSalt();
    expect((await rename({ salt_b64u: salt, name: 'owned' })).status).toBe(200);
    const ch = await createWithNames([salt], ['claim']);
    expect((await approve(ch, { adopt_names: 'all' })).status).toBe(400);
    expect((await approve(ch, { adopt_names: [0] })).status).toBe(200);
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
    expect((await approve(ch, { cache_ttl_s: 1200, cache_sealed_deks_b64u: sealed, adopt_names: [0] })).status).toBe(200);
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
    expect(list.groups).toHaveLength(1);
    expect(list.groups[0]!.project).toBe(makeMeta().project);
    expect(list.groups[0]!.records.map(r => [r.salt_b64u, r.name, r.claimed]).sort()).toEqual(
      [[salts[0], 'GH_TOKEN', 'GH_TOKEN'], [salts[1], 'second', '']].sort());
  });

  it('names the served records in the hit push, claims marked 自报', async () => {
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
    expect((await approve(ch, { cache_ttl_s: 1200, cache_sealed_deks_b64u: sealed, adopt_names: [0] })).status).toBe(200);
    const hit = await daemonPost('/api/dek-cache', {
      daemon_pubkey_b64u: DAEMON_PK, timestamp_ms: Date.now(), salts_b64u: salts, meta: { ...makeMeta(), names: ['A', 'B', ''] },
    });
    expect(hit.json).toMatchObject({ source: 'cache' });
    await inDO(() => Promise.all(tasks));
    // The approval push came first; the hit push is the last call.
    expect(send).toHaveBeenCalledTimes(2);
    const body = JSON.parse(send.mock.calls[1]![1] as string) as { kind: string; body: string };
    expect(body.kind).toBe('cache_hit');
    expect(body.body).toContain('records: A, B（自报）, 未命名');
    send.mockRestore();
  });
});
function accountStubPut(body: unknown) {
  return app.fetch(new Request(`${TEST_ORIGIN}/api/admin/config`, {
    method: 'PUT', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', ...adminHeaders() },
  }), env).then(async r => ({ status: r.status, text: await r.text() }));
}
