// The console-owned root key + config blob and the push fan-out that reads
// them. Storage is a Map standing in for DO storage, so this runs on plain
// vitest; fetch is stubbed per push service answer.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { AccountAdmin } from '../src/account_admin';
import { AccountNotifications } from '../src/account_notifications';
import { b64uEnc } from '../src/crypto';
import type { Challenge } from '../src/types';

const SECRET = 'synthetic-test-kek';
const ORIGIN = 'https://vt.test.invalid';
const ENTRY = { h: 'L0JnHXnwlzt3HXjLqjzbrgit2WcsVKLQIAFOIdeGB3s', i: 'aWQ', k: 'a2V5', p: 'cHVi', l: 'unit', t: 1 };

function fakeStorage(map = new Map<string, unknown>()) {
  return {
    map,
    get: async <T>(k: string) => map.get(k) as T | undefined,
    put: async (k: string | Record<string, unknown>, v?: unknown) => {
      if (typeof k === 'string') map.set(k, v);
      else for (const [kk, vv] of Object.entries(k)) map.set(kk, vv);
    },
    delete: async (k: string | string[]) => { for (const kk of Array.isArray(k) ? k : [k]) map.delete(kk); },
    list: async (o: { prefix: string }) => new Map([...map].filter(([k]) => k.startsWith(o.prefix))),
  } as unknown as DurableObjectStorage & { map: Map<string, unknown> };
}

/** A bootstrapped admin over `storage`. */
async function configured(storage = fakeStorage(), secret = SECRET) {
  const admin = new AccountAdmin(storage, secret);
  const resp = await admin.bootstrap(new Request('https://account.do/op/x', {
    method: 'POST', headers: { Origin: ORIGIN, 'CF-Connecting-IP': '203.0.113.1' }, body: JSON.stringify({ entry: ENTRY }),
  }));
  expect(resp.status).toBe(204);
  return admin;
}

// A real UA key pair so the encryption step accepts the subscription.
async function browserSub(n: number, label = `dev${n}`) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as CryptoKeyPair;
  return {
    endpoint: `https://push.test.invalid/s/${n}`,
    p256dh: b64uEnc(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey) as ArrayBuffer)),
    auth: b64uEnc(new Uint8Array(16).fill(n)),
    label,
  };
}

const post = (body: unknown) => new Request('https://account.do/op/x', { method: 'POST', body: JSON.stringify(body) });
const get = () => new Request('https://account.do/op/x');

async function listed(admin: AccountAdmin): Promise<Array<{ endpoint: string; label: string }>> {
  const r = await admin.pushOp('vapid', get());
  return ((await r.json()) as { subscriptions: Array<{ endpoint: string; label: string }> }).subscriptions;
}

describe('AccountAdmin config blob', () => {
  it('upserts by endpoint, newest first, and caps at 10', async () => {
    const admin = await configured();
    const a = await browserSub(1, 'first');
    expect((await admin.pushOp('subscribe', post(a))).status).toBe(200);
    expect((await admin.pushOp('subscribe', post(await browserSub(2)))).status).toBe(200);
    expect((await admin.pushOp('subscribe', post({ ...a, label: 'renamed' }))).status).toBe(200);
    expect((await listed(admin)).map(s => [s.endpoint, s.label])).toEqual([
      [a.endpoint, 'renamed'], ['https://push.test.invalid/s/2', 'dev2'],
    ]);
    for (let n = 3; n <= 12; n++) await admin.pushOp('subscribe', post(await browserSub(n)));
    const rows = await listed(admin);
    expect(rows).toHaveLength(10);
    expect(rows[0]!.endpoint).toBe('https://push.test.invalid/s/12');
    expect(rows.some(s => s.endpoint === a.endpoint)).toBe(false);
  });

  it('refuses a malformed subscription', async () => {
    const admin = await configured();
    const ok = await browserSub(1);
    for (const bad of [
      { ...ok, endpoint: 'http://push.test.invalid/s/1' },
      { ...ok, p256dh: b64uEnc(new Uint8Array(32)) },
      { ...ok, auth: 'short' },
      {},
    ]) expect((await admin.pushOp('subscribe', post(bad))).status).toBe(400);
    expect((await admin.pushOp('bogus', get())).status).toBe(400);
  });

  it('seals the blob under K_cfg from R: the same SECRET reads it back, another is unconfigured', async () => {
    const storage = fakeStorage();
    const admin = await configured(storage);
    const sub = await browserSub(7);
    await admin.pushOp('subscribe', post(sub));
    const vapid = ((await (await admin.pushOp('vapid', get())).json()) as { pub_b64u: string }).pub_b64u;
    const stored = JSON.stringify([storage.map.get('cfg:v1'), storage.map.get('root:v1')]);
    expect(stored).not.toContain('push.test.invalid');
    expect(stored).not.toContain(sub.auth);
    expect(stored).not.toContain(ORIGIN);
    expect((storage.map.get('root:v1') as { wraps: unknown[] }).wraps).toHaveLength(1);

    const again = new AccountAdmin(storage, SECRET);
    expect((await listed(again)).map(s => s.endpoint)).toEqual([sub.endpoint]);
    expect(((await (await again.pushOp('vapid', get())).json()) as { pub_b64u: string }).pub_b64u).toBe(vapid);
    expect(again.current.origin).toBe(ORIGIN);

    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const rotated = new AccountAdmin(storage, 'another-secret');
    expect(await rotated.load()).toBeNull();
    expect(await rotated.load()).toBeNull();
    expect(err.mock.calls.filter(c => String(c[0]).includes('config.unreadable'))).toHaveLength(1);
    err.mockRestore();
    // Unreadable root ⇒ the setup view, flagged as a reset.
    expect(await (await rotated.state(get())).json()).toEqual({ state: 'setup', rp_id: null, reset: true });
  });
});

describe('push fan-out', () => {
  afterEach(() => vi.unstubAllGlobals());

  function challenge(): Challenge {
    return {
      approve_token: 'tok00000000000A', poll_token: 'poll000000000000',
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32)), worker_nonce_b64u: b64uEnc(new Uint8Array(16)),
      timestamp_ms: 0, approve_challenge_hash_b64u: '', reject_challenge_hash_b64u: '',
      salts_b64u: ['a'], status: 'pending', created_ms: 0,
      meta: { op_kind: 'decrypt', command: 'cmd', host: 'h', user: 'u', pwd: '/p', project: '', ppid_cmd: '', ip: '1.2.3.4', reason: '' },
    };
  }

  it('drops a subscription on 410, keeps it on 5xx, and never touches the ceremony path', async () => {
    const admin = await configured();
    const dead = await browserSub(1, 'dead');
    const flaky = await browserSub(2, 'flaky');
    await admin.pushOp('subscribe', post(dead));
    await admin.pushOp('subscribe', post(flaky));
    await admin.pushOp('vapid', get());

    const tasks: Promise<unknown>[] = [];
    const notifications = new AccountNotifications(
      { waitUntil: (t: Promise<unknown>) => { tasks.push(t); } }, admin);
    const posted: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      posted.push(url);
      return new Response('', { status: url.endsWith('/1') ? 410 : 503 });
    });
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});

    notifications.approval(challenge());
    expect(posted).toEqual([]); // nothing awaited inline
    await Promise.all(tasks);
    expect(posted.sort()).toEqual([dead.endpoint, flaky.endpoint]);
    expect((await listed(admin)).map(s => s.label)).toEqual(['flaky']);
    const events = err.mock.calls.map(c => JSON.parse(String(c[0])) as { event: string; status?: number });
    expect(events).toEqual([{ event: 'push.failed', err: '', stack: expect.any(String), status: 503 }]);
    err.mockRestore();
  });

  it('sends nothing before a subscription exists', async () => {
    const tasks: Promise<unknown>[] = [];
    const notifications = new AccountNotifications(
      { waitUntil: (t: Promise<unknown>) => { tasks.push(t); } },
      await configured());
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    notifications.approval(challenge());
    await Promise.all(tasks);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
