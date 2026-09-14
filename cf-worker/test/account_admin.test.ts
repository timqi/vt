// The console-owned config blob and the push fan-out that reads it. Storage is
// a Map standing in for DO storage (the class takes get/put only), so this runs
// on plain vitest; fetch is stubbed per push service answer.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { AccountAdmin } from '../src/account_admin';
import { AccountNotifications } from '../src/account_notifications';
import { b64uEnc } from '../src/crypto';
import type { Challenge, Env } from '../src/types';

const ENV = { VT_AUTH_CF: 'synthetic-test-master', WORKER_ORIGIN: 'https://vt.test.invalid' } as Env;

function fakeStorage(map = new Map<string, unknown>()) {
  return {
    map,
    get: async <T>(k: string) => map.get(k) as T | undefined,
    put: async (k: string, v: unknown) => { map.set(k, v); },
  } as unknown as DurableObjectStorage & { map: Map<string, unknown> };
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
    const admin = new AccountAdmin(fakeStorage(), ENV);
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
    const admin = new AccountAdmin(fakeStorage(), ENV);
    const ok = await browserSub(1);
    for (const bad of [
      { ...ok, endpoint: 'http://push.test.invalid/s/1' },
      { ...ok, p256dh: b64uEnc(new Uint8Array(32)) },
      { ...ok, auth: 'short' },
      {},
    ]) expect((await admin.pushOp('subscribe', post(bad))).status).toBe(400);
    expect((await admin.pushOp('bogus', get())).status).toBe(400);
  });

  it('seals the blob under K_cfg: same master reads it back, another cannot', async () => {
    const storage = fakeStorage();
    const admin = new AccountAdmin(storage, ENV);
    const sub = await browserSub(7);
    await admin.pushOp('subscribe', post(sub));
    const vapid = ((await (await admin.pushOp('vapid', get())).json()) as { pub_b64u: string }).pub_b64u;
    const stored = JSON.stringify(storage.map.get('cfg:v1'));
    expect(stored).not.toContain('push.test.invalid');
    expect(stored).not.toContain(sub.auth);

    const again = new AccountAdmin(storage, ENV);
    expect((await listed(again)).map(s => s.endpoint)).toEqual([sub.endpoint]);
    expect(((await (await again.pushOp('vapid', get())).json()) as { pub_b64u: string }).pub_b64u).toBe(vapid);

    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const rotated = new AccountAdmin(storage, { ...ENV, VT_AUTH_CF: 'another-master' });
    expect(await listed(rotated)).toEqual([]);
    expect(err.mock.calls.some(c => String(c[0]).includes('config.unreadable'))).toBe(true);
    err.mockRestore();
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
    const admin = new AccountAdmin(fakeStorage(), ENV);
    const dead = await browserSub(1, 'dead');
    const flaky = await browserSub(2, 'flaky');
    await admin.pushOp('subscribe', post(dead));
    await admin.pushOp('subscribe', post(flaky));
    await admin.pushOp('vapid', get());

    const tasks: Promise<unknown>[] = [];
    const notifications = new AccountNotifications(
      { storage: fakeStorage(), waitUntil: (t: Promise<unknown>) => { tasks.push(t); } }, ENV, admin);
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
      { storage: fakeStorage(), waitUntil: (t: Promise<unknown>) => { tasks.push(t); } },
      ENV, new AccountAdmin(fakeStorage(), ENV));
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    notifications.approval(challenge());
    await Promise.all(tasks);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
