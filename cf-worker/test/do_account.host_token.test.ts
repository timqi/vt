// Host tokens end to end: an unauthenticated enroll request becomes a Passkey
// ceremony, approving it mints a token, and that token then authenticates
// /api/challenge and /api/dek-cache through the real router — the edge checks
// shape and caps, the DO compares the HMAC against the secret it derives from
// the root key and checks liveness / slides expiry. Revocation and the
// rate-limit / pending-cap guards on the public enroll route are covered here
// too — they are what makes the unauthenticated route safe.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import { b64uEnc, hmacSha256 } from '../src/crypto';
import { HOST_TOKEN_TTL_MS } from '../src/host_token';
import type { Challenge, HostTokenRow } from '../src/types';
import { AccountAdmin } from '../src/account_admin';
import {
  inDO, accountStub, configure, doPost, doGet, approve, reject, makeMeta, auditRow, bootstrap, hostSecret,
  redeployWithSecret, TEST_ORIGIN, TEST_CREDENTIAL_ENTRY,
} from './do_helpers';

const ORIGIN = 'https://vt.test.invalid';
const IP = '203.0.113.9';

type Env = Record<string, unknown> & { LIMITER?: unknown };
const routerEnv = (): Env => ({ ...(env as unknown as Env) });

beforeEach(bootstrap);

async function post(path: string, body: unknown, headers: Record<string, string> = {}, e: Env = routerEnv()) {
  const resp = await app.fetch(new Request(`${ORIGIN}${path}`, {
    method: 'POST',
    body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': IP, ...headers },
  }), e);
  const text = await resp.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* text */ }
  return { status: resp.status, text, json };
}

/** Sign a daemon body the way src/cf.rs does for a `vt1.` token; `secret`
 *  defaults to the one this test's root key derives. */
async function tokenHeaders(tokenId: string, body: unknown, secret?: Uint8Array) {
  const raw = new TextEncoder().encode(JSON.stringify(body));
  const mac = await hmacSha256(secret ?? await hostSecret(tokenId), raw);
  return { Authorization: `VT-HMAC ${b64uEnc(mac)}`, 'VT-Token-Id': tokenId };
}

/** The pre-enroll shape: HMAC keyed on some shared value, no VT-Token-Id. */
async function legacyHeaders(body: unknown) {
  const raw = new TextEncoder().encode(JSON.stringify(body));
  const mac = await hmacSha256(new TextEncoder().encode('any-shared-value'), raw);
  return { Authorization: `VT-HMAC ${b64uEnc(mac)}` };
}

function challengeBody(over: Record<string, unknown> = {}) {
  return {
    daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(1)),
    timestamp_ms: Date.now(),
    salts_b64u: [],
    // The CLI no longer sends host/user; whatever it claims must be ignored on
    // the token path.
    meta: { op_kind: 'auth', command: 'vt auth', host: 'spoofed', user: 'mallory', pwd: '/repo', ppid_cmd: 'zsh', reason: '' },
    ...over,
  };
}

async function enrollApproved(host = 'devbox', user = 'qiqi'): Promise<{ tokenId: string; hostToken: string; approveToken: string }> {
  const req = await post('/api/enroll', { host, user, timestamp_ms: Date.now() });
  expect(req.status).toBe(200);
  expect(req.json.pair_code).toMatch(/^\d{3}-\d{3}$/);
  const approveToken = req.json.approve_url.split('/a/')[1];
  const ch = await inDO(h => h.state.storage.get<Challenge>(`ch:${approveToken}`));
  expect(ch!.enroll!.pair_code).toBe(req.json.pair_code);
  const res = await approve(ch!);
  expect(res.status).toBe(200);
  const after = await inDO(h => h.state.storage.get<Challenge>(`ch:${approveToken}`));
  const tokenId = after!.enroll_token_id!;
  expect(tokenId).toMatch(/^[A-Za-z0-9_-]{16}$/);
  const ws = await inDO(h => h.inst.approvedWsMessage(after));
  expect(ws.host_token).toBe(`vt1.${tokenId}.${b64uEnc(await hostSecret(tokenId))}`);
  return { tokenId, hostToken: ws.host_token, approveToken };
}

async function tokenRow(tokenId: string): Promise<HostTokenRow | undefined> {
  return inDO(h => h.inst.tokens.get(tokenId));
}

describe('enrollment', () => {
  it('issues a token only after a verified Passkey approval, seeded from the enroll intent', async () => {
    const { tokenId, approveToken } = await enrollApproved('devbox', 'qiqi');
    const row = (await tokenRow(tokenId))!;
    expect(row.host).toBe('devbox');
    expect(row.user).toBe('qiqi');
    expect(row.enroll_ip).toBe(IP);
    expect(row.last_ip).toBe(IP);
    expect(row.revoked_ms).toBeNull();
    expect(row.expires_ms - row.created_ms).toBe(HOST_TOKEN_TTL_MS);
    expect(row.approve_token_id).toBe(approveToken.slice(0, 16));
    const audit = await inDO(h => auditRow(h, approveToken.slice(0, 16)));
    expect(audit?.op_kind).toBe('enroll');
    expect(audit?.status).toBe('approved');
  });

  it('shows the pairing code and the claimed host on the approval page', async () => {
    const req = await post('/api/enroll', { host: 'devbox', user: 'qiqi', timestamp_ms: Date.now() });
    const approveToken = req.json.approve_url.split('/a/')[1];
    const page = await doGet(`page?approve_token=${approveToken}`);
    expect(page.status).toBe(200);
    expect(page.json.enroll_pair_code).toBe(req.json.pair_code);
    expect(page.json.metadata.host).toBe('devbox');
    expect(page.json.metadata.ip).toBe(IP);
    expect(page.json.metadata.command).toContain(req.json.pair_code);
    expect(page.json.user_verification).toBe('required');
    expect(page.json.cache_options_s).toEqual([0]);
  });

  it('mints nothing when the ceremony is rejected or missing a host', async () => {
    expect((await post('/api/enroll', { host: '', user: 'x', timestamp_ms: Date.now() })).status).toBe(400);
    expect((await post('/api/enroll', { host: 'h', user: 'x', timestamp_ms: Date.now() - 3_600_000 })).status).toBe(400);
    const before = await inDO(h => h.inst.tokens.list().tokens.length);
    const req = await post('/api/enroll', { host: 'devbox', user: 'qiqi', timestamp_ms: Date.now() });
    const approveToken = req.json.approve_url.split('/a/')[1];
    const ch = await inDO(h => h.state.storage.get<Challenge>(`ch:${approveToken}`));
    expect((await reject(ch!)).status).toBe(200);
    const after = await inDO(h => h.state.storage.get<Challenge>(`ch:${approveToken}`));
    expect(after!.status).toBe('rejected');
    expect(after!.enroll_token_id).toBeUndefined();
    expect(await inDO(h => h.inst.tokens.list().tokens.length)).toBe(before);
  });

  it('fails closed without the rate limiter and caps pending enrollments', async () => {
    const e = routerEnv();
    delete e.LIMITER;
    expect((await post('/api/enroll', { host: 'h', user: 'u', timestamp_ms: Date.now() }, {}, e)).status).toBe(503);
    // W-6: the cap one IP hits is per IP; another IP still enrolls, and an
    // approval frees the slot.
    for (let i = 0; i < 2; i++) {
      expect((await post('/api/enroll', { host: `h${i}`, user: 'u', timestamp_ms: Date.now() })).status).toBe(200);
    }
    expect((await post('/api/enroll', { host: 'h6', user: 'u', timestamp_ms: Date.now() })).status).toBe(429);
    const other = { 'CF-Connecting-IP': '198.51.100.7' };
    expect((await post('/api/enroll', { host: 'h7', user: 'u', timestamp_ms: Date.now() }, other)).status).toBe(200);
    expect((await post('/api/enroll', { host: 'h8', user: 'u', timestamp_ms: Date.now() }, other)).status).toBe(200);
    expect((await post('/api/enroll', { host: 'h9', user: 'u', timestamp_ms: Date.now() }, other)).status).toBe(429);
    const h0 = await inDO(async h => [...(await h.state.storage.list<Challenge>({ prefix: 'ch:' })).values()].find(c => c.enroll?.host === 'h0')!);
    expect((await approve(h0)).status).toBe(200);
    expect((await post('/api/enroll', { host: 'h10', user: 'u', timestamp_ms: Date.now() })).status).toBe(200);
  });

  it('bounds pending enrollments globally across IPs', async () => {
    for (let i = 0; i < 32; i++) {
      const res = await post('/api/enroll', { host: `g${i}`, user: 'u', timestamp_ms: Date.now() }, { 'CF-Connecting-IP': `198.51.${i}.1` });
      expect(res.status).toBe(200);
    }
    expect((await post('/api/enroll', { host: 'g32', user: 'u', timestamp_ms: Date.now() }, { 'CF-Connecting-IP': '198.51.200.1' })).status).toBe(429);
  });

  // W-7: the count and the reservation share one input-gate window, so a burst
  // of concurrent requests cannot all pass the cap before any of them is stored.
  // The ceremony build is slowed with a real timer (the gate opens on any
  // non-storage await, as it would on thread-pooled WebCrypto in production).
  it('holds the pending cap under concurrent requests', async () => {
    await inDO(({ inst }) => {
      const build = inst.buildAdminCeremony.bind(inst);
      vi.spyOn(inst, 'buildAdminCeremony').mockImplementation(async (...args: unknown[]) => {
        const ch = await build(...args);
        await new Promise(r => setTimeout(r, 10));
        return ch;
      });
    });
    const enrollCreate = (i: number) => accountStub().fetch('https://account.do/op/enroll-create', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: `burst${i}`, user: 'u', ip: IP, origin: '' }),
    });
    const results = await Promise.all(Array.from({ length: 12 }, (_, i) => enrollCreate(i)));
    await Promise.all(results.map(r => r.text()));
    await inDO(({ inst }) => inst.buildAdminCeremony.mockRestore());
    const statuses = results.map(r => r.status);
    expect(statuses.filter(s => s === 200)).toHaveLength(2);
    expect(statuses.filter(s => s === 429)).toHaveLength(10);
    const pending = await inDO(async h => [...(await h.state.storage.list<Challenge>({ prefix: 'ch:' })).values()]
      .filter(c => c.enroll && c.status === 'pending').length);
    expect(pending).toBe(2);
  });
});

describe('authenticating with a host token', () => {
  it('accepts /api/challenge, names the host from the record, and slides expiry', async () => {
    const { tokenId } = await enrollApproved('devbox', 'qiqi');
    const issued = (await tokenRow(tokenId))!;
    // Move the clock: the record is what the DO reads, so age it directly.
    await inDO(h => h.state.storage.sql.exec(
      `UPDATE host_token SET expires_ms = ?, last_used_ms = ?, last_ip = ? WHERE token_id = ?`,
      issued.expires_ms - 86400_000, issued.last_used_ms - 86400_000, '198.51.100.7', tokenId));
    const body = challengeBody();
    const res = await post('/api/challenge', body, await tokenHeaders(tokenId, body));
    expect(res.status).toBe(200);
    const ch = await inDO(h => h.state.storage.get<Challenge>(`ch:${res.json.approve_token}`));
    expect(ch!.meta.host).toBe('devbox');
    expect(ch!.meta.user).toBe('qiqi');
    expect(ch!.meta.ip).toBe(IP);
    expect(ch!.meta.ip_prev).toBe('198.51.100.7');
    expect(ch!.token_id).toBe(tokenId);
    const page = await doGet(`page?approve_token=${res.json.approve_token}`);
    expect(page.json.host_verified).toBe(true);
    const touched = (await tokenRow(tokenId))!;
    // Slid back to a full window from NOW (not from the aged value).
    expect(Math.abs(touched.expires_ms - (Date.now() + HOST_TOKEN_TTL_MS))).toBeLessThan(60_000);
    expect(touched.last_ip).toBe(IP);
    const audit = await inDO(h => auditRow(h, res.json.approve_token.slice(0, 16)));
    expect(audit?.status).toBe('pending');
  });

  it('applies the by_host UV rule against the verified host', async () => {
    const { tokenId } = await enrollApproved('prod-db', 'qiqi');
    await configure({ uv_policy: { default: 'discouraged', by_host: { 'prod-db': 'required' } } });
    const body = challengeBody();
    const res = await post('/api/challenge', body, await tokenHeaders(tokenId, body));
    expect(res.status).toBe(200);
    const ch = await inDO(h => h.state.storage.get<Challenge>(`ch:${res.json.approve_token}`));
    // The body claimed host='spoofed' (discouraged); the record says prod-db.
    expect(ch!.uv).toBe('required');
    expect(res.json.approve_url).toBe(`${ORIGIN}/a/${res.json.approve_token}`);
  });

  it('refuses a wrong secret, an unknown id, and a malformed id', async () => {
    const { tokenId } = await enrollApproved();
    const body = challengeBody();
    const wrong = await post('/api/challenge', body, await tokenHeaders(tokenId, body, new Uint8Array(32).fill(1)));
    expect(wrong.status).toBe(401);
    expect(wrong.text).toBe('hmac mismatch');
    // An unknown id derives SOME secret; signing with it still fails the MAC
    // only if the caller does not know R — here the test does, so liveness is
    // what refuses it.
    const unknown = await post('/api/challenge', body, await tokenHeaders('zzzzzzzzzzzzzzzz', body));
    expect(unknown.status).toBe(401);
    expect(unknown.json.error).toBe('token_unknown');
    const malformed = await post('/api/challenge', body, { ...(await tokenHeaders(tokenId, body)), 'VT-Token-Id': 'short' });
    expect(malformed.status).toBe(401);
    // Nothing was stored or audited for the refusals.
    expect(await inDO(h => auditRow(h, 'never'))).toBeUndefined();
  });

  it('refuses revoked and expired tokens with a structured reason and never revives them', async () => {
    const { tokenId } = await enrollApproved();
    const body = challengeBody();
    await inDO(h => h.state.storage.sql.exec(`UPDATE host_token SET expires_ms = ? WHERE token_id = ?`, Date.now() - 1, tokenId));
    const expired = await post('/api/challenge', body, await tokenHeaders(tokenId, body));
    expect(expired.status).toBe(401);
    expect(expired.json.error).toBe('token_expired');
    expect((await tokenRow(tokenId))!.expires_ms).toBeLessThan(Date.now());

    const { tokenId: t2 } = await enrollApproved();
    expect(await inDO(h => h.inst.tokens.revoke(t2, Date.now()))).toBe(true);
    expect(await inDO(h => h.inst.tokens.revoke(t2, Date.now()))).toBe(false);
    const revoked = await post('/api/challenge', body, await tokenHeaders(t2, body));
    expect(revoked.status).toBe(401);
    expect(revoked.json.error).toBe('token_revoked');
    const probe = await post('/api/dek-cache', { ...challengeBody(), salts_b64u: [b64uEnc(new Uint8Array(16))] }, await tokenHeaders(t2, body));
    expect(probe.status).toBe(401);
  });

  it('counts a dek-cache probe as a use', async () => {
    const { tokenId } = await enrollApproved();
    const issued = (await tokenRow(tokenId))!;
    await inDO(h => h.state.storage.sql.exec(`UPDATE host_token SET expires_ms = ? WHERE token_id = ?`, issued.expires_ms - 3_600_000, tokenId));
    const body = { ...challengeBody(), salts_b64u: [b64uEnc(new Uint8Array(16).fill(3))] };
    const res = await post('/api/dek-cache', body, await tokenHeaders(tokenId, body));
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ miss: true });
    expect((await tokenRow(tokenId))!.expires_ms).toBeGreaterThan(issued.expires_ms - 60_000);
  });

  it('refuses a token-less signature on both daemon routes, storing and auditing nothing', async () => {
    // A host that never ran `vt enroll` has nothing but a guess to sign with
    // and sends no VT-Token-Id. It gets the same structured 401 as a dead
    // token, so the CLI prints the enroll hint.
    const body = challengeBody();
    const before = await inDO(h => h.state.storage.list({ prefix: 'ch:' }).then(m => m.size));
    for (const path of ['/api/challenge', '/api/dek-cache']) {
      const res = await post(path, body, await legacyHeaders(body));
      expect(res.status).toBe(401);
      expect(res.json).toMatchObject({ error: 'token_missing' });
    }
    expect(await inDO(h => h.state.storage.list({ prefix: 'ch:' }).then(m => m.size))).toBe(before);
  });

  it('fails closed inside the DO when a body arrives without auth', async () => {
    // Only the edge can reach these ops; a missing auth block there is a Worker
    // bug, and the DO must not fall back to the client-claimed host/user.
    const ch = { ...challengeBody(), approve_token: 'a'.repeat(16), poll_token: 'p'.repeat(16), status: 'pending', created_ms: Date.now() };
    expect((await doPost('create', { challenge: ch })).status).toBe(400);
    expect((await doPost('dek-cache', { ...challengeBody(), salts_b64u: [b64uEnc(new Uint8Array(16))] })).status).toBe(400);
    expect(await inDO(h => h.state.storage.get(`ch:${ch.approve_token}`))).toBeUndefined();
  });

  it('drops tty / ppid / ssh_client from the stored meta', async () => {
    const { tokenId } = await enrollApproved();
    const body = challengeBody({ meta: { ...makeMeta(), tty: '/dev/pts/1', ppid: 7, ssh_client: '10.0.0.1 1 22' } });
    const res = await post('/api/challenge', body, await tokenHeaders(tokenId, body));
    const ch = await inDO(h => h.state.storage.get<Challenge>(`ch:${res.json.approve_token}`));
    expect(Object.keys(ch!.meta).sort()).toEqual(['command', 'host', 'ip', 'ip_prev', 'op_kind', 'ppid_cmd', 'project', 'pwd', 'reason', 'user']);
  });
});

// SECRET is a KEK over the root key (docs/worker-slim.md#root-key-and-custody): rotating it
// through the console keeps R, so every host token keeps verifying; the old
// value dies on the first load under the new one. A FRESH secret without that
// rotation is the factory reset — root:v1 is unreadable, bootstrap replaces it
// with a new R, and every token derived from the old one fails at once. There
// is no second accepted generation and no PREV binding.
describe('SECRET rotation and reset', () => {
  /** A fresh AccountAdmin seeing `secret` as its SECRET, over the same storage. */
  const withSecret = (secret: string) => inDO(async ({ state }) => {
    const admin = new AccountAdmin(state.storage, secret);
    return { loaded: await admin.load(), admin };
  });

  it('keeps every host token across a console rotation and retires the old wrap on first use', async () => {
    const { tokenId } = await enrollApproved('devbox', 'qiqi');
    const rotated = await doPost('admin-rotate-secret', {});
    expect(rotated.status).toBe(200);
    const fresh = rotated.json.secret as string;
    expect(fresh).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const wraps = () => inDO(h => h.state.storage.get<{ wraps: unknown[] }>('root:v1').then(r => r!.wraps.length));
    expect(await wraps()).toBe(2);
    // Both values open R while the window is open …
    expect((await withSecret(env.SECRET)).loaded).not.toBeNull();
    expect(await wraps()).toBe(2);
    // … and the first load under the new one collapses to a single wrap.
    const under = await withSecret(fresh);
    expect(under.loaded).not.toBeNull();
    expect(await wraps()).toBe(1);
    expect((await withSecret(env.SECRET)).loaded).toBeNull();
    // The token secret is R's, not SECRET's: the enrolled host is untouched.
    expect(await under.admin.hostTokenSecret(tokenId)).toEqual(await hostSecret(tokenId));
    const body = challengeBody();
    expect((await post('/api/challenge', body, await tokenHeaders(tokenId, body))).status).toBe(200);
    // A second rotation before deploying replaces the pending wrap: never three.
    await doPost('admin-rotate-secret', {});
    await doPost('admin-rotate-secret', {});
    expect(await wraps()).toBe(2);
  });

  it('refuses every token from the previous root after a reset, PREV binding or not', async () => {
    const { tokenId } = await enrollApproved('oldhost', 'qiqi');
    const oldSecret = await hostSecret(tokenId);
    // Factory reset: a fresh SECRET, root:v1 unreadable, bootstrap again.
    await redeployWithSecret('a-fresh-secret');
    const state = await doGet('admin-state', {});
    expect(state.json).toEqual({ state: 'setup', rp_id: null, reset: true });
    const body = challengeBody();
    const probe = { ...challengeBody(), salts_b64u: [b64uEnc(new Uint8Array(16).fill(5))] };
    for (const path of ['/api/challenge', '/api/dek-cache'] as const) {
      const res = await post(path, path === '/api/challenge' ? body : probe,
        await tokenHeaders(tokenId, path === '/api/challenge' ? body : probe, oldSecret));
      expect(res.status).toBe(503);
      expect(res.json).toEqual({ error: 'not_configured' });
    }
    const boot = await app.fetch(new Request(`${ORIGIN}/api/admin/bootstrap`, {
      method: 'POST', body: JSON.stringify({ entry: TEST_CREDENTIAL_ENTRY }),
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN, 'CF-Connecting-IP': IP },
    }), routerEnv());
    await boot.text();
    expect(boot.status).toBe(204);
    for (const e of [routerEnv(), { ...routerEnv(), SECRET_PREV: 'test-kek-not-a-secret' }]) {
      const res = await post('/api/challenge', body, await tokenHeaders(tokenId, body, oldSecret), e);
      expect(res.status).toBe(401);
      expect(res.text).toBe('hmac mismatch');
      const miss = await post('/api/dek-cache', probe, await tokenHeaders(tokenId, probe, oldSecret), e);
      expect(miss.status).toBe(401);
      expect(miss.text).toBe('hmac mismatch');
    }
    // The refusals were not uses: the row is exactly as enrollment left it.
    const row = (await tokenRow(tokenId))!;
    expect(row.last_used_ms).toBe(row.created_ms);
    // Only a fresh `vt enroll` (a new token under the new R) gets back in.
    const { tokenId: again } = await enrollApproved('oldhost', 'qiqi');
    expect((await post('/api/challenge', body, await tokenHeaders(again, body))).status).toBe(200);
  });

  it('refuses a token-less signature under either generation', async () => {
    const body = challengeBody();
    for (const key of [env.SECRET, 'a-fresh-secret']) {
      const raw = new TextEncoder().encode(JSON.stringify(body));
      const mac = await hmacSha256(new TextEncoder().encode(key), raw);
      const res = await post('/api/challenge', body, { Authorization: `VT-HMAC ${b64uEnc(mac)}` });
      expect(res.status).toBe(401);
      expect(res.json).toMatchObject({ error: 'token_missing' });
    }
  });

  it('refuses an audit push signed with a previous root, and the hostname-keyed master form', async () => {
    const { tokenId } = await enrollApproved('mac', 'qiqi');
    const body = {
      timestamp_ms: Date.now(), agent_id: `t:${tokenId}`, hostname: 'mac',
      entry: { op_kind: 'sign', outcome: 'approved', salts: 0, latency_ms: 1, ts_ms: Date.now(),
               token_id: `a_t:${tokenId}_${Math.random()}`, meta: { op_kind: 'sign', host: 'mac', user: 'qiqi' } },
    };
    const raw = new TextEncoder().encode(JSON.stringify(body));
    const sign = async (key: Uint8Array) => ({ Authorization: `VT-HMAC ${b64uEnc(await hmacSha256(key, raw))}` });
    expect((await post('/api/audit-ingest', body, await sign(new Uint8Array(32).fill(9)))).status).toBe(401);
    expect((await post('/api/audit-ingest', body, await sign(await hostSecret(tokenId)))).status).toBe(200);

    // A hostname-salted master key is not a per-host token (docs/worker-slim.md#host-tokens):
    // no token id, no row, whatever it was signed with.
    const legacyBody = { ...body, agent_id: 'mac' };
    const legacyRaw = new TextEncoder().encode(JSON.stringify(legacyBody));
    const legacyMac = await hmacSha256(new TextEncoder().encode('test-kek-not-a-secret'), legacyRaw);
    const refused = await post('/api/audit-ingest', legacyBody, { Authorization: `VT-HMAC ${b64uEnc(legacyMac)}` });
    expect(refused.status).toBe(401);
    expect(refused.text).toBe('bad agent token id');
  });
});

describe('audit ingest keyed on a host token', () => {
  async function ingest(agentId: string, key: Uint8Array, entryOver: Record<string, unknown> = {}) {
    const body = {
      timestamp_ms: Date.now(), agent_id: agentId, hostname: 'mac',
      entry: { op_kind: 'sign', outcome: 'approved', salts: 0, latency_ms: 1, ts_ms: Date.now(),
               token_id: `a_${agentId}_${Math.random()}`, meta: { op_kind: 'sign', host: 'mac', user: 'qiqi' },
               ...entryOver },
    };
    const raw = new TextEncoder().encode(JSON.stringify(body));
    const mac = await hmacSha256(key, raw);
    return post('/api/audit-ingest', body, { Authorization: `VT-HMAC ${b64uEnc(mac)}` });
  }

  it('accepts a live token and refuses a revoked one', async () => {
    const { tokenId } = await enrollApproved('mac', 'qiqi');
    const key = await hostSecret(tokenId);
    expect((await ingest(`t:${tokenId}`, key)).status).toBe(200);
    const before = (await tokenRow(tokenId))!;
    // A background push is not a use: expiry did not slide.
    expect(before.last_used_ms).toBe(before.created_ms);
    await inDO(h => h.inst.tokens.revoke(tokenId, Date.now()));
    expect((await ingest(`t:${tokenId}`, key)).status).toBe(401);
    expect((await ingest('t:short', key)).status).toBe(401);
  });

  // W-2: a host writes only rows attributed to itself. The row key must carry
  // the signing token and host/user come from the token record.
  it('refuses a row keyed on another token and relabels host/user from the record', async () => {
    const { tokenId } = await enrollApproved('mac', 'qiqi');
    const { tokenId: other } = await enrollApproved('prod', 'root');
    const key = await hostSecret(tokenId);
    const forged = await ingest(`t:${tokenId}`, key, { token_id: `a_t:${other}_x` });
    expect(forged.status).toBe(400);
    expect((await ingest(`t:${tokenId}`, key, { token_id: `a_t:${tokenId}` })).status).toBe(400);
    expect((await ingest(`t:${tokenId}`, key, { token_id: `prefix_a_t:${tokenId}_x` })).status).toBe(400);
    const own = await ingest(`t:${tokenId}`, key, { meta: { op_kind: 'sign', host: 'prod', user: 'root' } });
    expect(own.status).toBe(200);
    const rows = await inDO(h => h.state.storage.sql
      .exec(`SELECT token_id, host, user FROM audit WHERE source = 'agent'`).toArray());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ host: 'mac', user: 'qiqi' });
    expect(String(rows[0]!.token_id).startsWith(`a_t:${tokenId}_`)).toBe(true);
  });
});

describe('admin token inventory', () => {
  it('lists without secrets and revokes idempotently', async () => {
    const { tokenId } = await enrollApproved('devbox', 'qiqi');
    const list = await doGet('tokens-list');
    expect(list.status).toBe(200);
    const row = list.json.tokens.find((t: HostTokenRow) => t.token_id === tokenId);
    expect(row.host).toBe('devbox');
    expect(JSON.stringify(list.json)).not.toContain(b64uEnc(await hostSecret(tokenId)));
    expect((await doPost('tokens-revoke', { token_id: tokenId })).json).toEqual({ revoked: true });
    expect((await doPost('tokens-revoke', { token_id: tokenId })).json).toEqual({ revoked: false });
    expect((await doPost('tokens-revoke', { token_id: '' })).status).toBe(400);
  });

  // W-9: a storage failure is a structured 5xx, never `revoked: false` (which
  // the console reads as "already inactive").
  it('reports a failed revoke as an error while the token stays live', async () => {
    const { tokenId } = await enrollApproved('devbox', 'qiqi');
    await inDO(({ state }) => {
      vi.spyOn(state.storage.sql, 'exec').mockImplementation(() => { throw new Error('synthetic SQL failure'); });
    });
    try {
      const res = await doPost('tokens-revoke', { token_id: tokenId });
      expect(res.status).toBe(500);
      expect(res.json).toEqual({ error: 'token.revoke_failed' });
    } finally {
      await inDO(({ state }) => (state.storage.sql.exec as unknown as { mockRestore(): void }).mockRestore());
    }
    expect((await tokenRow(tokenId))!.revoked_ms).toBeNull();
    expect((await doPost('tokens-revoke', { token_id: tokenId })).json).toEqual({ revoked: true });
  });
});
