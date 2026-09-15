// Passkey admin auth end to end (docs/worker-slim.md#sessions): bootstrap mints the
// root key and the first session; login is a discoverable-credential
// assertion over a single-use challenge; every admin op and the audit-stream
// upgrade verify the cookie in the DO; revocations bump the epoch and end
// every session at once. Router-level cases go through the real Hono app so
// the rate limiter and header forwarding are exercised too.

import { describe, it, expect, beforeEach } from 'vitest';
import { env, SELF } from 'cloudflare:test';
import app from '../src/index';
import { b64uDec, b64uEnc } from '../src/crypto';
import { SESSION_COOKIE, sessionCookieValue } from '../src/admin_auth';
import {
  accountStub, inDO, doGet, doPost, bootstrap, adminHeaders, signChallenge, loginAssertion,
  TEST_ORIGIN, TEST_CREDENTIAL_ENTRY,
} from './do_helpers';

type Env = Record<string, unknown> & { LIMITER?: unknown };
const IP = '203.0.113.9';

async function viaRouter(path: string, init: RequestInit & { headers?: Record<string, string> } = {}, e: Env = env as unknown as Env) {
  const resp = await app.fetch(new Request(`${TEST_ORIGIN}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': IP, ...(init.headers ?? {}) },
  }), e);
  const text = await resp.text();
  let json: unknown = null;
  try { json = JSON.parse(text); } catch { /* text */ }
  return { status: resp.status, text, json: json as Record<string, unknown>, cookie: resp.headers.get('Set-Cookie') };
}

const cookieHeader = (value: string) => ({ Cookie: `${SESSION_COOKIE}=${value}`, Origin: TEST_ORIGIN });

const assertion = loginAssertion;

/** A full login: challenge, assertion by the test authenticator, cookie. */
async function login(headers: Record<string, string> = {}) {
  const ch = await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}' });
  expect(ch.status).toBe(200);
  const c = ch.json as { challenge_id: string; challenge_b64u: string; rp_id: string };
  expect(c.rp_id).toBe('vt.test.invalid');
  const assertion = await signChallenge(b64uDec(c.challenge_b64u), 0x05);
  return viaRouter('/api/admin/login', {
    method: 'POST', body: JSON.stringify({ challenge_id: c.challenge_id, ...assertion }), headers,
  });
}

describe('bootstrap', () => {
  it('needs the rate limiter, an https Origin and a well-formed entry', async () => {
    const e = { ...(env as unknown as Env) };
    delete e.LIMITER;
    const body = JSON.stringify({ entry: TEST_CREDENTIAL_ENTRY });
    expect((await viaRouter('/api/admin/bootstrap', { method: 'POST', body, headers: { Origin: TEST_ORIGIN } }, e)).status).toBe(503);
    expect((await viaRouter('/api/admin/bootstrap', { method: 'POST', body })).status).toBe(400);
    expect((await viaRouter('/api/admin/bootstrap', { method: 'POST', body, headers: { Origin: 'http://vt.test.invalid' } })).status).toBe(400);
    expect((await viaRouter('/api/admin/bootstrap', {
      method: 'POST', body: JSON.stringify({ entry: { v: 1, c: [TEST_CREDENTIAL_ENTRY] } }), headers: { Origin: TEST_ORIGIN },
    })).status).toBe(400);
    expect(await inDO(h => h.state.storage.get('root:v1'))).toBeUndefined();
  });

  it('answers 409 with the first registration once configured, and login then works', async () => {
    const first = await viaRouter('/api/admin/bootstrap', {
      method: 'POST', body: JSON.stringify({ entry: TEST_CREDENTIAL_ENTRY }), headers: { Origin: TEST_ORIGIN },
    });
    expect(first.status).toBe(204);
    expect(first.cookie).toMatch(new RegExp(`^${SESSION_COOKIE}=1\\.\\d+\\.1\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800$`));

    const again = await viaRouter('/api/admin/bootstrap', {
      method: 'POST', body: JSON.stringify({ entry: { ...TEST_CREDENTIAL_ENTRY, h: 'B'.repeat(43) } }),
      headers: { Origin: 'https://evil.test.invalid', 'CF-Connecting-IP': '198.51.100.7' },
    });
    expect(again.status).toBe(409);
    expect(again.json.error).toBe('already_configured');
    expect(again.json.ip).toBe(IP);
    expect(Math.abs((again.json.ms as number) - Date.now())).toBeLessThan(60_000);
    // The stranger changed nothing: still one credential, the original origin.
    const creds = await doGet('admin-credentials', cookieHeader(sessionCookieValue(first.cookie)!));
    expect(creds.json.credentials).toHaveLength(1);
    expect(creds.json.epoch).toBe(1);

    const session = await login();
    expect(session.status).toBe(204);
    expect(session.cookie).toContain(`${SESSION_COOKIE}=1.`);
    // Root and blob at rest hold neither the origin nor the credential label.
    await inDO(async ({ state }) => {
      const raw = JSON.stringify([await state.storage.get('root:v1'), await state.storage.get('cfg:v1')]);
      expect(raw).not.toContain('vt.test.invalid');
      expect(raw).not.toContain('test-passkey');
    });
  });
});

describe('login', () => {
  beforeEach(bootstrap);

  it('consumes its challenge once, within 120 s, and caps pending challenges per IP', async () => {
    const ch = (await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}' })).json as { challenge_id: string; challenge_b64u: string };
    const assertion = await signChallenge(b64uDec(ch.challenge_b64u), 0x05);
    const body = JSON.stringify({ challenge_id: ch.challenge_id, ...assertion });
    expect((await viaRouter('/api/admin/login', { method: 'POST', body })).status).toBe(204);
    const replay = await viaRouter('/api/admin/login', { method: 'POST', body });
    expect(replay.status).toBe(401);
    expect(replay.json).toEqual({ error: 'login_failed' });

    const stale = (await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}' })).json as { challenge_id: string; challenge_b64u: string };
    await inDO(h => h.state.storage.put(`login:${stale.challenge_id}`, { c: stale.challenge_b64u, t: Date.now() - 121_000 }));
    const late = await signChallenge(b64uDec(stale.challenge_b64u), 0x05);
    expect((await viaRouter('/api/admin/login', { method: 'POST', body: JSON.stringify({ challenge_id: stale.challenge_id, ...late }) })).status).toBe(401);

    // W-11: an over-long challenge_id is refused before it becomes a storage key.
    const long = await viaRouter('/api/admin/login', { method: 'POST', body: JSON.stringify({ challenge_id: 'A'.repeat(3000), ...late }) });
    expect(long.status).toBe(400);
    expect(long.text).toBe('bad challenge_id');

    for (let i = 0; i < 5; i++) expect((await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}' })).status).toBe(200);
    expect((await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}' })).status).toBe(429);
    // One saturated client does not lock the operator out from elsewhere.
    const elsewhere = { 'CF-Connecting-IP': '198.51.100.7' };
    expect((await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}', headers: elsewhere })).status).toBe(200);
    await inDO(async h => {
      const rows = [...(await h.state.storage.list<{ ip: string }>({ prefix: 'login:' })).values()];
      expect(rows.filter(r => r.ip === IP)).toHaveLength(5);
      expect(rows.filter(r => r.ip === elsewhere['CF-Connecting-IP'])).toHaveLength(1);
    });
    const e = { ...(env as unknown as Env) };
    delete e.LIMITER;
    expect((await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}' }, e)).status).toBe(503);
  });

  it('refuses a presence-only assertion and an unknown credential', async () => {
    const ch = (await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}' })).json as { challenge_id: string; challenge_b64u: string };
    const upOnly = await signChallenge(b64uDec(ch.challenge_b64u), 0x01);
    expect((await viaRouter('/api/admin/login', { method: 'POST', body: JSON.stringify({ challenge_id: ch.challenge_id, ...upOnly }) })).status).toBe(401);
    const ch2 = (await viaRouter('/api/admin/login-challenge', { method: 'POST', body: '{}' })).json as { challenge_id: string; challenge_b64u: string };
    const other = { ...(await signChallenge(b64uDec(ch2.challenge_b64u), 0x05)), credential_id_b64u: b64uEnc(new Uint8Array(16).fill(3)) };
    expect((await viaRouter('/api/admin/login', { method: 'POST', body: JSON.stringify({ challenge_id: ch2.challenge_id, ...other }) })).status).toBe(401);
  });
});

describe('session verification in the DO', () => {
  beforeEach(bootstrap);

  it('rejects a tampered MAC, an expired cookie, a stale epoch, and no cookie at all', async () => {
    const value = sessionCookieValue(adminHeaders().Cookie!)!;
    const [v, exp, epoch, nonce, mac] = value.split('.');
    // Flip the FIRST char: the last one carries padding bits a decoder drops.
    const flipped = (mac!.startsWith('A') ? 'B' : 'A') + mac!.slice(1);
    for (const bad of [
      `${v}.${exp}.${epoch}.${nonce}.${flipped}`,
      `${v}.${Math.floor(Date.now() / 1000) - 1}.${epoch}.${nonce}.${mac}`,
      `${v}.${exp}.${Number(epoch) + 1}.${nonce}.${mac}`,
      'garbage',
    ]) {
      const res = await doGet('tokens-list', cookieHeader(bad));
      expect(res.status).toBe(401);
      expect(res.json).toEqual({ error: 'session_invalid' });
    }
    expect((await doGet('tokens-list', {})).status).toBe(401);
    expect((await doGet('tokens-list')).status).toBe(200);
  });

  it('requires the configured Origin on every non-GET and on the audit stream', async () => {
    const wrong = { ...adminHeaders(), Origin: 'https://evil.test.invalid' };
    const res = await doPost('clear-cache', {}, wrong);
    expect(res.status).toBe(403);
    expect(res.json).toEqual({ error: 'bad_origin' });
    expect((await doPost('clear-cache', {}, { Cookie: adminHeaders().Cookie! })).status).toBe(403);
    const ws = await accountStub().fetch('https://account.do/ws-admin', { headers: { Upgrade: 'websocket', ...wrong } });
    expect(ws.status).toBe(403);
    await ws.text();
    const noCookie = await accountStub().fetch('https://account.do/ws-admin', { headers: { Upgrade: 'websocket', Origin: TEST_ORIGIN } });
    expect(noCookie.status).toBe(401);
    await noCookie.text();
  });

  it('ignores a Cf-Access-Jwt-Assertion header everywhere', async () => {
    const forged = { 'Cf-Access-Jwt-Assertion': 'eyJhbGciOiJSUzI1NiJ9.e30.sig', Origin: TEST_ORIGIN };
    expect((await viaRouter('/api/admin/tokens', { headers: forged })).status).toBe(401);
    expect((await viaRouter('/api/admin/clear-cache', { method: 'POST', body: '{}', headers: forged })).status).toBe(401);
    expect((await doGet('tokens-list', forged)).status).toBe(401);
  });

  it('routes GET/PUT config and rotate-secret with the session, refusing them without', async () => {
    const put = (body: unknown, headers: Record<string, string> = adminHeaders()) => SELF.fetch(`${TEST_ORIGIN}/api/admin/config`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
    });
    const denied = await put({ cache_hit_notify: true }, {});
    expect(denied.status).toBe(401);
    await denied.text();
    const ok = await put({ cache_hit_notify: true, uv_policy: { default: 'required' } });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ cache_hit_notify: true, uv_policy: { default: 'required' } });
    // The deleted switch is a rejected input now, like any unknown key.
    const gone = await put({ cache_enabled: true });
    expect(gone.status).toBe(400);
    await gone.text();
    const bad = await put({ cache_hit_notify: true, origin: 'https://evil.test.invalid' });
    expect(bad.status).toBe(400);
    await bad.text();
    const got = await SELF.fetch(`${TEST_ORIGIN}/api/admin/config`, { headers: adminHeaders() });
    expect(await got.json()).toMatchObject({ cache_hit_notify: true, origin: TEST_ORIGIN, epoch: 1 });
    const rotate = await SELF.fetch(`${TEST_ORIGIN}/api/admin/rotate-secret`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...adminHeaders() }, body: JSON.stringify(await loginAssertion()),
    });
    expect(rotate.status).toBe(200);
    const { secret } = await rotate.json() as { secret: string };
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // The new value is shown once and never stored in the clear.
    await inDO(async ({ state }) => {
      expect(JSON.stringify([await state.storage.get('root:v1'), await state.storage.get('cfg:v1')])).not.toContain(secret);
    });
  });

  it('W-10: rotate-secret needs a verified Passkey assertion, not just the session', async () => {
    const wraps = () => inDO(h => h.state.storage.get<{ wraps: unknown[] }>('root:v1').then(r => r!.wraps.length));
    expect((await doPost('admin-rotate-secret', {})).status).toBe(400);
    const upOnly = await doPost('admin-rotate-secret', await loginAssertion(0x01));
    expect(upOnly.status).toBe(403);
    expect(upOnly.json).toEqual({ error: 'assertion_failed' });
    expect((await doPost('admin-rotate-secret', await loginAssertion(), {})).status).toBe(401);
    expect(await wraps()).toBe(1);
    const ok = await doPost('admin-rotate-secret', await loginAssertion());
    expect(ok.status).toBe(200);
    expect(await wraps()).toBe(2);
  });

  it('forwards the cookie through the router and no-stores every admin payload', async () => {
    const res = await viaRouter('/api/admin/tokens', { headers: adminHeaders() });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.json.tokens)).toBe(true);
    const resp = await SELF.fetch(`${TEST_ORIGIN}/api/admin/credentials`, { headers: adminHeaders() });
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(((await resp.json()) as { credentials: unknown[] }).credentials).toHaveLength(1);
  });
});

describe('credentials and sessions', () => {
  beforeEach(bootstrap);

  it('adds a credential without ending sessions, refuses a duplicate and the {v,c} envelope', async () => {
    const second = { ...TEST_CREDENTIAL_ENTRY, h: 'C'.repeat(43), i: 'c2Vjb25k', l: 'second' };
    expect((await doPost('admin-credentials-add', { entry: second, ...(await assertion()) })).status).toBe(200);
    expect((await doPost('admin-credentials-add', { entry: second, ...(await assertion()) })).status).toBe(409);
    expect((await doPost('admin-credentials-add', { entry: { v: 1, c: [second] }, ...(await assertion()) })).status).toBe(400);
    expect((await doPost('admin-credentials-add', { v: 1, c: [second], ...(await assertion()) })).status).toBe(400);
    const creds = await doGet('admin-credentials');
    expect(creds.json.credentials.map((c: { l: string }) => c.l)).toEqual(['test-passkey', 'second']);
    expect(creds.json.epoch).toBe(1);
  });

  it('W-3: the session alone cannot add or revoke a credential; the assertion must verify', async () => {
    const second = { ...TEST_CREDENTIAL_ENTRY, h: 'C'.repeat(43), i: 'c2Vjb25k', l: 'second' };
    const none = await doPost('admin-credentials-add', { entry: second });
    expect(none.status).toBe(400);
    const tampered = await assertion();
    for (const bad of [
      { ...tampered, signature_b64u: tampered.signature_b64u.replace(/^./, c => (c === 'A' ? 'B' : 'A')) },
      await assertion(0x01),                                            // presence only
      { ...(await assertion()), credential_id_b64u: b64uEnc(new Uint8Array(16).fill(3)) },
      { ...(await assertion()), challenge_id: 'bm9wZQ' },              // unknown challenge
    ]) {
      const res = await doPost('admin-credentials-add', { entry: second, ...bad });
      expect(res.status).toBe(403);
      expect(res.json).toEqual({ error: 'assertion_failed' });
    }
    // A consumed challenge does not answer twice.
    const a = await assertion();
    expect((await doPost('admin-credentials-add', { entry: second, ...a })).status).toBe(200);
    expect((await doPost('admin-credentials-revoke', { h: second.h, ...a })).status).toBe(403);
    expect((await doPost('admin-credentials-revoke', { h: second.h })).status).toBe(400);
    const creds = await doGet('admin-credentials');
    expect(creds.json.credentials).toHaveLength(2);
    expect(creds.json.epoch).toBe(1);
  });

  it('revoke bumps the epoch (all sessions end) and refuses the last credential', async () => {
    const second = { ...TEST_CREDENTIAL_ENTRY, h: 'C'.repeat(43), i: 'c2Vjb25k', l: 'second' };
    await doPost('admin-credentials-add', { entry: second, ...(await assertion()) });
    const before = adminHeaders();
    const revoked = await doPost('admin-credentials-revoke', { h: second.h, ...(await assertion()) });
    expect(revoked.status).toBe(204);
    expect((await doGet('tokens-list', before)).status).toBe(401);
    expect((await doPost('admin-credentials-revoke', { h: 'zzz', ...(await assertion()) }, before)).status).toBe(401);

    const fresh = await login();
    expect(fresh.status).toBe(204);
    const h = cookieHeader(sessionCookieValue(fresh.cookie)!);
    const last = await doPost('admin-credentials-revoke', { h: TEST_CREDENTIAL_ENTRY.h, ...(await assertion()) }, h);
    expect(last.status).toBe(409);
    expect(last.json).toEqual({ error: 'last_credential' });
    expect((await doPost('admin-credentials-revoke', { h: 'unknown', ...(await assertion()) }, h)).status).toBe(404);
    expect((await doGet('admin-credentials', h)).json.epoch).toBe(2);
  });

  // W-4: a stream minted under an earlier epoch or past its session's exp
  // gets nothing more — it is closed by the revocation itself, and any socket
  // that slipped through is dropped before a broadcast reaches it.
  it('closes admin audit streams on epoch bump and skips stale ones on broadcast', async () => {
    const open = async () => {
      const res = await accountStub().fetch('https://account.do/ws-admin', { headers: { Upgrade: 'websocket', ...adminHeaders() } });
      expect(res.status).toBe(101);
      const ws = res.webSocket!;
      ws.accept();
      const closed = new Promise<number>(resolve => ws.addEventListener('close', ev => resolve(ev.code)));
      return { ws, closed };
    };
    const a = await open();
    const stale = await open();
    const expired = await open();
    await inDO(({ inst, state }) => {
      const [x, y] = state.getWebSockets('admin').slice(1);
      // Attachments as an older epoch / a lapsed session would leave them.
      x!.serializeAttachment({ exp: Math.floor(Date.now() / 1000) + 3600, epoch: inst.admin.current.epoch - 1 });
      y!.serializeAttachment({ exp: Math.floor(Date.now() / 1000) - 1, epoch: inst.admin.current.epoch });
    });
    await inDO(({ inst }) => {
      expect(inst.liveAdminSockets()).toHaveLength(1);
      inst.audit.broadcastRow('nothing', 'update');
    });
    expect(await stale.closed).toBe(4001);
    expect(await expired.closed).toBe(4001);
    expect((await doPost('admin-sessions-revoke', {})).status).toBe(204);
    expect(await a.closed).toBe(4001);
    await inDO(({ inst }) => expect(inst.liveAdminSockets()).toHaveLength(0));
  });

  it('logout clears only the browser copy; sessions-revoke ends every session', async () => {
    const a = adminHeaders();
    const out = await doPost('admin-logout', {});
    expect(out.status).toBe(204);
    expect((await doGet('tokens-list', a)).status).toBe(200); // a copied cookie still works
    const b = await login();
    expect((await doPost('admin-sessions-revoke', {}, cookieHeader(sessionCookieValue(b.cookie)!))).status).toBe(204);
    expect((await doGet('tokens-list', a)).status).toBe(401);
    expect((await doGet('tokens-list', cookieHeader(sessionCookieValue(b.cookie)!))).status).toBe(401);
  });
});
