// Host tokens end to end: an unauthenticated enroll request becomes a Passkey
// ceremony, approving it mints a token, and that token then authenticates
// /api/challenge and /api/dek-cache through the real router (HMAC keyed on the
// derived secret) with the DO checking liveness and sliding expiry. Revocation
// and the rate-limit / pending-cap guards on the public enroll route are
// covered here too — they are what makes the unauthenticated route safe.

import { describe, it, expect, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import { b64uEnc, hmacSha256 } from '../src/crypto';
import { deriveHostTokenSecret, HOST_TOKEN_TTL_MS } from '../src/host_token';
import type { Challenge, HostTokenRow } from '../src/types';
import { inDO, setDoVar, doPost, doGet, approve, reject, makeMeta, auditRow } from './do_helpers';

const MASTER = 'throwaway-host-token-test-master';
const ORIGIN = 'https://vt.test.invalid';
const IP = '203.0.113.9';

type Env = Record<string, unknown> & { ENROLL_LIMITER?: unknown };
const routerEnv = (): Env => ({ ...(env as unknown as Env), VT_AUTH_CF: MASTER });

// The DO derives token secrets from ITS env's master, which is a different
// object from the one the router is invoked with.
beforeEach(async () => { await setDoVar('VT_AUTH_CF', MASTER); });

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

/** Sign a daemon body the way src/cf.rs does for a `vt1.` token. */
async function tokenHeaders(tokenId: string, body: unknown, master = MASTER) {
  const raw = new TextEncoder().encode(JSON.stringify(body));
  const mac = await hmacSha256(await deriveHostTokenSecret(master, tokenId), raw);
  return { Authorization: `VT-HMAC ${b64uEnc(mac)}`, 'VT-Token-Id': tokenId };
}

async function legacyHeaders(body: unknown) {
  const raw = new TextEncoder().encode(JSON.stringify(body));
  const mac = await hmacSha256(new TextEncoder().encode(MASTER), raw);
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
  expect(ws.host_token).toBe(`vt1.${tokenId}.${b64uEnc(await deriveHostTokenSecret(MASTER, tokenId))}`);
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
    delete e.ENROLL_LIMITER;
    expect((await post('/api/enroll', { host: 'h', user: 'u', timestamp_ms: Date.now() }, {}, e)).status).toBe(503);
    for (let i = 0; i < 5; i++) {
      expect((await post('/api/enroll', { host: `h${i}`, user: 'u', timestamp_ms: Date.now() })).status).toBe(200);
    }
    expect((await post('/api/enroll', { host: 'h6', user: 'u', timestamp_ms: Date.now() })).status).toBe(429);
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

  it('re-applies the by_host UV rule against the verified host', async () => {
    const { tokenId } = await enrollApproved('prod-db', 'qiqi');
    await setDoVar('APPROVAL_UV_JSON', '{"default":"discouraged","by_host":{"prod-db":"required"}}');
    try {
      const body = challengeBody();
      const res = await post('/api/challenge', body, await tokenHeaders(tokenId, body));
      expect(res.status).toBe(200);
      const ch = await inDO(h => h.state.storage.get<Challenge>(`ch:${res.json.approve_token}`));
      // The Worker saw host='spoofed' (discouraged); the record says prod-db.
      expect(ch!.uv).toBe('required');
    } finally {
      await setDoVar('APPROVAL_UV_JSON', '');
    }
  });

  it('refuses a wrong secret, an unknown id, and a malformed id at the edge', async () => {
    const { tokenId } = await enrollApproved();
    const body = challengeBody();
    const wrong = await post('/api/challenge', body, await tokenHeaders(tokenId, body, 'other-master'));
    expect(wrong.status).toBe(401);
    expect(wrong.text).toBe('hmac mismatch');
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

  it('still accepts the bare master during migration, keeping client-claimed host/user', async () => {
    const body = challengeBody();
    const res = await post('/api/challenge', body, await legacyHeaders(body));
    expect(res.status).toBe(200);
    const ch = await inDO(h => h.state.storage.get<Challenge>(`ch:${res.json.approve_token}`));
    expect(ch!.meta.host).toBe('spoofed');
    expect(ch!.meta.ip_prev).toBeUndefined();
    expect(ch!.token_id).toBeUndefined();
    expect((await doGet(`page?approve_token=${res.json.approve_token}`)).json.host_verified).toBe(false);
  });

  it('drops tty / ppid / ssh_client from the stored meta', async () => {
    const body = challengeBody({ meta: { ...makeMeta(), tty: '/dev/pts/1', ppid: 7, ssh_client: '10.0.0.1 1 22' } });
    const res = await post('/api/challenge', body, await legacyHeaders(body));
    const ch = await inDO(h => h.state.storage.get<Challenge>(`ch:${res.json.approve_token}`));
    expect(Object.keys(ch!.meta).sort()).toEqual(['command', 'host', 'ip', 'op_kind', 'ppid_cmd', 'pwd', 'reason', 'user']);
  });
});

describe('audit ingest keyed on a host token', () => {
  async function ingest(agentId: string, key: Uint8Array) {
    const body = {
      timestamp_ms: Date.now(), agent_id: agentId, hostname: 'mac',
      entry: { op_kind: 'sign', outcome: 'approved', salts: 0, latency_ms: 1, ts_ms: Date.now(),
               token_id: `a_${agentId}_${Math.random()}`, meta: { op_kind: 'sign', host: 'mac', user: 'qiqi' } },
    };
    const raw = new TextEncoder().encode(JSON.stringify(body));
    const mac = await hmacSha256(key, raw);
    return post('/api/audit-ingest', body, { Authorization: `VT-HMAC ${b64uEnc(mac)}` });
  }

  it('accepts a live token and refuses a revoked one', async () => {
    const { tokenId } = await enrollApproved('mac', 'qiqi');
    const key = await deriveHostTokenSecret(MASTER, tokenId);
    expect((await ingest(`t:${tokenId}`, key)).status).toBe(200);
    const before = (await tokenRow(tokenId))!;
    // A background push is not a use: expiry did not slide.
    expect(before.last_used_ms).toBe(before.created_ms);
    await inDO(h => h.inst.tokens.revoke(tokenId, Date.now()));
    expect((await ingest(`t:${tokenId}`, key)).status).toBe(401);
    expect((await ingest('t:short', key)).status).toBe(401);
  });
});

describe('admin token inventory', () => {
  it('lists without secrets and revokes idempotently', async () => {
    const { tokenId } = await enrollApproved('devbox', 'qiqi');
    const list = await doGet('tokens-list');
    expect(list.status).toBe(200);
    const row = list.json.tokens.find((t: HostTokenRow) => t.token_id === tokenId);
    expect(row.host).toBe('devbox');
    expect(JSON.stringify(list.json)).not.toContain(b64uEnc(await deriveHostTokenSecret(MASTER, tokenId)));
    expect((await doPost('tokens-revoke', { token_id: tokenId })).json).toEqual({ revoked: true });
    expect((await doPost('tokens-revoke', { token_id: tokenId })).json).toEqual({ revoked: false });
    expect((await doPost('tokens-revoke', { token_id: '' })).status).toBe(400);
  });
});
