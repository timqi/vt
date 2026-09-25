// Public route body limits run in workerd, including streams without a truthful
// Content-Length. Import the router directly to observe cancellation of the body.
// The edge checks header shape and caps; the MAC is compared in the DO against
// the secret of a live token, so the daemon-route cases below enroll one.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import { b64uEnc, hmacSha256 } from '../src/crypto';
import { makeMeta, bootstrap, liveTokenId, hostSecret, inDO, auditRows } from './do_helpers';

const CAP = 256 * 1024;
let TOKEN_ID = '';
let KEY = new Uint8Array(32);
beforeEach(async () => {
  await bootstrap();
  TOKEN_ID = await liveTokenId();
  KEY = await hostSecret(TOKEN_ID);
});
const encoder = new TextEncoder();
const headers = () => ({ Authorization: `VT-HMAC ${b64uEnc(new Uint8Array(32))}`, 'VT-Token-Id': TOKEN_ID });
const routes = [
  ['/api/challenge', CAP],
  ['/api/dek-cache', CAP],
  ['/api/audit-ingest', 64 * 1024],
  ['/api/approve', CAP],
  ['/api/reject', CAP],
] as const;

async function post(path: string, body: BodyInit, extraHeaders: Record<string, string | undefined> = {}) {
  const requestHeaders = new Headers(headers());
  for (const [name, value] of Object.entries(extraHeaders)) {
    if (value === undefined) requestHeaders.delete(name);
    else requestHeaders.set(name, value);
  }
  const response = await app.fetch(new Request(`https://vt.test.invalid${path}`, {
    method: 'POST', body, headers: requestHeaders,
  }), env);
  const text = await response.text();
  return { status: response.status, text };
}

describe.each(routes)('%s body limit', (path, limit) => {
  it('refuses an oversized declared length without reading the stream', async () => {
    let reads = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull() { reads++; throw new Error('body must not be read'); },
    }, { highWaterMark: 0 });
    const response = await post(path, stream, { 'Content-Length': String(limit + 1) });
    expect(response.status).toBe(413);
    expect(reads).toBe(0);
  });

  it.each([undefined, '1'])('cancels at the streamed limit with Content-Length=%s', async (length) => {
    let reads = 0;
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        reads++;
        if (reads === 1) controller.enqueue(new Uint8Array(limit));
        else if (reads === 2) controller.enqueue(new Uint8Array(1));
        else controller.error(new Error('oversized stream must not be drained'));
      },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 });
    const response = await post(path, stream, length ? { 'Content-Length': length } : {});
    expect(response.status).toBe(413);
    expect(reads).toBe(2);
    expect(cancelled).toBe(true);
  });
});

describe.each(['/api/challenge', '/api/dek-cache'])('%s HMAC boundary', (path) => {
  it.each([
    [undefined, 'missing auth'],
    ['', 'missing auth'],
    ['Bearer synthetic', 'missing auth'],
    ['VT-HMAC !', 'hmac length'],
    [`VT-HMAC ${b64uEnc(new Uint8Array(31))}`, 'hmac length'],
  ])('rejects auth %s before reading or checking the declared body size', async (auth, text) => {
    let reads = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull() { reads++; throw new Error('body must not be read'); },
    }, { highWaterMark: 0 });
    expect(await post(path, stream, {
      Authorization: auth, 'Content-Length': String(CAP + 1),
    })).toEqual({ status: 401, text });
    expect(reads).toBe(0);
  });

  it('refuses a request without VT-Token-Id before reading the body, with the enroll hint', async () => {
    // The bare master is no longer a key: signing with it and omitting the
    // header is rejected structurally, the same 401 shape a dead token gets.
    let reads = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull() { reads++; throw new Error('body must not be read'); },
    }, { highWaterMark: 0 });
    const res = await post(path, stream, { 'VT-Token-Id': undefined, 'Content-Length': String(CAP + 1) });
    expect(res.status).toBe(401);
    expect(JSON.parse(res.text)).toMatchObject({ error: 'token_missing' });
    expect(reads).toBe(0);
    const body = encoder.encode('{}');
    const tag = await hmacSha256(KEY, body);
    const signed = await post(path, body, { 'VT-Token-Id': undefined, Authorization: `VT-HMAC ${b64uEnc(tag)}` });
    expect(signed.status).toBe(401);
    expect(JSON.parse(signed.text)).toMatchObject({ error: 'token_missing' });
  });

  it('reports the JSON error for an empty or truncated body, whatever the MAC', async () => {
    for (const text of ['', '{']) {
      const tag = await hmacSha256(KEY, encoder.encode(text));
      expect(await post(path, text, { Authorization: `VT-HMAC ${b64uEnc(tag)}` }))
        .toEqual({ status: 400, text: 'json parse error' });
      expect(await post(path, text)).toEqual({ status: 400, text: 'json parse error' });
    }
  });

  it('accepts exactly the cap for parsing, but rejects one extra byte first', async () => {
    expect((await post(path, new Uint8Array(CAP))).status).toBe(400);
    expect((await post(path, new Uint8Array(CAP + 1))).status).toBe(413);
  });

  it('authenticates the original bytes, including JSON whitespace across chunks', async () => {
    const bytes = encoder.encode('\n  ' + JSON.stringify({
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)),
      timestamp_ms: Date.now(), salts_b64u: [b64uEnc(new Uint8Array(16).fill(4))], meta: makeMeta(),
    }) + '\t\n');
    const tag = await hmacSha256(KEY, bytes);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes.slice(0, 13));
        controller.enqueue(bytes.slice(13));
        controller.close();
      },
    });
    const result = await post(path, stream, { Authorization: `VT-HMAC ${b64uEnc(tag)}` });
    // The DO compared the MAC over exactly these bytes, padding included.
    expect(result.status).toBe(200);
    expect(JSON.parse(result.text)).toEqual(path === '/api/challenge'
      ? expect.objectContaining({ approve_url: expect.stringMatching(/^https:\/\/vt\.test\.invalid\/a\//) })
      : { miss: true });
  });

  it('rejects changes to bytes covered by an otherwise valid HMAC in the DO, storing nothing', async () => {
    const body = (reason: string) => JSON.stringify({
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)),
      timestamp_ms: Date.now(), salts_b64u: [], meta: makeMeta({ reason }),
    });
    const tag = await hmacSha256(KEY, encoder.encode(body('a')));
    expect(await post(path, body('b'), {
      Authorization: `VT-HMAC ${b64uEnc(tag)}`,
    })).toEqual({ status: 401, text: 'hmac mismatch' });
    expect(await inDO(h => h.state.storage.list({ prefix: 'ch:' }).then(m => m.size))).toBe(0);
  });

  // The edge, not the client, names the source IP, and the challenge's UV level
  // is the DO's to decide: observed on the op the router forwards.
  it('forces meta.ip from CF-Connecting-IP and leaves the challenge uv to the DO', async () => {
    const body = {
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)),
      timestamp_ms: Date.now(), salts_b64u: [], meta: makeMeta({ ip: '198.51.100.99' }),
    };
    const bytes = encoder.encode(JSON.stringify(body));
    const tag = await hmacSha256(KEY, bytes);
    const fetch = vi.fn(async (_url: string, _init: RequestInit) => Response.json(
      path === '/api/challenge' ? { meta: body.meta, approve_url: 'https://vt.test.invalid/a/x' } : { miss: true }));
    const account = { idFromName: () => 'synthetic-account-id', get: () => ({ fetch }) };
    const response = await app.fetch(new Request(`https://vt.test.invalid${path}`, {
      method: 'POST', body: bytes,
      headers: { Authorization: `VT-HMAC ${b64uEnc(tag)}`, 'VT-Token-Id': TOKEN_ID, 'CF-Connecting-IP': '203.0.113.42' },
    }), { ...env, ACCOUNT: account });
    expect(response.status).toBe(200);
    await response.text();
    const forwarded = JSON.parse(fetch.mock.calls[0]![1].body as string);
    if (path === '/api/challenge') {
      expect(forwarded.challenge.meta.ip).toBe('203.0.113.42');
      expect(forwarded.challenge).not.toHaveProperty('uv');
    } else {
      expect(forwarded.meta.ip).toBe('203.0.113.42');
    }
  });
});

// Per route, not just in inReplayWindow: a correctly signed body replayed after
// the five-minute window is refused at the edge and reaches no DO effect.
describe('replay window', () => {
  const bodies: Record<string, (ts: number) => unknown> = {
    '/api/challenge': ts => ({
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)), timestamp_ms: ts, salts_b64u: [], meta: makeMeta(),
    }),
    '/api/dek-cache': ts => ({
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)), timestamp_ms: ts,
      salts_b64u: [b64uEnc(new Uint8Array(16).fill(4))], meta: makeMeta(),
    }),
    '/api/audit-ingest': ts => ({
      timestamp_ms: ts, agent_id: `t:${TOKEN_ID}`, hostname: 'testbox',
      entry: { op_kind: 'sign', outcome: 'approved', salts: 0, latency_ms: 1, ts_ms: ts,
               token_id: `a_t:${TOKEN_ID}_${ts}`, meta: { op_kind: 'sign' } },
    }),
  };
  const signed = async (path: string, ts: number) => {
    const bytes = encoder.encode(JSON.stringify(bodies[path]!(ts)));
    return post(path, bytes, { Authorization: `VT-HMAC ${b64uEnc(await hmacSha256(KEY, bytes))}` });
  };
  const effects = () => inDO(async h => ({
    ch: (await h.state.storage.list({ prefix: 'ch:' })).size,
    audit: (await auditRows(h)).length,
    token: h.state.storage.sql.exec('SELECT last_used_ms FROM host_token').toArray(),
  }));

  it.each(Object.keys(bodies))('%s refuses a validly signed body six minutes old', async (path) => {
    const before = await effects();
    expect(await signed(path, Date.now() - 6 * 60_000)).toEqual({ status: 400, text: 'timestamp skew' });
    expect(await effects()).toEqual(before);
    // The same signing inside the window is accepted, so only the window refused.
    expect((await signed(path, Date.now())).status).toBe(200);
  });
});
