// Public route body limits run in workerd, including streams without a truthful
// Content-Length. Import the router directly to observe cancellation of the body.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import { b64uEnc, hmacSha256 } from '../src/crypto';
import { deriveHostTokenSecret } from '../src/host_token';
import { makeMeta, bootstrap } from './do_helpers';

beforeEach(bootstrap);

const CAP = 256 * 1024;
const MASTER = 'throwaway-request-limit-test-key';
const TOKEN_ID = 'limitsTokenId000';
// The edge verifies statelessly, so a well-formed token_id and its derived
// secret are enough here; liveness is the DO's job (host_token suite).
const KEY = await deriveHostTokenSecret(MASTER, TOKEN_ID);
const encoder = new TextEncoder();
const headers = { Authorization: `VT-HMAC ${b64uEnc(new Uint8Array(32))}`, 'VT-Token-Id': TOKEN_ID };
const routes = [
  ['/api/challenge', CAP],
  ['/api/dek-cache', CAP],
  ['/api/audit-ingest', 64 * 1024],
  ['/api/approve', CAP],
  ['/api/reject', CAP],
] as const;

async function post(path: string, body: BodyInit, extraHeaders: Record<string, string | undefined> = {}) {
  const requestHeaders = new Headers(headers);
  for (const [name, value] of Object.entries(extraHeaders)) {
    if (value === undefined) requestHeaders.delete(name);
    else requestHeaders.set(name, value);
  }
  const response = await app.fetch(new Request(`https://vt.test.invalid${path}`, {
    method: 'POST', body, headers: requestHeaders,
  }), { ...env, VT_AUTH_CF: MASTER });
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

  it('rejects an incorrect HMAC before attempting JSON parsing', async () => {
    expect(await post(path, '{')).toEqual({ status: 401, text: 'hmac mismatch' });
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
    const tag = await hmacSha256(encoder.encode(MASTER), body);
    const signed = await post(path, body, { 'VT-Token-Id': undefined, Authorization: `VT-HMAC ${b64uEnc(tag)}` });
    expect(signed.status).toBe(401);
    expect(JSON.parse(signed.text)).toMatchObject({ error: 'token_missing' });
  });

  it('preserves the JSON error after a valid HMAC, including an empty body', async () => {
    for (const text of ['', '{']) {
      const tag = await hmacSha256(KEY, encoder.encode(text));
      expect(await post(path, text, { Authorization: `VT-HMAC ${b64uEnc(tag)}` }))
        .toEqual({ status: 400, text: 'json parse error' });
    }
  });

  it('accepts exactly the cap for HMAC processing, but rejects one extra byte first', async () => {
    expect((await post(path, new Uint8Array(CAP))).status).toBe(401);
    expect((await post(path, new Uint8Array(CAP + 1))).status).toBe(413);
  });

  it('authenticates the original bytes, including JSON whitespace across chunks', async () => {
    const bytes = encoder.encode('\n  ' + JSON.stringify({
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)),
      timestamp_ms: 0, salts_b64u: [], meta: makeMeta(),
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
    // A deliberate stale timestamp reaches the post-HMAC validation without
    // creating a ceremony or retaining an unrelated DO response stream.
    expect(result.status).toBe(400);
    expect(result.text).toBe('timestamp skew');
  });

  it('rejects changes to bytes covered by an otherwise valid HMAC', async () => {
    const bytes = encoder.encode('{"timestamp_ms":0}');
    const tag = await hmacSha256(KEY, bytes);
    expect(await post(path, encoder.encode('{"timestamp_ms":1}'), {
      Authorization: `VT-HMAC ${b64uEnc(tag)}`,
    })).toEqual({ status: 401, text: 'hmac mismatch' });
  });

  it('passes valid authenticated requests to the route-specific DO operation', async () => {
    const body = {
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)),
      timestamp_ms: Date.now(), salts_b64u: [], meta: makeMeta(),
    };
    const bytes = encoder.encode(JSON.stringify(body));
    const tag = await hmacSha256(KEY, bytes);
    const fetch = vi.fn(async (_url: string, _init: RequestInit) => Response.json({ miss: true }));
    const account = {
      idFromName: vi.fn(() => 'synthetic-account-id'),
      get: vi.fn(() => ({ fetch })),
    };
    const response = await app.fetch(new Request(`https://vt.test.invalid${path}`, {
      method: 'POST', body: bytes,
      headers: { Authorization: `VT-HMAC ${b64uEnc(tag)}`, 'VT-Token-Id': TOKEN_ID, 'CF-Connecting-IP': '203.0.113.42' },
    }), { ...env, VT_AUTH_CF: MASTER, ACCOUNT: account });
    expect(response.status).toBe(200);
    const result = await response.json() as Record<string, unknown>;
    expect(fetch).toHaveBeenCalledOnce();
    expect(account.idFromName).toHaveBeenCalledWith('account');
    const [url, init] = fetch.mock.calls[0]!;
    expect(init.method).toBe('POST');
    const forwarded = JSON.parse(init.body as string);
    if (path === '/api/challenge') {
      expect(url).toBe('https://account.do/op/create');
      expect(forwarded.token_id).toBe(TOKEN_ID);
      expect(forwarded.challenge).toMatchObject({
        daemon_pubkey_b64u: body.daemon_pubkey_b64u, timestamp_ms: body.timestamp_ms,
        salts_b64u: [], status: 'pending', meta: { ip: '203.0.113.42' },
      });
      expect(result.approve_token).toBe(forwarded.challenge.approve_token);
      expect(result.poll_token).toBe(forwarded.challenge.poll_token);
    } else {
      expect(url).toBe('https://account.do/op/dek-cache');
      expect(forwarded).toMatchObject({
        daemon_pubkey_b64u: body.daemon_pubkey_b64u, salts_b64u: [], meta: { ip: '203.0.113.42' }, token_id: TOKEN_ID,
      });
      expect(result).toEqual({ miss: true });
    }
  });
});
