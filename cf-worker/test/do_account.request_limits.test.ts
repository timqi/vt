// Public route body limits run in workerd, including streams without a truthful
// Content-Length. Import the router directly to observe cancellation of the body.
import { describe, it, expect } from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import { b64uEnc, hmacSha256 } from '../src/crypto';
import { makeMeta } from './do_helpers';

const CAP = 256 * 1024;
const KEY = 'throwaway-request-limit-test-key';
const encoder = new TextEncoder();
const headers = { Authorization: `VT-HMAC ${b64uEnc(new Uint8Array(32))}` };
const routes = [
  ['/api/challenge', CAP],
  ['/api/dek-cache', CAP],
  ['/api/audit-ingest', 64 * 1024],
  ['/api/approve', CAP],
  ['/api/reject', CAP],
] as const;

async function post(path: string, body: BodyInit, extraHeaders = {}) {
  const response = await app.fetch(new Request(`https://vt.test.invalid${path}`, {
    method: 'POST', body, headers: { ...headers, ...extraHeaders },
  }), { ...env, VT_AUTH_CF: KEY });
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
  it('accepts exactly the cap for HMAC processing, but rejects one extra byte first', async () => {
    expect((await post(path, new Uint8Array(CAP))).status).toBe(401);
    expect((await post(path, new Uint8Array(CAP + 1))).status).toBe(413);
  });

  it('authenticates the original bytes, including JSON whitespace across chunks', async () => {
    const bytes = encoder.encode('\n  ' + JSON.stringify({
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)),
      timestamp_ms: 0, salts_b64u: [], meta: makeMeta(),
    }) + '\t\n');
    const tag = await hmacSha256(encoder.encode(KEY), bytes);
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
});
