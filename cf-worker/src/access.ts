// Cloudflare Access (Zero Trust) JWT verification middleware for the admin
// surface (/<ADMIN_SEG>/*; ADMIN_SEG is a constant in index.ts).
//
// SECURITY MODEL: Cloudflare does NOT strip a client-supplied
// `Cf-Access-Jwt-Assertion` header on routes its Access Application does not
// cover. An attacker can therefore forge that header against /<ADMIN_SEG>/*. The
// JWT signature verification below is the LOAD-BEARING primary defense, not a
// "defense in depth" nicety. We fail closed on every uncertainty.
//
// Verification order (each failure → opaque 403):
//   1. ACCESS_TEAM_DOMAIN / ACCESS_AUD configured (else fail closed)
//   2. header present
//   3. JWT well-formed (3 segments), header.alg === "RS256" pinned BEFORE any
//      key lookup, header.kid present
//   4. JWKS key selected by kid (refetch-once on unknown kid, throttled)
//   5. RS256 signature verified with the fixed algorithm (token alg ignored)
//   6. aud (array) includes ACCESS_AUD; iss === https://<team>; exp strict; nbf/iat skew
//
// Worker-side admin events (auth_failed / access) are written to CF Logs only
// (via log.ts) — never to the singleton AccountDO — to avoid serialized
// write contention with live approval ceremonies.

import type { MiddlewareHandler } from 'hono';
import { Env } from './types';
import { b64uDec } from './crypto';
import { log } from './log';

interface Jwk { kid?: string; kty?: string; n?: string; e?: string; }
interface Jwks { keys?: Jwk[] }

/** Context variables requireAccess sets after a successful verification, so a
 *  gated handler can bind work to the caller's authenticated session. `accessExp`
 *  (JWT exp, epoch seconds) lets the audit-stream WebSocket self-close when the
 *  Access session ends — a hibernating socket must not outlive its auth. */
export interface AccessVars {
  accessExp: number;
  accessEmail: string;
}

interface JwtHeader { alg?: string; kid?: string; typ?: string }
interface JwtPayload {
  aud?: string | string[];
  iss?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  email?: string;
}

const JWKS_TTL_MS = 60 * 60 * 1000;        // cache JWKS for 1h per isolate
const JWKS_MIN_REFETCH_MS = 60 * 1000;     // throttle forced refetches (anti-amplification)
const CLOCK_SKEW_SEC = 60;
const AUTH_FAIL_LOG_THROTTLE_MS = 5000;    // coalesce forged-token log spam

// Per-isolate JWKS cache.
let jwksCache: { keys: Map<string, CryptoKey>; fetchedAt: number } | null = null;
let lastFetchAttempt = 0;
let lastAuthFailLog = 0;

function logAuthFail(reason: string, ip: string, path: string): void {
  const now = Date.now();
  if (now - lastAuthFailLog < AUTH_FAIL_LOG_THROTTLE_MS) return;
  lastAuthFailLog = now;
  log('admin.auth_failed', { reason, ip, path });
}

async function importRsaKey(jwk: Jwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
}

// Load JWKS keyed by kid. `force` re-fetches even within TTL (used once on an
// unknown kid to absorb Cloudflare key rotation), but is throttled so forged
// tokens with random kids cannot drive unbounded upstream fetches.
async function loadJwks(teamDomain: string, force: boolean): Promise<Map<string, CryptoKey>> {
  const now = Date.now();
  if (!force && jwksCache && now - jwksCache.fetchedAt < JWKS_TTL_MS) {
    return jwksCache.keys;
  }
  if (force && jwksCache && now - lastFetchAttempt < JWKS_MIN_REFETCH_MS) {
    return jwksCache.keys; // throttled: reuse what we have
  }
  lastFetchAttempt = now;
  const resp = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!resp.ok) throw new Error(`jwks http ${resp.status}`);
  const jwks = (await resp.json()) as Jwks;
  const keys = new Map<string, CryptoKey>();
  for (const k of jwks.keys ?? []) {
    if (k.kty === 'RSA' && k.kid && k.n && k.e) {
      try { keys.set(k.kid, await importRsaKey(k)); } catch { /* skip bad key */ }
    }
  }
  jwksCache = { keys, fetchedAt: now };
  return keys;
}

function decodeSegment(seg: string): Uint8Array {
  // JWT segments are unpadded base64url; b64uDec tolerates that.
  return b64uDec(seg);
}

export const requireAccess: MiddlewareHandler<{ Bindings: Env; Variables: AccessVars }> = async (c, next) => {
  const ip = c.req.header('CF-Connecting-IP') ?? '';
  const path = new URL(c.req.url).pathname;
  const deny = (reason: string): Response => {
    logAuthFail(reason, ip, path);
    return c.text('forbidden', 403);
  };

  const teamDomain = c.env.ACCESS_TEAM_DOMAIN;
  const aud = c.env.ACCESS_AUD;
  if (!teamDomain || !aud) return deny('config_missing');

  const token = c.req.header('Cf-Access-Jwt-Assertion');
  if (!token) return deny('no_token');

  const parts = token.split('.');
  if (parts.length !== 3) return deny('malformed');

  // Header: pin alg=RS256 BEFORE any key work; require kid.
  let header: JwtHeader;
  try { header = JSON.parse(new TextDecoder().decode(decodeSegment(parts[0]!))); }
  catch { return deny('bad_header'); }
  if (header.alg !== 'RS256') return deny('alg');
  if (!header.kid) return deny('no_kid');

  // Select JWKS key by kid; refetch once (throttled) on unknown kid.
  let key: CryptoKey | undefined;
  try {
    let keys = await loadJwks(teamDomain, false);
    key = keys.get(header.kid);
    if (!key) {
      keys = await loadJwks(teamDomain, true);
      key = keys.get(header.kid);
    }
  } catch {
    return deny('jwks_fetch'); // fail closed on fetch/parse error
  }
  if (!key) return deny('unknown_kid');

  // Verify signature with the FIXED algorithm (token alg is ignored).
  let sig: Uint8Array;
  try { sig = decodeSegment(parts[2]!); } catch { return deny('bad_sig'); }
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  let ok: boolean;
  try {
    ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, signingInput);
  } catch {
    return deny('verify_error');
  }
  if (!ok) return deny('sig');

  // Claims.
  let payload: JwtPayload;
  try { payload = JSON.parse(new TextDecoder().decode(decodeSegment(parts[1]!))); }
  catch { return deny('bad_payload'); }

  // Cloudflare Access always issues `aud` as an array; a non-array claim is
  // malformed/forged → fail closed (no scalar fallback).
  const audOk = Array.isArray(payload.aud) && payload.aud.includes(aud);
  if (!audOk) return deny('aud');
  if (payload.iss !== `https://${teamDomain}`) return deny('iss');

  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || nowSec >= payload.exp) return deny('exp');
  if (typeof payload.nbf === 'number' && nowSec + CLOCK_SKEW_SEC < payload.nbf) return deny('nbf');
  if (typeof payload.iat === 'number' && payload.iat > nowSec + CLOCK_SKEW_SEC) return deny('iat');

  const email = typeof payload.email === 'string' ? payload.email : '';
  // Expose the verified exp/email so a gated handler (e.g. the audit-stream WS)
  // can bind a long-lived resource to this authenticated session. exp is a
  // verified claim (checked above), safe to trust downstream.
  c.set('accessExp', payload.exp);
  c.set('accessEmail', email);
  log('admin.access', { email, path });
  await next();
};
