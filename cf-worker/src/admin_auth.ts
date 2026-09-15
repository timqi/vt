// Admin session cookie (docs/worker-slim.md#sessions) — the pure half. Minting
// and verification take the session key as bytes so this file has no storage,
// no Env and no Worker types; account_admin.ts derives K_sess from the root
// key and calls in here.
//
//   __Host-vt_admin = 1.<exp_s>.<epoch>.<nonce_b64u>.<mac_b64u>
//   mac = HMAC-SHA256(K_sess, "vt-admin-session-v1|" + exp_s + "|" + epoch + "|" + nonce_b64u)
//
// `exp_s` is absolute (no sliding); `epoch` is the config's, so one bump ends
// every session at once. A copied cookie lives to exp_s or the next bump —
// logout only clears the browser's copy.

import { b64uDec, b64uEnc, ctEq, hmacSha256, randomBytes } from './crypto';

export const SESSION_COOKIE = '__Host-vt_admin';
export const SESSION_TTL_S = 8 * 60 * 60;
const SESSION_INFO = 'vt-admin-session-v1';
const VALUE_RE = /^1\.(\d{1,12})\.(\d{1,9})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;

async function mac(kSess: Uint8Array, expS: number, epoch: number, nonce: string): Promise<Uint8Array> {
  return hmacSha256(kSess, new TextEncoder().encode(`${SESSION_INFO}|${expS}|${epoch}|${nonce}`));
}

export async function mintSession(kSess: Uint8Array, epoch: number, nowMs: number): Promise<{ value: string; exp_s: number }> {
  const expS = Math.floor(nowMs / 1000) + SESSION_TTL_S;
  const nonce = b64uEnc(randomBytes(16));
  const tag = await mac(kSess, expS, epoch, nonce);
  return { value: `1.${expS}.${epoch}.${nonce}.${b64uEnc(tag)}`, exp_s: expS };
}

/** `exp_s` of a valid session, null for anything else (shape, MAC, expiry,
 *  epoch). The MAC is checked before the cheap claims so every failure costs
 *  the same. */
export async function verifySession(kSess: Uint8Array, value: string, epoch: number, nowMs: number): Promise<number | null> {
  const m = VALUE_RE.exec(value);
  if (!m) return null;
  const expS = Number(m[1]);
  const claimedEpoch = Number(m[2]);
  if (!ctEq(b64uDec(m[4]!), await mac(kSess, expS, claimedEpoch, m[3]!))) return null;
  if (Math.floor(nowMs / 1000) >= expS) return null;
  if (claimedEpoch !== epoch) return null;
  return expS;
}

/** The `Set-Cookie` header value; `null` clears the browser copy. */
export function sessionSetCookie(value: string | null): string {
  const attrs = 'Path=/; Secure; HttpOnly; SameSite=Strict';
  return value === null
    ? `${SESSION_COOKIE}=; ${attrs}; Max-Age=0`
    : `${SESSION_COOKIE}=${value}; ${attrs}; Max-Age=${SESSION_TTL_S}`;
}

/** Our cookie out of a `Cookie` header; null when absent. */
export function sessionCookieValue(cookieHeader: string | null | undefined): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === SESSION_COOKIE) return part.slice(eq + 1).trim();
  }
  return null;
}
