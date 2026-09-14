// Web Push on crypto.subtle alone: RFC 8291 encryption (ECDH P-256 → HKDF →
// one aes128gcm record), RFC 8292 VAPID, RFC 8030 delivery. Every step has a
// published vector (test/webpush.test.ts); a dependency here would be code
// inside the process that holds the VAPID private key.

import { b64uEnc, b64uDec, hkdfSha256, randomBytes } from './crypto';
import type { PushSubscription } from './types';

/** P-256 pair: the raw public point a browser subscribes with, the private
 *  half as the JWK WebCrypto exported (stored under K_cfg, account_admin.ts). */
export interface VapidKeys {
  pub_b64u: string;
  jwk: JsonWebKey;
}

/** RFC 8291 §4: a push service need not accept more than 4096 octets of body;
 *  header (86) + padding delimiter (1) + GCM tag (16) leaves this. */
export const MAX_PUSH_PLAINTEXT = 3993;
const RECORD_SIZE = 4096;
// Apple refuses a VAPID token past 24 h.
const JWT_TTL_S = 12 * 60 * 60;
const SEND_TIMEOUT_MS = 6000;
const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const enc = new TextEncoder();
// workers-types widen generateKey/exportKey to unions and spell ECDH's `public`
// as `$public`; the runtime shapes are the standard ones.
const rawKey = async (k: CryptoKey) => new Uint8Array(await crypto.subtle.exportKey('raw', k) as ArrayBuffer);

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export async function generateVapid(): Promise<VapidKeys> {
  const kp = await crypto.subtle.generateKey(ECDSA_P256, true, ['sign']) as CryptoKeyPair;
  return {
    pub_b64u: b64uEnc(await rawKey(kp.publicKey)),
    jwk: await crypto.subtle.exportKey('jwk', kp.privateKey) as JsonWebKey,
  };
}

/** RFC 8291 §3.4 with the RFC 8188 header. `fixed` exists only for the RFC's
 *  worked example: a reused salt or server key is a broken cipher. */
export async function encryptPush(
  plaintext: Uint8Array,
  target: Pick<PushSubscription, 'p256dh' | 'auth'>,
  fixed?: { salt: Uint8Array; keyPair: CryptoKeyPair },
): Promise<Uint8Array> {
  if (plaintext.length > MAX_PUSH_PLAINTEXT) {
    throw new Error(`push payload ${plaintext.length} bytes, cap ${MAX_PUSH_PLAINTEXT}`);
  }
  const uaPub = b64uDec(target.p256dh);
  // importKey rejects a point off the curve (RFC 8291 §7) before any private
  // key touches it.
  const uaKey = await crypto.subtle.importKey('raw', uaPub, ECDH_P256, false, []);
  const kp = fixed?.keyPair
    ?? await crypto.subtle.generateKey(ECDH_P256, false, ['deriveBits']) as CryptoKeyPair;
  const asPub = await rawKey(kp.publicKey);
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'ECDH', public: uaKey } as SubtleCryptoDeriveKeyAlgorithm, kp.privateKey, 256));
  const ikm = await hkdfSha256(
    shared, b64uDec(target.auth), concat(enc.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = fixed?.salt ?? randomBytes(16);
  const cek = await hkdfSha256(ikm, salt, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdfSha256(ikm, salt, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  // 0x02 delimits the last (here: only) record; the 16-byte tag is appended.
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, key, concat(plaintext, new Uint8Array([2]))));
  const header = new Uint8Array(21);
  header.set(salt);
  new DataView(header.buffer).setUint32(16, RECORD_SIZE);
  header[20] = asPub.length;
  return concat(header, asPub, sealed);
}

/** RFC 8292 §3: an ES256 JWT bound to the push service's origin, plus the
 *  public key the subscription was created with. */
export async function vapidAuthorization(
  endpoint: string, keys: VapidKeys, subject: string, now = Date.now(),
): Promise<string> {
  const part = (o: unknown) => b64uEnc(enc.encode(JSON.stringify(o)));
  const token = `${part({ typ: 'JWT', alg: 'ES256' })}.${part({
    aud: new URL(endpoint).origin, exp: Math.floor(now / 1000) + JWT_TTL_S, sub: subject,
  })}`;
  const key = await crypto.subtle.importKey('jwk', keys.jwk, ECDSA_P256, false, ['sign']);
  // WebCrypto's ECDSA output is already the raw r‖s JOSE wants — no DER step.
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(token)));
  return `vapid t=${token}.${b64uEnc(sig)}, k=${keys.pub_b64u}`;
}

/** `status: 0` is "no answer" (network, timeout, local failure), distinct from
 *  a rejection so a caller never drops a subscription because the network was
 *  down. Never throws. */
export interface PushResult {
  status: number;
  error?: string;
}

export async function sendPush(
  target: PushSubscription,
  payload: string,
  keys: VapidKeys,
  subject: string,
  ttlS: number,
  urgency: 'normal' | 'high',
): Promise<PushResult> {
  try {
    const body = await encryptPush(enc.encode(payload), target);
    const res = await fetch(target.endpoint, {
      method: 'POST',
      headers: {
        Authorization: await vapidAuthorization(target.endpoint, keys, subject),
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        TTL: String(ttlS),
        Urgency: urgency,
      },
      body,
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    if (res.ok) return { status: res.status };
    // The service's own sentence is the only thing that explains a 400.
    const said = (await res.text().catch(() => '')).slice(0, 200);
    return { status: res.status, error: said || res.statusText };
  } catch (e) {
    return { status: 0, error: String(e) };
  }
}
