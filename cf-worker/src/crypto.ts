// Crypto primitives: SHA-256, HMAC-SHA256, challenge_hash,
// constant-time comparison, random bytes.

export function b64uEnc(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDec(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? s : s + '='.repeat(4 - (s.length % 4));
  const bin = atob(pad.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Decode b64u and assert exact byte length. Throws on missing/non-b64u
// inputs and on length mismatch; callers translate the throw into a 400.
const B64U_RE = /^[A-Za-z0-9_-]+$/;
export function decodeB64uExact(v: unknown, expectedLen: number, field: string): Uint8Array {
  if (typeof v !== 'string' || v.length === 0 || !B64U_RE.test(v)) {
    throw new Error(`${field}: missing or not b64u`);
  }
  const bytes = b64uDec(v);
  if (bytes.length !== expectedLen) throw new Error(`${field}: wrong length`);
  return bytes;
}

export function isB64uString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0 && B64U_RE.test(v);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

// HKDF-SHA256 (RFC 5869, extract + expand). Used to derive the per-agent audit
// key from VT_AUTH_CF: hkdfSha256(VT_AUTH_CF, agent_id, "vt-agent-audit-v1", 32).
// MUST match the Rust `derive_agent_audit_key` (src/audit.rs) — both feed the
// same ikm/salt/info, so a row signed by the agent verifies here.
export async function hkdfSha256(
  ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8);
  return new Uint8Array(bits);
}

// challenge_hash = SHA-256(
//   "vt-challenge-v2"        (15 bytes)
//   || daemon_pubkey         (32 bytes)
//   || worker_nonce          (16 bytes)
//   || timestamp_ms          (8 bytes big-endian u64)
//   || sha256(concat(salts)) (32 bytes) — binds salts to the phone's assertion
//   || action_byte           (1 byte: 0x01 approve, 0x02 reject)
// )
// Domain-separating the action prevents replay of an approve assertion against
// /api/reject (or vice versa).
const ACTION_BYTE = { approve: 0x01, reject: 0x02 } as const;
export type ChallengeAction = keyof typeof ACTION_BYTE;

export async function challengeHash(
  daemonPubkey: Uint8Array,
  workerNonce: Uint8Array,
  timestampMs: number,
  salts: Uint8Array[],
  action: ChallengeAction,
): Promise<Uint8Array> {
  const domain = new TextEncoder().encode('vt-challenge-v2');
  const tsBytes = new Uint8Array(8);
  new DataView(tsBytes.buffer).setBigUint64(0, BigInt(timestampMs), false);

  // Hash the concatenated salts to bind them into the challenge
  const saltConcat = new Uint8Array(salts.reduce((n, s) => n + s.length, 0));
  let off = 0;
  for (const s of salts) { saltConcat.set(s, off); off += s.length; }
  const saltsHash = await sha256(saltConcat);

  const msg = new Uint8Array(15 + 32 + 16 + 8 + 32 + 1);
  msg.set(domain, 0);
  msg.set(daemonPubkey, 15);
  msg.set(workerNonce, 47);
  msg.set(tsBytes, 63);
  msg.set(saltsHash, 71);
  msg[103] = ACTION_BYTE[action];
  return sha256(msg);
}

// Constant-time bytes comparison (equal length only).
export function ctEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// Reject requests outside ±5 minutes of the worker clock.
export function inReplayWindow(nowMs: number, bodyMs: number): boolean {
  return Math.abs(nowMs - bodyMs) <= 5 * 60 * 1000;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
