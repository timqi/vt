// Crypto primitives: SHA-256, HMAC-SHA256, challenge_hash, path prefix,
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

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

// Returns 16 b64url chars of HMAC-SHA256(VT_AUTH_CF, "vt-path-prefix").
// Must match the Rust derive_path_prefix() in src/cf.rs exactly.
export async function derivePathPrefix(vtAuthCf: string): Promise<string> {
  const keyBytes = new TextEncoder().encode(vtAuthCf);
  const mac = await hmacSha256(keyBytes, new TextEncoder().encode('vt-path-prefix'));
  return b64uEnc(mac).slice(0, 16);
}

// challenge_hash = SHA-256(
//   "vt-challenge-v1"  (15 bytes)
//   || daemon_pubkey   (32 bytes)
//   || worker_nonce    (16 bytes)
//   || timestamp_ms    (8 bytes big-endian u64)
//   || sha256(concat(salts))  (32 bytes) — binds salts to the phone's assertion
// )
export async function challengeHash(
  daemonPubkey: Uint8Array,
  workerNonce: Uint8Array,
  timestampMs: number,
  salts: Uint8Array[],
): Promise<Uint8Array> {
  const domain = new TextEncoder().encode('vt-challenge-v1');
  const tsBytes = new Uint8Array(8);
  new DataView(tsBytes.buffer).setBigUint64(0, BigInt(timestampMs), false);

  // Hash the concatenated salts to bind them into the challenge
  const saltConcat = new Uint8Array(salts.reduce((n, s) => n + s.length, 0));
  let off = 0;
  for (const s of salts) { saltConcat.set(s, off); off += s.length; }
  const saltsHash = await sha256(saltConcat);

  const msg = new Uint8Array(15 + 32 + 16 + 8 + 32);
  msg.set(domain, 0);
  msg.set(daemonPubkey, 15);
  msg.set(workerNonce, 47);
  msg.set(tsBytes, 63);
  msg.set(saltsHash, 71);
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
