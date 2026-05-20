// WebAuthn assertion verification using WebCrypto.
//
// Supported algorithms: ES256 (P-256 ECDSA, cose alg -7), EdDSA (Ed25519, cose alg -8).
//
// Signed payload: authenticatorData || SHA-256(clientDataJSON)
// P-256 signatures arrive DER-encoded; Ed25519 signatures are raw (64 bytes).

import { sha256, b64uDec, ctEq } from './crypto';

export async function verifyAssertion(opts: {
  /** COSE-encoded public key bytes (from credentials.p) */
  cosePublicKey: Uint8Array;
  /** Raw bytes of clientDataJSON from authenticator */
  clientDataJson: Uint8Array;
  /** Raw bytes of authenticatorData from authenticator */
  authenticatorData: Uint8Array;
  /** Signature bytes from authenticator */
  signature: Uint8Array;
  /** The expected challenge bytes (= challenge_hash 32 bytes) */
  expectedChallenge: Uint8Array;
  /** Relying party ID (hostname) */
  rpId: string;
}): Promise<void> {
  const { cosePublicKey, clientDataJson, authenticatorData, signature, expectedChallenge, rpId } = opts;

  // 1. Parse and validate clientDataJSON
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJson));
  if (clientData.type !== 'webauthn.get') {
    throw new Error('clientData.type must be webauthn.get');
  }
  const challengeBytes = b64uDec(clientData.challenge as string);
  if (!ctEq(challengeBytes, expectedChallenge)) {
    throw new Error('challenge mismatch');
  }

  // 2. Check rpIdHash
  const rpIdHash = await sha256(new TextEncoder().encode(rpId));
  if (authenticatorData.length < 37) throw new Error('authenticatorData too short');
  if (!ctEq(rpIdHash, authenticatorData.slice(0, 32))) {
    throw new Error('rpIdHash mismatch');
  }

  // 3. Check UV flag (bit 2 of flags byte at offset 32)
  const flags = authenticatorData[32]!;
  if ((flags & 0x04) === 0) throw new Error('user verification required but UV flag not set');

  // 4. Build signed data
  const clientDataHash = await sha256(clientDataJson);
  const signedData = new Uint8Array(authenticatorData.length + 32);
  signedData.set(authenticatorData, 0);
  signedData.set(clientDataHash, authenticatorData.length);

  // 5. Decode COSE pubkey and verify signature
  await verifyCoseSignature(cosePublicKey, signedData, signature);
}

async function verifyCoseSignature(
  coseKey: Uint8Array,
  signedData: Uint8Array,
  sig: Uint8Array,
): Promise<void> {
  const map = decodeCborMap(coseKey);
  const alg = map.get(3); // alg
  if (alg === -7) {
    // ES256 — P-256 ECDSA with SHA-256
    const xBytes = expectBytes(map.get(-2), 'x');
    const yBytes = expectBytes(map.get(-3), 'y');
    const uncompressed = new Uint8Array(65);
    uncompressed[0] = 0x04;
    uncompressed.set(xBytes, 1);
    uncompressed.set(yBytes, 33);
    const key = await crypto.subtle.importKey(
      'raw', uncompressed, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const rawSig = derToRaw(sig);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key, rawSig, signedData);
    if (!ok) throw new Error('P-256 signature verification failed');
  } else if (alg === -8) {
    // EdDSA — Ed25519
    const xBytes = expectBytes(map.get(-2), 'x');
    const key = await crypto.subtle.importKey(
      'raw', xBytes, { name: 'Ed25519' }, false, ['verify']);
    const ok = await crypto.subtle.verify('Ed25519', key, sig, signedData);
    if (!ok) throw new Error('Ed25519 signature verification failed');
  } else {
    throw new Error(`unsupported COSE algorithm ${alg}`);
  }
}

// Convert DER-encoded ECDSA signature (ASN.1 SEQUENCE { INTEGER r, INTEGER s })
// to raw 64-byte format (r[32] || s[32]).
function derToRaw(der: Uint8Array): Uint8Array {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error('DER: not a SEQUENCE');
  // Length (skip long-form)
  const lenByte = der[offset++]!;
  if (lenByte & 0x80) offset += lenByte & 0x7f;

  const raw = new Uint8Array(64);

  // Parse r
  if (der[offset++] !== 0x02) throw new Error('DER: expected INTEGER for r');
  let rLen = der[offset++]!;
  let rStart = offset;
  if (der[rStart] === 0x00) { rStart++; rLen--; } // strip leading zero
  raw.set(der.slice(rStart, rStart + rLen), 32 - rLen);
  offset = rStart + rLen;

  // Parse s
  if (der[offset++] !== 0x02) throw new Error('DER: expected INTEGER for s');
  let sLen = der[offset++]!;
  let sStart = offset;
  if (der[sStart] === 0x00) { sStart++; sLen--; } // strip leading zero
  raw.set(der.slice(sStart, sStart + sLen), 64 - sLen);

  return raw;
}

// Minimal CBOR map decoder (integers and byte strings only — enough for COSE keys).
function decodeCborMap(data: Uint8Array): Map<number, unknown> {
  let offset = 0;
  const map = new Map<number, unknown>();

  const readByte = () => {
    if (offset >= data.length) throw new Error('CBOR: unexpected end');
    return data[offset++]!;
  };

  const readUint = (additional: number): number => {
    if (additional < 24) return additional;
    if (additional === 24) return readByte();
    if (additional === 25) {
      const hi = readByte(); const lo = readByte();
      return (hi << 8) | lo;
    }
    throw new Error('CBOR: integer too large');
  };

  const readItem = (): unknown => {
    const initial = readByte();
    const major = initial >> 5;
    const additional = initial & 0x1f;
    if (major === 0) return readUint(additional);          // uint
    if (major === 1) return -(readUint(additional) + 1);   // negative int
    if (major === 2) {
      const len = readUint(additional);
      const bytes = data.slice(offset, offset + len);
      offset += len;
      return bytes;
    }
    if (major === 3) {
      const len = readUint(additional);
      const bytes = data.slice(offset, offset + len);
      offset += len;
      return new TextDecoder().decode(bytes);
    }
    if (major === 5) {
      // map
      const count = readUint(additional);
      const m = new Map<unknown, unknown>();
      for (let i = 0; i < count; i++) {
        const k = readItem(); const v = readItem();
        m.set(k, v);
      }
      return m;
    }
    throw new Error(`CBOR: unsupported major type ${major}`);
  };

  const initial = readByte();
  const major = initial >> 5;
  const additional = initial & 0x1f;
  if (major !== 5) throw new Error('CBOR: expected map at top level');
  const count = readUint(additional);
  for (let i = 0; i < count; i++) {
    const k = readItem();
    const v = readItem();
    if (typeof k === 'number') map.set(k, v);
  }
  return map;
}

function expectBytes(v: unknown, field: string): Uint8Array {
  if (!(v instanceof Uint8Array)) throw new Error(`COSE: field ${field} is not bytes`);
  return v;
}
