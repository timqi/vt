// Shared harness for the AccountDO tests.
//
// Two things it provides that the tests would otherwise repeat:
//
//   • direct access to the singleton DO (storage, SQL, and the private cache
//     methods — TypeScript `private` is erased at runtime, so the tests reach
//     writeCache/commitExtend without any export-surface change to
//     do_account.ts, which is being refactored on a sibling branch);
//   • a software authenticator that produces a REAL WebAuthn assertion the
//     Worker's own verifyAssertion accepts, so "expires_ms moves only after a
//     verified assertion" is proven by driving the whole ceremony rather than by
//     calling commitExtend directly.
//
// The P-256 keypair below is a throwaway generated for this suite; its public
// half is the single credential enrolled in wrangler.test.toml. It is not a
// credential for anything, anywhere.

import { env, runInDurableObject } from 'cloudflare:test';
import { b64uEnc, b64uDec, sha256 } from '../src/crypto';
import { seal, cachePublicKey } from '../src/cache_crypto';
import type { CacheEntry, Challenge, ChallengeMeta } from '../src/types';

// ── DO access ──────────────────────────────────────────────────────────────

export const testEnv = env as unknown as {
  ACCOUNT: DurableObjectNamespace;
  CACHE_SECKEY: string;
  WORKER_ORIGIN: string;
  RP_ID: string;
};

/** The singleton instance index.ts always talks to (idFromName('account')). */
export function accountStub(): DurableObjectStub {
  const ns = testEnv.ACCOUNT;
  return ns.get(ns.idFromName('account'));
}

/** Anything reachable from inside the DO: the instance (including its private
 *  methods and its own mutable `env`) and its storage/SQL. */
export interface DoHandle {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  inst: any;
  state: DurableObjectState;
}

export function inDO<T>(fn: (h: DoHandle) => T | Promise<T>): Promise<T> {
  return runInDurableObject(accountStub(), (inst, state) =>
    fn({ inst: inst as unknown as DoHandle['inst'], state }),
  ) as Promise<T>;
}

/** Set a var on the DO's OWN env. The `env` the test file sees is a different
 *  object from the one the DO was constructed with, so a kill-switch test has to
 *  reach inside. Tests reset this in beforeEach — the DO instance (unlike its
 *  storage) is reused across tests in a file. */
export async function setDoVar(name: string, value: string): Promise<void> {
  await inDO(({ inst }) => { inst.env[name] = value; });
}

// ── Storage fixtures ───────────────────────────────────────────────────────

export const FAKE_CTX = 'testctx0000000000000000000000000000000000';

let saltCounter = 0;
export function nextSalt(): string {
  saltCounter++;
  return b64uEnc(new Uint8Array(16).map((_, i) => (saltCounter * 31 + i) & 0xff));
}

/** A sealed blob writeCache/opDekCache will accept: crypto_box_seal of a 32-byte
 *  fake DEK to the public key derived from the fixture CACHE_SECKEY. */
export function sealFakeDek(fill = 7): string {
  const dek = new Uint8Array(32).fill(fill);
  return seal(dek, cachePublicKey(testEnv.CACHE_SECKEY));
}

export function makeEntry(over: Partial<CacheEntry> = {}): CacheEntry {
  const now = Date.now();
  return {
    sealed_to_cache_b64u: sealFakeDek(),
    expires_ms: now + 60_000,
    origin_token_id: 'origin0000000000',
    ip: '203.0.113.9',
    ppid: 4242,
    ppid_cmd: 'zsh -c fake',
    cache_group_id: 'g_testgroup00000',
    created_ms: now - 60_000,
    ...over,
  };
}

/** Write one cache group straight into storage — the shortest path to "an entry
 *  in state X exists", without going through an approval.
 *
 *  The entry template is built ONCE and reused for every key: a real writeCache
 *  puts one batch, so a group's entries agree on origin/created_ms/ip. Rebuilding
 *  it per key would let the clock advance across the `put` awaits and hand every
 *  test a `consistent: false` group. */
export async function seedGroup(
  h: DoHandle,
  n: number,
  over: Partial<CacheEntry> = {},
): Promise<string[]> {
  const entry = makeEntry(over);
  const keys: string[] = [];
  for (let i = 0; i < n; i++) {
    const key = `dek:${FAKE_CTX}:${nextSalt()}`;
    keys.push(key);
    await h.state.storage.put(key, entry);
  }
  return keys;
}

export async function readEntries(h: DoHandle, keys: string[]): Promise<CacheEntry[]> {
  const out: CacheEntry[] = [];
  for (const k of keys) {
    const e = await h.state.storage.get<CacheEntry>(k);
    if (e) out.push(e);
  }
  return out;
}

export async function allDekKeys(h: DoHandle): Promise<string[]> {
  return [...(await h.state.storage.list<CacheEntry>({ prefix: 'dek:' })).keys()];
}

// ── Challenge fixtures ─────────────────────────────────────────────────────

export function makeMeta(over: Partial<ChallengeMeta> = {}): ChallengeMeta {
  return {
    op_kind: 'decrypt',
    command: 'vt read .env',
    host: 'testbox',
    user: 'tester',
    pwd: '/home/tester/repo',
    tty: '/dev/pts/0',
    ppid_cmd: 'zsh -c fake',
    ppid: 4242,
    ssh_client: '',
    ip: '203.0.113.9',
    reason: '',
    ...over,
  };
}

let tokenCounter = 0;
/** 16-char token, so auditKey() (slice(0,16)) is the whole thing — the same
 *  property the production 12-byte b64u tokens have. */
export function nextToken(prefix = 'tok'): string {
  tokenCounter++;
  return (prefix + String(tokenCounter).padStart(13 - prefix.length, '0') + 'zzzzzzzzzzzzzzzz')
    .slice(0, 16);
}

export function makeChallenge(over: Partial<Challenge> = {}): Challenge {
  const token = nextToken();
  return {
    approve_token: token,
    poll_token: 'poll' + token,
    daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(1)),
    worker_nonce_b64u: b64uEnc(new Uint8Array(16).fill(2)),
    timestamp_ms: Date.now(),
    approve_challenge_hash_b64u: b64uEnc(new Uint8Array(32).fill(3)),
    reject_challenge_hash_b64u: b64uEnc(new Uint8Array(32).fill(4)),
    salts_b64u: [],
    meta: makeMeta(),
    status: 'pending',
    created_ms: Date.now(),
    ...over,
  };
}

// ── Audit access ───────────────────────────────────────────────────────────

export interface AuditSnapshot {
  token_id: string;
  status: string;
  op_kind: string | null;
  source: string;
  cache_ttl_s: number | null;
  cache_expires_ms: number | null;
  command: string | null;
  reason: string | null;
}

export async function auditRows(h: DoHandle): Promise<AuditSnapshot[]> {
  return h.state.storage.sql
    .exec(`SELECT token_id, status, op_kind, source, cache_ttl_s, cache_expires_ms,
                  command, reason
             FROM audit ORDER BY id`)
    .toArray() as unknown as AuditSnapshot[];
}

export async function auditRow(h: DoHandle, tokenId: string): Promise<AuditSnapshot | undefined> {
  return (await auditRows(h)).find(r => r.token_id === tokenId);
}

// ── Software authenticator (throwaway P-256 keypair) ───────────────────────

// TEST FIXTURE ONLY. Generated for this suite; the matching public key is the
// lone credential in wrangler.test.toml. Grants nothing anywhere.
const TEST_AUTHENTICATOR_JWK: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'gz7X_ylWpbthTAsQXVplvh0gFmKY7J0z58Aml1Bf03w',
  y: 'IcsGbg-NW_rShPt68QxCXmBA7dV9v8NEw2B2OqvOW_4',
  d: 'zh_7N-Uz6LoAmmbU4iErdP2oTxD3nKuPUY5rbcEiGsU',
};

/** b64u(credential_id) as enrolled in wrangler.test.toml ("vt-test-credential"). */
export const TEST_CREDENTIAL_ID_B64U = 'dnQtdGVzdC1jcmVkZW50aWFs';

/** The PWA's ephemeral X25519 pubkey. An extension ceremony delivers no key
 *  material, so any 32 bytes will do — it only has to be bound into the
 *  assertion, which is precisely what the test is checking. */
export const TEST_PWA_PK = new Uint8Array(32).fill(9);

/** WebCrypto returns raw r||s; verifyAssertion decodes DER (what a real
 *  authenticator emits). Re-encode so the fixture goes through the same
 *  derToRaw path production does. */
function rawSigToDer(raw: Uint8Array): Uint8Array {
  const trim = (b: Uint8Array): number[] => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const out = Array.from(b.slice(i));
    if ((out[0]! & 0x80) !== 0) out.unshift(0);   // ASN.1 INTEGER is signed
    return out;
  };
  const r = trim(raw.slice(0, 32));
  const s = trim(raw.slice(32, 64));
  const body = [0x02, r.length, ...r, 0x02, s.length, ...s];
  return Uint8Array.from([0x30, body.length, ...body]);
}

/** Build the assertion the Worker expects for `approve`:
 *  challenge = SHA-256(approve_challenge_hash || pwa_pk). */
export async function signApproval(approveChallengeHashB64u: string): Promise<{
  credential_id_b64u: string;
  client_data_json_b64u: string;
  authenticator_data_b64u: string;
  signature_b64u: string;
  pwa_pk_b64u: string;
}> {
  const hash = b64uDec(approveChallengeHashB64u);
  const effective = new Uint8Array(hash.length + TEST_PWA_PK.length);
  effective.set(hash, 0);
  effective.set(TEST_PWA_PK, hash.length);
  const expectedChallenge = new Uint8Array(await crypto.subtle.digest('SHA-256', effective));

  const clientDataJson = new TextEncoder().encode(JSON.stringify({
    type: 'webauthn.get',
    challenge: b64uEnc(expectedChallenge),
    origin: new URL(testEnv.WORKER_ORIGIN).origin,
    crossOrigin: false,
  }));

  // rpIdHash || flags(UP|UV) || signCount
  const rpIdHash = await sha256(new TextEncoder().encode(testEnv.RP_ID));
  const authData = new Uint8Array(37);
  authData.set(rpIdHash, 0);
  authData[32] = 0x05;               // UP (bit0) | UV (bit2)

  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData, 0);
  signedData.set(await sha256(clientDataJson), authData.length);

  const key = await crypto.subtle.importKey(
    'jwk', TEST_AUTHENTICATOR_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, signedData));

  return {
    credential_id_b64u: TEST_CREDENTIAL_ID_B64U,
    client_data_json_b64u: b64uEnc(clientDataJson),
    authenticator_data_b64u: b64uEnc(authData),
    signature_b64u: b64uEnc(rawSigToDer(rawSig)),
    pwa_pk_b64u: b64uEnc(TEST_PWA_PK),
  };
}

/** Drive a full approval through the DO's public `approve` op: a genuine
 *  WebAuthn assertion over the stored challenge, verified by the Worker's own
 *  verifyAssertion. Extra body fields (cache_ttl_s, cache_sealed_deks_b64u) go
 *  through untouched so a tampered approve body can be tested too. */
export async function approve(
  ch: Pick<Challenge, 'approve_token' | 'approve_challenge_hash_b64u'>,
  extra: Record<string, unknown> = {},
): Promise<DoResult> {
  const assertion = await signApproval(ch.approve_challenge_hash_b64u);
  return doPost('approve', {
    approve_token: ch.approve_token,
    sealed_deks_b64u: b64uEnc(new Uint8Array(48).fill(5)),
    binding_tag_b64u: b64uEnc(new Uint8Array(32).fill(6)),
    ...assertion,
    ...extra,
  });
}

// ── DO ops ───────────────────────────────────────────────────────────

export interface DoResult {
  status: number;
  text: string;
  json: any;
}

/** Always drains the body. An unconsumed response body holds the isolated
 *  storage stack frame open and makes the WHOLE FILE fail at teardown
 *  (cloudflare/workers-sdk#5629), so no test may check a status alone. */
async function consume(resp: Response): Promise<DoResult> {
  const text = await resp.text();
  let json: unknown = null;
  try { json = JSON.parse(text); } catch { /* plain-text error body */ }
  return { status: resp.status, text, json };
}

export async function doPost(op: string, body: unknown): Promise<DoResult> {
  return consume(await accountStub().fetch(`https://account.do/op/${op}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }));
}

export async function doGet(op: string): Promise<DoResult> {
  return consume(await accountStub().fetch(`https://account.do/op/${op}`));
}
