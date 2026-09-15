// WebAuthn user-verification (UV) policy for APPROVAL ceremonies — the pure,
// testable half. The ceremony plumbing lives in do_account.ts (opCreate decides
// the level, page data + assertion verification read it back).
//
// Registration is NOT covered here: enrolling a credential stays
// `userVerification: 'required'` in pwa/admin/setup.js. This module decides only
// what an approve/reject `navigator.credentials.get()` asks for, and what the
// Worker then enforces on the returned assertion.
//
// WHY a policy at all: a platform/1Password passkey has usually just verified
// the human to unlock its vault, so demanding UV again turns every approval into
// a second biometric step on top of the tap that opened the approval page. The
// tap on the approval page is the presence signal that matters (UP is still
// mandatory in every case — see webauthn.ts), and the approve token itself is an
// unguessable 96-bit capability with a 5-minute life. So the default for
// approvals is `discouraged`, and a deployment that wants the biometric step
// back configures it instead of patching the PWA.
//
// CAVEAT (docs/cf-worker-deploy.md#settings): a CTAP2
// security key derives the PRF extension from a different secret when it
// completes without user verification, so a YubiKey enrolled under `required`
// cannot unwrap its master key from a `discouraged` ceremony. It fails closed —
// the approval errors, nothing leaks — but such deployments want a `required`
// default. Platform/1Password passkeys verify while unlocking, so their PRF
// output does not depend on this policy.

/** WebAuthn's three levels, ordered. `discouraged` < `preferred` < `required`. */
export type UvLevel = 'discouraged' | 'preferred' | 'required';

const RANK: Record<UvLevel, number> = { discouraged: 0, preferred: 1, required: 2 };

/** Level an approval ceremony gets when nothing raises it. */
export const DEFAULT_APPROVAL_UV: UvLevel = 'discouraged';

/** Accept only the three spec levels. Anything else — absent, misspelled, a
 *  non-string from a client body — is "no opinion", never a level. */
export function parseUvLevel(v: unknown): UvLevel | null {
  return typeof v === 'string' && v in RANK ? (v as UvLevel) : null;
}

/** The stricter of two levels. The single operation the whole policy is built
 *  from: every input can only RAISE the effective level. */
export function maxUvLevel(a: UvLevel, b: UvLevel): UvLevel {
  return RANK[b] > RANK[a] ? b : a;
}

/** Server-side approval policy, parsed from `config.uv_policy`. */
export interface UvPolicy {
  /** Applies to every approval ceremony. */
  default: UvLevel;
  /** Keyed by `meta.op_kind` (decrypt | encrypt | auth | cache-extend | …). */
  byOp: Record<string, UvLevel>;
  /** Keyed by `meta.host` — the client-reported hostname. Advisory input, so it
   *  may only raise (like every other rule); never use it to relax. */
  byHost: Record<string, UvLevel>;
}

/** What a deployment gets with `uv_policy: null`. */
export function defaultUvPolicy(): UvPolicy {
  return { default: DEFAULT_APPROVAL_UV, byOp: {}, byHost: {} };
}

function levelMap(v: unknown): Record<string, UvLevel> {
  const out: Record<string, UvLevel> = {};
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return out;
  for (const [k, raw] of Object.entries(v as Record<string, unknown>)) {
    const level = parseUvLevel(raw);
    if (level) out[k] = level;
  }
  return out;
}

/** Parse the `uv_policy` object of the config blob (docs/worker-slim.md#approval-policy),
 *  the same shape the Settings tab PUTs:
 *
 *    {"default":"discouraged","by_op":{"decrypt":"required"},"by_host":{"prod":"required"}}
 *
 *  `null`/absent → the default policy, no error. MALFORMED → `required`
 *  everywhere plus an error: the PUT refuses it, and a stored one (a bug)
 *  reads as the strict pre-policy behaviour, never as "ask for less".
 *
 *  Unknown keys and unparseable levels inside a well-formed object are dropped
 *  rather than fatal — one bad op name cannot take the whole policy strict. */
export function parseUvPolicy(obj: unknown): {
  policy: UvPolicy;
  error: string | null;
} {
  if (obj === null || obj === undefined) return { policy: defaultUvPolicy(), error: null };
  const strict: UvPolicy = { default: 'required', byOp: {}, byHost: {} };
  if (typeof obj !== 'object' || Array.isArray(obj)) {
    return { policy: strict, error: 'not an object' };
  }
  const o = obj as Record<string, unknown>;
  if ('default' in o && parseUvLevel(o['default']) === null) {
    return { policy: strict, error: 'invalid default level' };
  }
  return {
    policy: {
      default: parseUvLevel(o['default']) ?? DEFAULT_APPROVAL_UV,
      byOp: levelMap(o['by_op']),
      byHost: levelMap(o['by_host']),
    },
    error: null,
  };
}

/** The level a ceremony is CREATED with: the maximum of the policy default, the
 *  op rule, the host rule and the client's `requested` level (the CLI's `--uv`,
 *  so raise-only — an unknown or absent value is simply no request). Every
 *  input can only raise, so there is no precedence puzzle to get wrong and
 *  adding a rule can never weaken another.
 *
 *  This runs ONCE, at challenge creation; the result is stored on the challenge
 *  and is what both the approval page and the assertion check read afterwards,
 *  so nothing a caller sends at verify time can downgrade a ceremony. */
export function effectiveUvLevel(
  policy: UvPolicy,
  scope: { op_kind?: string; host?: string },
  requested?: unknown,
): UvLevel {
  let level = policy.default;
  for (const rule of [
    policy.byOp[scope.op_kind ?? ''],
    policy.byHost[scope.host ?? ''],
    parseUvLevel(requested),
  ]) {
    if (rule) level = maxUvLevel(level, rule);
  }
  return level;
}
