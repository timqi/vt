// Audit-key derivation (kept in its own non-macOS-gated module so the HKDF and
// its cross-impl golden-vector test compile and run on every platform).
//
// The macOS agent calls this at startup to derive its per-host audit subkey
// from the worker master (`--audit-key`, == VT_AUTH_CF) + the hostname; the
// push path itself (HTTP POST, AgentAuditEntry, config) lives in the cfg-gated
// `server_macos::audit` module, which depends on macOS-only types.
//
// Key scheme (see docs/agent-audit.md):
//
//   agent_audit_key = HKDF-SHA256(
//       ikm  = VT_AUTH_CF (worker master, == VT_PASSKEY_TOKEN),
//       salt = agent_id   (= the machine hostname, UTF-8 bytes),
//       info = "vt-agent-audit-v1",
//       L    = 32)
//
// The Worker re-derives the same key per request from the (unverified)
// `agent_id` (hostname) in the body, then verifies the HMAC — so a key that
// won't verify is the only thing a forged `agent_id` can produce.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF info string for the agent-audit subkey. Domain-separates this
/// derivation from any other HKDF use keyed on `VT_AUTH_CF`. The cf-worker
/// `hkdfSha256(VT_AUTH_CF, agent_id, "vt-agent-audit-v1", 32)` MUST match.
pub const AGENT_AUDIT_INFO: &[u8] = b"vt-agent-audit-v1";

/// Derive the per-agent audit HMAC key from the worker master and a stable
/// `agent_id`. Deterministic: the same `(master, agent_id)` always yields the
/// same 32-byte key, so the Worker can re-derive it on each ingest.
pub fn derive_agent_audit_key(master: &[u8], agent_id: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(agent_id.as_bytes()), master);
    let mut out = Zeroizing::new([0u8; 32]);
    // `expand` only errors if the output length exceeds 255*HashLen; 32 is well
    // within bounds, so this never fails.
    hk.expand(AGENT_AUDIT_INFO, &mut *out)
        .expect("HKDF expand of 32 bytes never fails");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    /// Golden vector pinning the agent-audit key derivation. The cf-worker
    /// `hkdfSha256` TS implementation MUST produce the identical key for these
    /// same inputs (cross-impl parity, like `approve_challenge_hash_golden_vector`).
    /// If this changes, agent audit rows will fail HMAC verification at the
    /// Worker and silently drop.
    #[test]
    fn derive_agent_audit_key_golden_vector() {
        // master = "test-master-token", agent_id = "AAAAAAAAAAAAAAAAAAAAAA"
        let key = derive_agent_audit_key(b"test-master-token", "AAAAAAAAAAAAAAAAAAAAAA");
        let got = URL_SAFE_NO_PAD.encode(&*key);
        // Cross-validated against an independent HKDF-SHA256 implementation
        // (RFC 5869) over the same ikm/salt/info. Locked so any formula drift
        // (info string, salt source, length) flips this value.
        assert_eq!(got, "meJjGMXAQFmzcmodJL9ypJpdSFrd_AsvMvSGZ0KcYlY");
    }

    #[test]
    fn derive_agent_audit_key_is_deterministic() {
        let a = derive_agent_audit_key(b"m", "agent-1");
        let b = derive_agent_audit_key(b"m", "agent-1");
        assert_eq!(&*a, &*b);
    }

    #[test]
    fn derive_agent_audit_key_varies_by_agent_id() {
        let a = derive_agent_audit_key(b"m", "agent-1");
        let b = derive_agent_audit_key(b"m", "agent-2");
        assert_ne!(&*a, &*b, "different agent_id must yield a different key");
    }

    #[test]
    fn derive_agent_audit_key_varies_by_master() {
        let a = derive_agent_audit_key(b"master-a", "agent-1");
        let b = derive_agent_audit_key(b"master-b", "agent-1");
        assert_ne!(&*a, &*b, "different master must yield a different key");
    }
}
