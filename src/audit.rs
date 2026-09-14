// Audit-key selection (kept in its own non-macOS-gated module so it compiles
// and tests on every platform).
//
// The macOS agent pushes audit rows signed with this Mac's own host token
// (`--audit-key vt1.<id>.<secret>`, from `vt enroll`): the token secret is the
// HMAC key and `agent_id = t:<id>` tells the Worker which token to derive it
// for. The push path itself (HTTP POST, AgentAuditEntry, config) lives in the
// cfg-gated `server_macos::audit` module, which depends on macOS-only types.
// The hostname-salted master form is gone (docs/refactor.md §1): the Worker's
// secret is a KEK that never reaches a host, so there is nothing to derive from.

use zeroize::Zeroizing;

/// When `--audit-key` is a host token (`vt1.<id>.<secret>`), the audit HMAC key
/// is the token secret itself and the Worker selects it via `agent_id =
/// t:<id>`. `None` for anything else — the caller disables audit push.
pub fn host_token_audit_key(audit_key: &str) -> Option<(String, Zeroizing<[u8; 32]>)> {
    let auth = crate::cf::WorkerAuth::parse(audit_key).ok()?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(auth.key_bytes());
    Some((auth.token_id, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    #[test]
    fn host_token_audit_key_only_for_host_tokens() {
        assert!(host_token_audit_key("plain-master").is_none());
        assert!(host_token_audit_key("vt1.bad").is_none());
        let (id, key) = host_token_audit_key(
            "vt1.AAAAAAAAAAAAAAAA.iaR45SwFl4C19e0hLGVnh32aBZlyjE4i47Jp_FbuKAI",
        )
        .unwrap();
        assert_eq!(id, "AAAAAAAAAAAAAAAA");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.as_slice()),
            "iaR45SwFl4C19e0hLGVnh32aBZlyjE4i47Jp_FbuKAI"
        );
    }
}
