// macOS agent audit push (fire-and-forget).
//
// After the SSH agent reaches a decision (approve / reject / unavailable /
// cache-hit / spawn-failed) for any of encrypt@vt / decrypt@vt / auth@vt /
// run@vt / sign, it builds an `AgentAuditEntry` and hands it to
// `spawn_push`, which POSTs one record to the Worker WITHOUT being awaited —
// zero added latency on the decision path. Loss semantics match the old
// `tracing::info!`: if the agent has no network at decision time, the record
// is dropped (online → now queryable; offline → same as before).
//
// The cross-platform key derivation lives in `crate::audit`; this module is
// macOS-gated because it depends on the agent runtime (tokio) and the
// `cf::ChallengeMeta` display shape. See docs/agent-audit.md.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::cf::{cf_post_with_timeout, hmac_auth_header_raw, ChallengeMeta};

/// One agent-side audit record. Serialized as the `entry` field of the ingest
/// body. `meta` carries the full [`ChallengeMeta`] wire shape (all 11 fields)
/// so the Worker's `capChallengeMeta` sanitizer has everything it expects;
/// the scalar siblings carry the audit-specific data. `meta.op_kind` and the
/// sibling `op_kind` hold the same value.
#[derive(Serialize)]
pub struct AgentAuditEntry {
    /// encrypt | decrypt | auth | run | sign
    pub op_kind: String,
    /// approved | rejected | unavailable | cache_hit | spawn_failed
    pub outcome: String,
    /// Decrypt batch size; 0 for auth/sign/run.
    pub salts: usize,
    /// Prompt-shown → decision, in milliseconds. 0 for cache hits (no prompt).
    pub latency_ms: u64,
    /// Event time (epoch ms). Used as both `created_ms` and `finalized_ms`.
    pub ts_ms: u64,
    /// Synthetic, unique, retry-dedup key: `a_<agent_id>_<8 random bytes b64u>`.
    /// The `a_` prefix is structurally disjoint from the 16-char ceremony tokens
    /// and the `c_` cache-event rows.
    pub token_id: String,
    /// Full display context (host/user/pwd/tty/ppid_cmd/ssh_client/ppid/…).
    pub meta: ChallengeMeta,
}

impl AgentAuditEntry {
    /// Build an entry from the per-request client meta plus the agent-derived
    /// fields. `peer_pid` is the socket peer PID (see `get_peer_pid`); `None`
    /// for forwarded/remote sessions, in which case `meta.ppid` is left 0.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        op_kind: &str,
        outcome: &str,
        host: &str,
        client_meta: &crate::core::ClientMeta,
        command: &str,
        reason: &str,
        peer_pid: Option<i32>,
        salts: usize,
        latency_ms: u64,
        agent_id: &str,
    ) -> Self {
        let meta = ChallengeMeta {
            op_kind: op_kind.to_string(),
            command: command.to_string(),
            host: host.to_string(),
            user: client_meta.user.clone(),
            pwd: client_meta.pwd.clone(),
            tty: client_meta.tty.clone(),
            ppid_cmd: client_meta.ppid_cmd.clone(),
            // Q1: the socket peer PID, not the agent's own ppid. 0 (→ absent on
            // the wire after capChallengeMeta) when the session is forwarded.
            ppid: peer_pid.filter(|p| *p > 0).map(|p| p as u32).unwrap_or(0),
            ssh_client: client_meta.ssh_client.clone(),
            reason: reason.to_string(),
        };
        AgentAuditEntry {
            op_kind: op_kind.to_string(),
            outcome: outcome.to_string(),
            salts,
            latency_ms,
            ts_ms: now_ms(),
            token_id: mint_token_id(agent_id),
            meta,
        }
    }
}

/// The full ingest body POSTed to `{url}/api/audit-ingest`.
#[derive(Serialize)]
struct IngestBody<'a> {
    timestamp_ms: u64,
    agent_id: &'a str,
    hostname: &'a str,
    entry: &'a AgentAuditEntry,
}

/// Configuration for the agent's audit push. Built once at agent startup from
/// the `--audit-url` / `--audit-key` flags and threaded (as `Arc`) into
/// every session.
pub struct AuditPushConfig {
    /// Worker base URL, e.g. `https://vt-passkey.example.com` (no trailing path).
    url: String,
    /// The per-host derived HMAC subkey (HKDF of the master + hostname, computed
    /// at startup in `build_audit_push_config`). The raw master is NOT stored
    /// here. `Zeroizing` wipes it on drop; the fixed `[u8; 32]` avoids any
    /// transient un-zeroized heap copy.
    key: Zeroizing<[u8; 32]>,
    /// The agent's id (= hostname): HKDF salt selector + `token_id` prefix.
    agent_id: String,
    /// Display-only hostname (currently identical to `agent_id`).
    hostname: String,
    /// Master switch: false → `spawn_push` is a no-op.
    pub enabled: bool,
}

impl AuditPushConfig {
    /// The agent's stable id, embedded in each row's `token_id`. Empty when
    /// the config is disabled.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

impl AuditPushConfig {
    /// A fully-disabled config (no flags, or `--no-audit-push`).
    pub fn disabled() -> Self {
        Self {
            url: String::new(),
            key: Zeroizing::new([0u8; 32]),
            agent_id: String::new(),
            hostname: String::new(),
            enabled: false,
        }
    }

    /// Build an enabled config from the already-derived 32-byte per-host subkey
    /// and the hostname (used as both `agent_id` and display `hostname`).
    /// Validates that `url` is an `https://` URL; on failure it logs a warning
    /// and returns a disabled config (S6 — never silently push to an http origin).
    pub fn new(url: String, key: Zeroizing<[u8; 32]>, hostname: String) -> Self {
        let url_ok = url.starts_with("https://") && url.len() > "https://".len();
        if !url_ok {
            tracing::warn!(
                "audit push disabled: --audit-url must be an https:// URL (got {:?})",
                url
            );
            return Self::disabled();
        }
        Self {
            // Normalize away a trailing slash so `{url}/api/audit-ingest` is clean.
            url: url.trim_end_matches('/').to_string(),
            key,
            agent_id: hostname.clone(),
            hostname,
            enabled: true,
        }
    }
}

/// Fire-and-forget: spawn a background task that POSTs `entry` to the Worker.
/// Never awaited by the caller, so it adds no latency to the decision path.
/// All errors are swallowed (debug-logged); it never panics or blocks.
pub fn spawn_push(cfg: Arc<AuditPushConfig>, entry: AgentAuditEntry) {
    if !cfg.enabled {
        return;
    }
    tokio::spawn(async move {
        if let Err(e) = push_once_with_retry(&cfg, &entry).await {
            tracing::debug!("audit push dropped: {e:#}");
        }
    });
}

async fn push_once_with_retry(cfg: &AuditPushConfig, entry: &AgentAuditEntry) -> anyhow::Result<()> {
    let body = serde_json::to_vec(&IngestBody {
        timestamp_ms: entry.ts_ms,
        agent_id: &cfg.agent_id,
        hostname: &cfg.hostname,
        entry,
    })?;
    let auth = hmac_auth_header_raw(&cfg.key[..], &body);
    let url = format!("{}/api/audit-ingest", cfg.url);

    // Up to 2 attempts: retry ONLY on a transport error or a 5xx. A 4xx is a
    // permanent rejection (bad HMAC, stale ts, oversized) — retrying is futile
    // and just doubles the load, so we bail immediately. 5 s timeout per attempt
    // so a single row can never stall longer than ~10 s, off the decision path.
    // A transient failure carries the last error forward; if both attempts fail
    // it surfaces after the loop.
    let mut last_err = anyhow::anyhow!("audit ingest failed");
    for _ in 0..2 {
        match cf_post_with_timeout(&url, &auth, &body, 5).await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return Ok(());
                }
                if status.is_client_error() {
                    anyhow::bail!("audit ingest rejected: HTTP {}", status.as_u16());
                }
                last_err = anyhow::anyhow!("audit ingest server error: HTTP {}", status.as_u16());
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// `a_<agent_id>_<8 random bytes b64u>` — random suffix (NOT a timestamp) so
/// two events in the same millisecond on a fast machine cannot collide on the
/// UNIQUE `token_id` column.
///
/// The `agent_id` (hostname) portion is capped at 60 chars so the random suffix
/// always survives the Worker's `capMeta(token_id, 80)`: `"a_" + 60 + "_" + 11
/// = 74 ≤ 80`. Without this cap a long hostname (macOS allows up to 255) would
/// push the random tail past the cap, so every row from that host would collide
/// on `token_id` and `ON CONFLICT(token_id) DO NOTHING` would silently drop them.
fn mint_token_id(agent_id: &str) -> String {
    let mut rnd = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rnd);
    let id: String = agent_id.chars().take(60).collect();
    format!("a_{}_{}", id, URL_SAFE_NO_PAD.encode(rnd))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The serialized `entry.meta` must carry the exact field names the
    /// Worker's `capChallengeMeta` reads — and `ip` must be ABSENT (the Worker
    /// always forces it from CF-Connecting-IP). Any rename here silently breaks
    /// the audit row's display fields.
    #[test]
    fn agent_audit_entry_has_expected_json_keys() {
        let meta = crate::core::ClientMeta {
            user: "u".into(),
            pwd: "/p".into(),
            tty: "/dev/x".into(),
            ppid_cmd: "zsh".into(),
            ssh_client: "1.2.3.4".into(),
        };
        let entry = AgentAuditEntry::build(
            "decrypt", "approved", "host1", &meta, "cmd", "why", Some(4242), 3, 120, "AGENTID",
        );
        let v = serde_json::to_value(&entry).unwrap();

        for k in ["op_kind", "outcome", "salts", "latency_ms", "ts_ms", "token_id", "meta"] {
            assert!(v.get(k).is_some(), "missing sibling field {k}");
        }
        let m = v.get("meta").unwrap();
        for k in [
            "op_kind", "command", "host", "user", "pwd", "tty", "ppid_cmd", "ppid", "ssh_client",
            "reason",
        ] {
            assert!(m.get(k).is_some(), "missing meta field {k}");
        }
        // ip MUST be absent — the ChallengeMeta wire shape has no ip field, and
        // the Worker overwrites it from CF-Connecting-IP.
        assert!(m.get("ip").is_none(), "meta.ip must be absent on the wire");
        assert_eq!(m.get("ppid").unwrap().as_u64().unwrap(), 4242);
        assert_eq!(v["salts"].as_u64().unwrap(), 3);
        assert!(v["token_id"].as_str().unwrap().starts_with("a_AGENTID_"));
    }

    /// Forwarded/remote sessions have no socket peer PID → ppid serializes as 0
    /// (which the Worker reads as absent and stores as 0).
    #[test]
    fn build_with_no_peer_pid_yields_zero_ppid() {
        let entry = AgentAuditEntry::build(
            "auth",
            "approved",
            "h",
            &crate::core::ClientMeta::default(),
            "",
            "",
            None,
            0,
            0,
            "X",
        );
        let v = serde_json::to_value(&entry).unwrap();
        assert_eq!(v["meta"]["ppid"].as_u64().unwrap(), 0);
    }

    /// Config validation: a non-https URL disables; https enables.
    #[test]
    fn config_rejects_non_https() {
        assert!(!AuditPushConfig::new(
            "http://insecure.example".into(),
            Zeroizing::new([1u8; 32]),
            "host".into()
        )
        .enabled);
        assert!(AuditPushConfig::new(
            "https://ok.example".into(),
            Zeroizing::new([1u8; 32]),
            "host".into()
        )
        .enabled);
    }

    /// token_id keeps its random suffix even for a very long hostname, so the
    /// UNIQUE constraint + ON CONFLICT dedup never collapses to one row/host.
    #[test]
    fn token_id_caps_long_hostname() {
        let long = "h".repeat(200);
        let entry = AgentAuditEntry::build(
            "auth", "approved", "h", &crate::core::ClientMeta::default(), "", "", None, 0, 0, &long,
        );
        // "a_" + 60 + "_" + 11 = 74, comfortably under the Worker's 80-char cap.
        assert!(entry.token_id.len() <= 74, "token_id too long: {}", entry.token_id.len());
        assert!(entry.token_id.starts_with("a_hhhhh"));
    }
}
