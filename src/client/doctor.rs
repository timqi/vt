//! `vt doctor` — read-only diagnosis of config, routing, and agent cache
//! behavior, including the dedicated `diag@vt` round-trip.

use std::env;

use super::{parse_envelope, VTClient};
use crate::core::crypto::{decode_auth_cipher_from_b64, AesGcmCrypto};
use crate::core::{sanitize_for_display, ContextBasis};
use anyhow::Result;
use ssh_agent_lib::proto::{Extension, Unparsed};

// ---------------------------------------------------------------------------
// vt doctor — read-only diagnosis of config, routing, and agent cache behavior
// ---------------------------------------------------------------------------

/// Outcome of the dedicated `diag@vt` call. Unlike [`VTClient::try_agent_extension`],
/// the wire shapes stay distinct (see `docs/diag-design.md` §4): an agent that
/// merely *ignores* the unknown extension name (an older vt agent) answers SSH
/// success with an empty payload, which is a different signal from an explicit
/// `SSH_AGENT_FAILURE` (non-vt agent, wrong VT_AUTH, or a locked agent).
#[cfg(unix)]
enum DiagOutcome {
    /// Socket missing/refused — no agent at all.
    NoSocket,
    /// SSH success, empty extension payload: the agent ignored `diag@vt`.
    TooOld,
    /// Explicit failure or an error envelope, with a display string.
    Refused(String),
    /// The agent answered a valid OK envelope whose body doesn't parse as
    /// `DiagRes` — client/agent version skew, not a transport problem.
    Skew(String),
    Report(Box<crate::core::DiagRes>),
}

/// Read/write timeout for the diag round-trip. Every other agent call must
/// wait indefinitely for a human Touch ID; diag@vt is interaction-free by
/// design, so a hung or foreign agent must not hang the doctor.
#[cfg(unix)]
const DIAG_SOCKET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(unix)]
fn call_diag(auth_token: &str) -> Result<DiagOutcome> {
    let stream = match VTClient::connect_agent_socket()? {
        Some(s) => s,
        None => return Ok(DiagOutcome::NoSocket),
    };
    stream.set_read_timeout(Some(DIAG_SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(DIAG_SOCKET_TIMEOUT))?;
    let auth_key = decode_auth_cipher_from_b64(auth_token)?;
    let auth_cipher = AesGcmCrypto::new(&auth_key)?;
    let payload = serde_json::to_vec(&crate::core::DiagReq::default())?;
    let ext = Extension {
        name: "diag@vt".to_string(),
        details: Unparsed::from(auth_cipher.encrypt(&payload)?),
    };
    let mut client = ssh_agent_lib::blocking::Client::new(stream);
    match client.extension(ext) {
        Err(e) => Ok(DiagOutcome::Refused(e.to_string())),
        Ok(None) => Ok(DiagOutcome::TooOld),
        Ok(Some(resp)) => {
            let envelope = match auth_cipher.decrypt(resp.details.as_ref()) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(DiagOutcome::Refused(
                        "response did not decrypt under VT_AUTH".to_string(),
                    ))
                }
            };
            match parse_envelope(&envelope) {
                Ok(body) => match serde_json::from_slice(&body) {
                    Ok(res) => Ok(DiagOutcome::Report(Box::new(res))),
                    Err(e) => Ok(DiagOutcome::Skew(e.to_string())),
                },
                Err(e) => Ok(DiagOutcome::Refused(e.to_string())),
            }
        }
    }
}

/// Map a `ContextBasis` wire tag to an operator-facing explanation. Unknown
/// tags (a newer agent) degrade to naming the tag. The known-tag sentences
/// live on [`ContextBasis::human`] in core, next to `as_wire`, so adding an
/// agent-side variant forces the client sentence at compile time.
fn basis_human(tag: &str) -> String {
    match ContextBasis::from_wire(tag) {
        Some(basis) => basis.human().to_string(),
        None => format!("unknown basis '{}' (newer agent?)", tag),
    }
}

fn doctor_redact(key: &str, value: &str) -> String {
    // Bearer secrets: presence + length is enough to diagnose; showing a
    // prefix in terminal scrollback helps nobody.
    if matches!(key, "VT_AUTH" | "VT_PASSKEY_TOKEN") {
        return format!("set (len {})", value.len());
    }
    // Named PRIVATE_KEY: expected to hold a vt:// ciphertext record — safe to
    // acknowledge, never to echo. If it holds anything else the user has put
    // key material (or garbage) in it; either way don't print a prefix.
    if key == "VT_GIT_SSH_PRIVATE_KEY" {
        return if value.starts_with("vt://") {
            format!("set (vt:// record, len {})", value.len())
        } else {
            format!(
                "set (len {}) ⚠ not a vt:// record — value not shown; \
                 `vt ssh keygen` produces the expected format",
                value.len()
            )
        };
    }
    // Non-secrets: strip control chars (terminal-escape hygiene, same as
    // every other display surface) and truncate char-safely.
    let shown = sanitize_for_display(value, 60);
    if value.chars().count() > 60 {
        format!("{} (len {})", shown, value.len())
    } else {
        shown
    }
}

/// `vt doctor`: diagnose config sources, transport routing, and (when an
/// agent is reachable) cache behavior via `diag@vt`. Read-only, never
/// hard-fails on findings — always exits 0; see `docs/diag-design.md`.
pub async fn doctor(auth_token: &str, file_populated_keys: &[String]) -> Result<()> {
    println!("vt doctor — vt {}", env!("VT_VERSION"));

    // ── 1. Config ─────────────────────────────────────────────────────────
    println!("\nConfig (env beats config.toml):");
    match crate::config::config_path() {
        Some(path) if path.exists() => {
            println!("  file: {}", path.display());
            if let Some(mode) = crate::config::insecure_config_mode(&path) {
                println!(
                    "  ⚠ file is group/other accessible (mode {:o}); it holds \
                     secrets — run: chmod 600 {}",
                    mode,
                    path.display()
                );
            }
        }
        Some(path) => println!("  file: {} (absent — env vars only)", path.display()),
        None => println!("  file: none (no home directory and no $VT_CONFIG)"),
    }
    const DOCTOR_KEYS: &[&str] = &[
        "VT_BACKEND",
        "VT_AUTH",
        "VT_PASSKEY_URL",
        "VT_PASSKEY_TOKEN",
        "VT_GIT_SSH_PRIVATE_KEY",
        "VT_GIT_SSH_PUB",
        "VT_AGENT_CONFIG",
    ];
    for key in DOCTOR_KEYS {
        match env::var(key) {
            Ok(v) => {
                let source = if file_populated_keys.iter().any(|k| k == key) {
                    "config.toml"
                } else {
                    "env"
                };
                if v.is_empty() {
                    println!("  {:24} set but EMPTY ({})", key, source);
                } else {
                    println!("  {:24} {} ({})", key, doctor_redact(key, &v), source);
                }
            }
            Err(_) => println!("  {:24} unset", key),
        }
    }
    // A typo'd key (VT_PASKEY_URL…) hydrates silently and is the single most
    // likely config bug this command is run to find — surface names only.
    let unrecognized: Vec<&str> = file_populated_keys
        .iter()
        .map(String::as_str)
        .filter(|k| !DOCTOR_KEYS.contains(k))
        .collect();
    if !unrecognized.is_empty() {
        println!(
            "  ⚠ config.toml also sets: {} — not a key vt doctor knows; \
             check for typos",
            unrecognized.join(", ")
        );
    }

    // ── 2. Routing ────────────────────────────────────────────────────────
    // NOTE: mirrors VTClient::new (validation) + agent_call_or_fallback
    // (fallback gating: recoverable agent errors ALWAYS fall back under
    // auto, regardless of whether the passkey path is configured). When
    // changing either, keep this report in lockstep.
    println!("\nRouting:");
    let has_auth = !auth_token.is_empty();
    let has_passkey_url = env::var("VT_PASSKEY_URL").is_ok();
    let has_passkey_token = env::var("VT_PASSKEY_TOKEN").is_ok();
    let passkey_state = match (has_passkey_url, has_passkey_token) {
        (true, true) => "configured",
        (true, false) => "incomplete (VT_PASSKEY_TOKEN unset)",
        (false, true) => "incomplete (VT_PASSKEY_URL unset)",
        (false, false) => "unconfigured",
    };
    match crate::config::Backend::from_env() {
        Err(e) => println!("  ⚠ {}", e),
        Ok(crate::config::Backend::Agent) => {
            if has_auth {
                println!("  VT_BACKEND=agent: SSH agent only, no passkey fallback");
            } else {
                println!("  ⚠ VT_BACKEND=agent but VT_AUTH is unset — every call will fail");
            }
        }
        Ok(crate::config::Backend::Passkey) => {
            // Same precondition VTClient::new enforces (URL only) — plus the
            // token warning it defers to ceremony time.
            if !has_passkey_url {
                println!(
                    "  ⚠ VT_BACKEND=passkey but VT_PASSKEY_URL is unset — every call will fail"
                );
            } else if !has_passkey_token {
                println!(
                    "  VT_BACKEND=passkey: phone ceremony only — ⚠ VT_PASSKEY_TOKEN unset, \
                     ceremonies will fail"
                );
            } else {
                println!("  VT_BACKEND=passkey: phone ceremony only, agent never probed");
            }
        }
        Ok(crate::config::Backend::Auto) => match (has_auth, has_passkey_url && has_passkey_token)
        {
            (true, true) => println!(
                "  auto: try SSH agent first, fall back to phone passkey on \
                 recoverable errors"
            ),
            (true, false) => println!(
                "  auto: SSH agent first; recoverable agent errors still fall back \
                 to the passkey path, which is {} and will error there",
                passkey_state
            ),
            (false, true) => println!("  auto: phone passkey only (VT_AUTH unset — agent skipped)"),
            (false, false) => println!(
                "  ⚠ no usable path: VT_AUTH unset and passkey {} — vt commands \
                 needing auth will fail",
                passkey_state
            ),
        },
    }

    // ── 3. Agent (diag@vt) ────────────────────────────────────────────────
    println!("\nAgent:");
    let socket = env::var("SSH_AUTH_SOCK")
        .unwrap_or_else(|_| "~/.ssh/vt.sock (default; $SSH_AUTH_SOCK unset)".to_string());
    println!("  socket: {}", socket);
    #[cfg(unix)]
    if !has_auth {
        println!("  agent path disabled (VT_AUTH unset) — diag@vt skipped");
    } else {
        let token = auth_token.to_string();
        // Never hard-fail the report (doctor's contract): a panicked probe
        // (outer Err) is itself a finding, printed like any other.
        match tokio::task::spawn_blocking(move || call_diag(&token))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r)
        {
            Err(e) => println!("  ⚠ diag@vt transport error: {}", e),
            Ok(DiagOutcome::NoSocket) => {
                println!("  no agent listening (socket missing or connection refused)")
            }
            Ok(DiagOutcome::TooOld) => println!(
                "  agent reachable but ignored diag@vt — a vt agent older than \
                 this client (rebuild/restart it), or a non-vt agent"
            ),
            Ok(DiagOutcome::Refused(e)) => println!(
                "  agent refused diag@vt ({}). Likely causes: a `vt ssh connect` \
                 relay running without --forward-real-agent (or built before \
                 diag@vt existed), a non-vt agent, wrong VT_AUTH, an agent \
                 locked via ssh-add -x, or a dropped connection",
                e
            ),
            Ok(DiagOutcome::Skew(e)) => println!(
                "  agent answered but the reply didn't parse as a diag report \
                 ({}) — client/agent version skew; rebuild both from the same \
                 commit",
                e
            ),
            Ok(DiagOutcome::Report(d)) => {
                println!("  agent version: {}", d.agent_version);
                // The agent is a long-lived daemon and does not restart on CLI
                // upgrade — skew is common right after an update and changes
                // scope/diag behavior silently.
                if d.agent_version != env!("VT_VERSION") {
                    println!(
                        "  ⚠ agent is {}, this client is {} — restart the agent \
                         (`vt ssh agent`) so both run the same build",
                        d.agent_version,
                        env!("VT_VERSION")
                    );
                }
                // Over --forward-real-agent the upstream agent's peer is the
                // relay process on the agent's host — that IS the connection
                // relayed requests ride, so label it honestly.
                let peer_label = if d.peer.is_vt_relay {
                    "peer (the relay process on the agent host)"
                } else {
                    "peer (this process)"
                };
                println!(
                    "  {}: pid {}, exe {}, tty {}, ssh-client {}, vt-relay {}",
                    peer_label,
                    d.peer.pid.map_or("?".to_string(), |p| p.to_string()),
                    d.peer.exe.as_deref().unwrap_or("?"),
                    if d.peer.has_tty { "yes" } else { "no" },
                    if d.peer.is_ssh_client { "yes" } else { "no" },
                    if d.peer.is_vt_relay { "yes" } else { "no" },
                );
                for (label, c) in [("sign", &d.sign_cache), ("decrypt", &d.decrypt_cache)] {
                    println!(
                        "  {:8} ttl {}s, live grants (this caller): {}",
                        format!("{}:", label),
                        c.ttl_secs,
                        c.live_entries
                    );
                    println!("           → {}", basis_human(&c.context_basis));
                }
                println!(
                    "  run@vt: {}; audit push: {}",
                    if d.run_allow_len == 0 {
                        "disabled".to_string()
                    } else {
                        format!("{} allowlist entries", d.run_allow_len)
                    },
                    if d.audit_push { "on" } else { "off" }
                );
                println!(
                    "  (classification applies to connections opened the way this \
                     one was; a different launcher may classify differently)"
                );
            }
        }
    }

    // ── 4. Worker ─────────────────────────────────────────────────────────
    println!("\nWorker:");
    match env::var("VT_PASSKEY_URL") {
        Err(_) => println!("  not configured (VT_PASSKEY_URL unset)"),
        Ok(url) => {
            // Doctor never hard-fails: a TLS-init error is reported, not raised.
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
            {
                Err(e) => println!("  ⚠ could not build HTTP client: {}", e),
                Ok(client) => match client.get(&url).send().await {
                    Ok(resp) => {
                        println!("  {} reachable (HTTP {})", url, resp.status().as_u16())
                    }
                    Err(e) => println!("  ⚠ {} unreachable: {}", url, e),
                },
            }
            if env::var("VT_PASSKEY_TOKEN").is_err() {
                println!("  ⚠ VT_PASSKEY_URL set but VT_PASSKEY_TOKEN unset");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── vt doctor ────────────────────────────────────────────────────────

    #[test]
    fn doctor_redact_hides_secrets_and_truncates_on_char_boundaries() {
        // Bearer secrets never echo their value.
        let r = doctor_redact("VT_AUTH", "supersecrettoken");
        assert!(!r.contains("supersecret"), "got {r}");
        assert!(r.contains("len 16"));
        // The private-key slot acknowledges a vt:// record but never echoes
        // the value — not even a prefix — when it holds anything else.
        let r = doctor_redact("VT_GIT_SSH_PRIVATE_KEY", "vt://0abcdef");
        assert!(r.contains("vt:// record"), "got {r}");
        assert!(!r.contains("abcdef"), "got {r}");
        let raw_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA";
        let r = doctor_redact("VT_GIT_SSH_PRIVATE_KEY", raw_key);
        assert!(!r.contains("BEGIN"), "must not echo key material, got {r}");
        assert!(r.contains("not a vt:// record"), "got {r}");
        // Long non-secrets truncate by CHARS, not bytes — a multi-byte char
        // spanning the cut must not panic — and control chars are stripped
        // (terminal-escape hygiene via sanitize_for_display).
        let long = "变".repeat(61);
        let r = doctor_redact("VT_GIT_SSH_PUB", &long);
        assert!(r.ends_with(&format!("… (len {})", long.len())));
        assert_eq!(r.chars().take_while(|c| *c == '变').count(), 60);
        assert_eq!(doctor_redact("VT_BACKEND", "au\x1b[31mto"), "au[31mto");
        // Short values pass through verbatim.
        assert_eq!(doctor_redact("VT_BACKEND", "auto"), "auto");
    }

    #[test]
    fn doctor_basis_human_known_and_unknown_tags() {
        // Known-tag sentences are compile-checked on ContextBasis::human in
        // core (adding a variant forces an arm); here pin the two doctor-side
        // behaviors: wire tags resolve, unknown tags degrade by naming the tag.
        assert_eq!(
            basis_human("session-bind"),
            crate::core::ContextBasis::SessionBind.human()
        );
        assert!(basis_human("future-tag").contains("future-tag"));
    }

    #[test]
    fn diag_wire_round_trip() {
        // Client-side view of the agent's DiagRes JSON — pins the field names
        // the macOS handler serializes (they cross the wire; renames break
        // old clients).
        let json = r#"{
            "agent_version": "v1",
            "sign_cache": {"ttl_secs":120,"live_entries":1,"context_basis":"session-bind"},
            "decrypt_cache": {"ttl_secs":30,"live_entries":0,"context_basis":"disabled"},
            "peer": {"pid":42,"exe":"zsh","has_tty":true,"is_ssh_client":false,"is_vt_relay":false},
            "run_allow_len": 0,
            "audit_push": false
        }"#;
        let d: crate::core::DiagRes = serde_json::from_str(json).unwrap();
        assert_eq!(d.sign_cache.context_basis, "session-bind");
        assert_eq!(d.decrypt_cache.live_entries, 0);
        assert_eq!(d.peer.exe.as_deref(), Some("zsh"));
        // And the request serializes to an (empty) object.
        assert_eq!(
            serde_json::to_string(&crate::core::DiagReq::default()).unwrap(),
            "{}"
        );
    }
}
