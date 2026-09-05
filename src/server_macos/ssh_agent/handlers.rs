//! Extension operations return serialized bodies and uncommitted permits.
//! The parent dispatcher alone encrypts responses, commits, and notifies.

use std::sync::atomic::Ordering;

use anyhow::Result;
use rand::RngCore;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Extension, Unparsed};
use ssh_key::public::KeyData;
use zeroize::{Zeroize, Zeroizing};

use super::super::security::{load_mac_cipher, validate_mac_key_material};
use super::super::store::KeychainStore;
use super::scopes::append_reuse_line;
use super::{
    agent_err, authorization_failure_wire, cache_hit_note_for, fingerprint_str, sanitize_prompt,
    sanitize_prompt_multiline, sign_data_with_privkey, spawn_detached, HandlerSuccess,
    VtSshSession, WireFailure, DETAIL_BAD_REQUEST_JSON, DETAIL_BATCH_EMPTY, DETAIL_BATCH_TOO_LARGE,
    DETAIL_DISPLAY_FIELD_TOO_LARGE, DETAIL_INTERNAL_SERIALIZE, DETAIL_LEGACY_DISABLED,
    DETAIL_NOT_INITIALIZED, DETAIL_RUN_ARGV_EMPTY, DETAIL_RUN_ARGV_TOO_LARGE, DETAIL_RUN_DISABLED,
    DETAIL_RUN_NOT_ALLOWLISTED, DETAIL_RUN_SPAWN_FAILED, DETAIL_SIGN_BAD_PUBKEY,
    DETAIL_SIGN_FAILED, DETAIL_SIGN_KEYS_LOAD, DETAIL_SIGN_KEY_NOT_IN_AGENT,
    DETAIL_UNKNOWN_SECRET_TYPE, MAX_CRYPTO_BATCH, PROMPT_COMMAND_MAX_LINES,
    PROMPT_COMMAND_MAX_LINE_LEN, PROMPT_DISPLAY_MAX_BYTES, RUN_PROMPT_ARGV_MAX,
    RUN_REQ_ARGV_MAX_BYTES,
};
use crate::core::authorization::{AuthorizationRequest, GrantScope, Operation, ReusePolicy};
use crate::core::crypto::{derive_dek, AesGcmCrypto};
use crate::core::wire::ErrKind;
use crate::core::{
    legacy_decrypt, AuthReq, AuthRes, DecryptInput, DecryptReq, DecryptResItem, DiagCacheReport,
    DiagPeerReport, DiagReq, DiagRes, EncryptReq, EncryptResItem, RunReq, RunRes, SignReq, SignRes,
    UiStatusReq, UiStatusRes, SALT_LEN,
};

fn plural_secrets(n: usize) -> &'static str {
    if n == 1 {
        "secret"
    } else {
        "secrets"
    }
}

/// First line of every Touch ID prompt: `"{verb}"` for old clients that
/// don't send `meta.user`/`host`, or `"{verb} {prep} {who}"` when we have
/// somewhere to attribute the request to. `prep` is per-call ("on" for
/// decrypt/auth on the box; "from" for `run` which spawns *on* this Mac
/// but *originates* on the remote host).
fn header_with_who(verb: &str, prep: &str, who: &str) -> String {
    if who.is_empty() {
        verb.to_string()
    } else {
        format!("{} {} {}", verb, prep, who)
    }
}

/// Render `user@host`, omitting either side when empty so the prompt
/// degrades gracefully for old clients that don't send `meta.user`.
fn who_at_host(user: &str, host: &str) -> String {
    let u = sanitize_prompt(user, 40);
    let h = sanitize_prompt(host, 60);
    match (u.is_empty(), h.is_empty()) {
        (true, true) => String::new(),
        (true, false) => h,
        (false, true) => u,
        (false, false) => format!("{}@{}", u, h),
    }
}

/// Append the extra context lines (pwd, parent process, ssh-from) to the
/// Touch ID prompt body. Each is on its own line — `LAContext`'s
/// `localizedReason` renders multi-line strings. Empty fields are skipped so
/// the prompt stays compact for old clients.
fn append_meta_lines(message: &mut String, meta: &crate::core::ClientMeta) {
    if !meta.pwd.is_empty() {
        message.push_str("\npwd: ");
        message.push_str(&sanitize_prompt(&meta.pwd, 100));
    }
    if !meta.ppid_cmd.is_empty() {
        message.push_str("\nvia: ");
        message.push_str(&sanitize_prompt(&meta.ppid_cmd, 100));
    }
    if !meta.ssh_client.is_empty() {
        message.push_str("\nssh: ");
        message.push_str(&sanitize_prompt(&meta.ssh_client, 80));
    }
}

impl VtSshSession {
    // ---- Structured-envelope dispatch helpers --------------------------------
    //
    // Each `handle_*` returns either the inner JSON body (DEKs included for
    // encrypt/decrypt, wrapped in Zeroizing) or a `(ErrKind, Option<&'static
    // str>)` failure that the caller serializes into `ExtResponse::Err`. The
    // `detail` string is bounded to the `DETAIL_*` allow-list defined below
    // so dynamic user-supplied data (host, command, reason, fingerprints)
    // can never leak across `auth@vt` over a forwarded socket.

    pub(super) async fn handle_encrypt(
        &self,
        decrypted: &[u8],
        store: &KeychainStore,
        passphrase_cipher: &AesGcmCrypto,
    ) -> Result<HandlerSuccess, WireFailure> {
        // v2 envelope: agent allocates a fresh per-record (salt, DEK) pair
        // for each requested SecretType. The agent NEVER receives plaintext
        // on this path. The salt is generated server-side (never accepted
        // from the client) — this is the security invariant that prevents
        // an attacker holding `VT_AUTH` from extracting a salt from a
        // stored vt://0{salt||ct} URL and requesting its DEK to bypass
        // Touch ID.
        let req: EncryptReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;
        if req.types.len() > MAX_CRYPTO_BATCH {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_TOO_LARGE)));
        }
        let (_mac_cipher, mac_key) = load_mac_cipher(store, passphrase_cipher)
            .map_err(|_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED)))?;
        let mut result: Vec<EncryptResItem> = Vec::with_capacity(req.types.len());
        for _t in &req.types {
            let mut salt = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            let dek = derive_dek(&mac_key, &salt);
            result.push(EncryptResItem {
                salt,
                dek,
                err_message: String::new(),
            });
        }
        drop(mac_key);
        let bytes = serde_json::to_vec(&result)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?;
        // The DEKs now live inside `bytes`; scrub the in-memory
        // `Vec<EncryptResItem>` copy before it falls out of scope.
        for item in result.iter_mut() {
            item.dek.zeroize();
        }
        // encrypt@vt has no Touch ID gate; record the mint as `approved` so the
        // audit shows "agent minted N DEKs". EncryptReq carries no client meta,
        // so host/meta are empty. latency 0 (no prompt).
        self.emit_audit(
            "encrypt",
            "approved",
            "",
            &crate::core::ClientMeta::default(),
            "",
            "",
            req.types.len(),
            0,
            self.audit_ctx(),
        );
        Ok(HandlerSuccess::without_authorization(Zeroizing::new(bytes)))
    }

    pub(super) async fn handle_decrypt(
        &self,
        decrypted: &[u8],
        store: &KeychainStore,
        passphrase_cipher: &AesGcmCrypto,
    ) -> Result<HandlerSuccess, WireFailure> {
        let req: DecryptReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        if req.command.len() > PROMPT_DISPLAY_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_DISPLAY_FIELD_TOO_LARGE)));
        }
        if req.items.len() > MAX_CRYPTO_BATCH {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_TOO_LARGE)));
        }
        // An empty batch has nothing to authorize; without this guard it
        // would fall through to the uncached always-prompt path and put a
        // "decrypt 0 secrets" dialog in front of the user — free prompt spam
        // for any peer holding VT_AUTH.
        if req.items.is_empty() {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_EMPTY)));
        }

        // Reject `SecretType::UNKNOWN` v2 items: serde would otherwise
        // accept them from a malformed `DecryptInput::V2`, the downstream
        // decrypt would fail on AAD mismatch, but the cache could be
        // polluted with `t.as_byte() == b'_'` entries in the meantime.
        let mut legacy_count = 0usize;
        let mut v2_inputs: Vec<(crate::core::SecretType, [u8; SALT_LEN])> =
            Vec::with_capacity(req.items.len());
        for item in &req.items {
            match item {
                DecryptInput::V2 {
                    t: crate::core::SecretType::UNKNOWN,
                    ..
                } => {
                    tracing::warn!("decrypt@vt rejecting v2 item with UNKNOWN type");
                    return Err((ErrKind::BadRequest, Some(DETAIL_UNKNOWN_SECRET_TYPE)));
                }
                DecryptInput::V2 { t, salt } => v2_inputs.push((*t, *salt)),
                DecryptInput::Legacy { .. } => legacy_count += 1,
            }
        }

        // Fail fast on `--no-legacy-decrypt`: if the agent is configured to
        // reject legacy URLs, surface a dedicated kind before prompting the
        // user. We still let pure-v2 batches through here.
        if self.disable_legacy_decrypt && legacy_count > 0 {
            return Err((ErrKind::LegacyDisabled, Some(DETAIL_LEGACY_DISABLED)));
        }

        // Verify that the stored master key is present and decryptable before
        // consulting reusable authorization state or prompting. Drop this
        // short-lived copy immediately; the operation reloads it only after a
        // permit is obtained, so raw key material is not held across a human
        // prompt. Validation is deterministic over the already-loaded store
        // and passphrase cipher, making the later load a non-fallible
        // precondition in normal operation while retaining defensive mapping.
        validate_mac_key_material(store, passphrase_cipher)
            .map_err(|_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED)))?;

        let who = who_at_host(&req.meta.user, &req.host);
        let n = req.items.len();
        let mut local_auth_message =
            header_with_who(&format!("decrypt {} {}", n, plural_secrets(n)), "on", &who);
        self.append_relay_origin(&mut local_auth_message);
        self.append_caller_line(&mut local_auth_message);
        // Pure-v2 batches use one atomic scope per record and require an all-of
        // hit. Any legacy member makes the entire request explicitly Fresh.
        // The reuse line is agent-derived truth and is appended BEFORE the
        // client-reported body/meta below, for the same reason as the relay
        // origin marker: a hostile caller must not be able to pad the one
        // line that says the tap creates a standing grant off-screen.
        let (scopes, reuse, reuse_label) = if legacy_count > 0 {
            (
                vec![GrantScope::fresh(Operation::Decrypt)],
                ReusePolicy::Fresh,
                None,
            )
        } else {
            let (scopes, reuse_label) = self.decrypt_scopes(&v2_inputs, &req.host, &req.meta.pwd);
            let display = reuse_label.clone().unwrap_or_default();
            let scopes: Vec<GrantScope> = scopes
                .into_iter()
                .map(|scope| scope.with_display(display.clone()))
                .collect();
            append_reuse_line(
                &mut local_auth_message,
                &reuse_label,
                self.cache_ttls.decrypt_secs,
            );
            (
                scopes,
                ReusePolicy::from_ttl_secs(self.cache_ttls.decrypt_secs),
                reuse_label,
            )
        };
        let audit_ctx = self.audit_ctx_scoped(
            scopes.first().and_then(GrantScope::family),
            &reuse_label,
            self.cache_ttls.decrypt_secs,
        );
        let body = sanitize_prompt_multiline(
            &req.command,
            PROMPT_COMMAND_MAX_LINE_LEN,
            PROMPT_COMMAND_MAX_LINES,
        );
        if !body.is_empty() {
            local_auth_message.push('\n');
            local_auth_message.push_str(&body);
        }
        append_meta_lines(&mut local_auth_message, &req.meta);
        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::new(scopes, reuse, local_auth_message))
            .await
        {
            Ok(permit) => {
                self.emit_audit(
                    "decrypt",
                    permit.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &req.command,
                    "",
                    req.items.len(),
                    permit.latency_ms(),
                    audit_ctx,
                );
                permit
            }
            Err(failure) => {
                self.emit_audit(
                    "decrypt",
                    failure.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &req.command,
                    "",
                    req.items.len(),
                    failure.latency_ms(),
                    audit_ctx,
                );
                return Err(authorization_failure_wire(&failure));
            }
        };
        let (mac_cipher, mac_key) = load_mac_cipher(store, passphrase_cipher)
            .map_err(|_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED)))?;
        let mut result: Vec<DecryptResItem> = Vec::with_capacity(req.items.len());
        for item in req.items {
            match item {
                DecryptInput::V2 { t: _, salt } => {
                    let dek = derive_dek(&mac_key, &salt);
                    result.push(DecryptResItem::V2 {
                        dek,
                        err_message: String::new(),
                    });
                }
                DecryptInput::Legacy { url } => {
                    if self.disable_legacy_decrypt {
                        // Should be unreachable: we returned LegacyDisabled
                        // above before prompting. Keep a defensive arm so
                        // the per-item err is still well-formed.
                        result.push(DecryptResItem::Legacy {
                            result: String::new(),
                            err_message: "legacy decryption disabled on this agent".to_string(),
                        });
                    } else {
                        let item = legacy_decrypt(&mac_cipher, &url);
                        result.push(DecryptResItem::Legacy {
                            result: item.result,
                            err_message: item.err_message,
                        });
                    }
                }
            }
        }
        drop(mac_key);
        let bytes = Zeroizing::new(
            serde_json::to_vec(&result)
                .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?,
        );
        // Scrub DEKs inside the response Vec before drop. `bytes` already
        // carries them (still wiped via `Zeroizing` below).
        for item in result.iter_mut() {
            if let DecryptResItem::V2 { dek, .. } = item {
                dek.zeroize();
            }
        }
        let note = cache_hit_note_for(&permit, "decrypt", &reuse_label);
        Ok(HandlerSuccess::authorized(bytes, permit).with_cache_hit_note(note))
    }

    pub(super) async fn handle_auth(
        &self,
        decrypted: &[u8],
    ) -> Result<HandlerSuccess, WireFailure> {
        let req: AuthReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        if req.reason.len() > PROMPT_DISPLAY_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_DISPLAY_FIELD_TOO_LARGE)));
        }

        let who = who_at_host(&req.meta.user, &req.host);
        let mut auth_message = header_with_who("auth", "on", &who);
        self.append_relay_origin(&mut auth_message);
        self.append_caller_line(&mut auth_message);
        let reason = sanitize_prompt(&req.reason, 100);
        if !reason.is_empty() {
            auth_message.push_str("\nreason: ");
            auth_message.push_str(&reason);
        }
        append_meta_lines(&mut auth_message, &req.meta);

        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::fresh(
                GrantScope::fresh(Operation::Auth),
                auth_message,
            ))
            .await
        {
            Ok(permit) => {
                self.emit_audit(
                    "auth",
                    permit.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    "",
                    &req.reason,
                    0,
                    permit.latency_ms(),
                    self.audit_ctx(),
                );
                permit
            }
            Err(failure) => {
                self.emit_audit(
                    "auth",
                    failure.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    "",
                    &req.reason,
                    0,
                    failure.latency_ms(),
                    self.audit_ctx(),
                );
                return Err(authorization_failure_wire(&failure));
            }
        };

        let result = AuthRes { approved: true };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&result)
                .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?,
        );
        Ok(HandlerSuccess::authorized(bytes, permit))
    }

    /// `diag@vt`: read-only diagnostics for `vt doctor`. No Touch ID (it
    /// discloses no secret and mints no DEK), never cached, not audit-pushed
    /// (no human decision to record), and — enforced in `extension()` — it
    /// does not reset the idle-activity clock. `live_entries` is scoped to
    /// THIS connection's resolved context; see `docs/diag-design.md` §3.4 for
    /// the accepted disclosure tradeoffs.
    pub(super) async fn handle_diag(
        &self,
        decrypted: &[u8],
    ) -> Result<HandlerSuccess, WireFailure> {
        let _req: DiagReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        let peer = DiagPeerReport {
            pid: self.peer_pid,
            exe: self.peer_exe.clone(),
            has_tty: self.peer_has_tty(),
            is_ssh_client: self.peer_is_ssh_client,
            is_vt_relay: self.peer_is_vt_relay,
        };
        // live_entries counts only grants THIS connection's own scope
        // classification could reuse — never a whole-store count, and never
        // grants a differently-classified caller would need. A caller whose
        // basis says "never cached" therefore always reports 0.
        let sign_basis = self.sign_basis();
        let sign_live = self.live_grants(sign_basis, Operation::Sign).await;
        let decrypt_basis = self.decrypt_basis();
        let decrypt_live = self.live_grants(decrypt_basis, Operation::Decrypt).await;
        let sign_cache = DiagCacheReport {
            ttl_secs: self.cache_ttls.sign_secs,
            live_entries: sign_live,
            context_basis: sign_basis.as_wire().to_string(),
        };
        let decrypt_cache = DiagCacheReport {
            ttl_secs: self.cache_ttls.decrypt_secs,
            live_entries: decrypt_live,
            context_basis: decrypt_basis.as_wire().to_string(),
        };
        let result = DiagRes {
            agent_version: env!("VT_VERSION").to_string(),
            sign_cache,
            decrypt_cache,
            peer,
            run_allow_len: self.run_allow.len(),
            audit_push: self.audit_push.enabled,
        };
        Ok(HandlerSuccess::without_authorization(Zeroizing::new(
            serde_json::to_vec(&result)
                .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?,
        )))
    }

    /// `ui-status@vt` (docs/app-bundle.md §5): plaintext, token-gated
    /// status/revoke channel for the VT.app shell. Runs BEFORE the lock
    /// check and the VT_AUTH cipher path, never touches the idle clock, is
    /// never cached and never audit-pushed. The only whole-store grant
    /// visibility in the agent — every failure mode is an unstructured
    /// `AgentError::Failure` so a prober without the token cannot even
    /// distinguish "agent without token" from "unknown extension".
    pub(super) async fn handle_ui_status(
        &self,
        extension: &Extension,
    ) -> Result<Option<Extension>, AgentError> {
        use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
        use subtle::ConstantTimeEq;

        let req: UiStatusReq =
            serde_json::from_slice(extension.details.as_ref()).map_err(|_| AgentError::Failure)?;
        // Constant-time token compare, same idiom as `unlock()`. A
        // CLI-started agent has no token and refuses every request.
        let authorized = match (&self.ui_token, BASE64_URL_SAFE_NO_PAD.decode(&req.token)) {
            (Some(expected), Ok(candidate)) if candidate.len() == 32 => {
                expected.ct_eq(candidate.as_slice()).into()
            }
            _ => false,
        };
        if !authorized {
            return Err(AgentError::Failure);
        }

        let revoked = match req.action.as_str() {
            crate::core::UI_STATUS_ACTION_STATUS => None,
            // Authority-reducing only: reuses the linearized revoker, so the
            // epoch advances even when the store is empty and an in-flight
            // prompt cannot recreate a revoked grant. May wait while a live
            // permit holds the security gate — the shell shows "waiting for
            // the in-flight approval".
            crate::core::UI_STATUS_ACTION_REVOKE_ALL => {
                Some(self.authorization.invalidate_all().await)
            }
            _ => return Err(AgentError::Failure),
        };
        let res = UiStatusRes {
            agent_version: env!("VT_VERSION").to_string(),
            locked: self.locked.load(Ordering::Acquire),
            sign_ttl_secs: self.cache_ttls.sign_secs,
            decrypt_ttl_secs: self.cache_ttls.decrypt_secs,
            idle_timeout_secs: self.idle_timeout_secs,
            run_allow_len: self.run_allow.len(),
            audit_push: self.audit_push.enabled,
            revoked,
            grants: self.authorization.snapshot().await,
        };
        let bytes = serde_json::to_vec(&res).map_err(|e| agent_err(e.into()))?;
        Ok(Some(Extension {
            name: extension.name.clone(),
            details: Unparsed::from(bytes),
        }))
    }

    /// Touch-ID-gated local command launcher. Every call prompts — no auth
    /// cache, by design. Mirrors the auth@vt policy: forwarded agents share
    /// a single local process, so caching would let any one remote session's
    /// approval be reused by every other session's request, defeating the
    /// guarantee that each `vt run` is acknowledged by a human tap.
    ///
    /// Returns the structured envelope body for the OK arm (`RunRes`) or an
    /// `(ErrKind, detail)` pair the dispatcher turns into `ExtResponse::Err`.
    pub(super) async fn handle_run(&self, decrypted: &[u8]) -> Result<HandlerSuccess, WireFailure> {
        let req: RunReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        // Fast-fail before any user interaction --------------------------------
        if self.run_allow.is_empty() {
            return Err((ErrKind::BadRequest, Some(DETAIL_RUN_DISABLED)));
        }
        if req.argv.is_empty() {
            return Err((ErrKind::BadRequest, Some(DETAIL_RUN_ARGV_EMPTY)));
        }
        let argv_total: usize = req.argv.iter().map(|s| s.len()).sum();
        if argv_total > RUN_REQ_ARGV_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_RUN_ARGV_TOO_LARGE)));
        }
        // NUL bytes in any argv string would either be rejected by `Command`
        // later or, worse, silently truncated by some downstream consumers.
        // Reject up front with a stable static reason.
        if req.argv.iter().any(|s| s.contains('\0')) {
            return Err((ErrKind::BadRequest, Some(DETAIL_RUN_ARGV_EMPTY)));
        }

        let resolved = self.run_allow.resolve(&req.argv[0]).map_err(|why| {
            tracing::warn!("run@vt rejected: {} (argv0={:?})", why, &req.argv[0]);
            (ErrKind::BadRequest, Some(DETAIL_RUN_NOT_ALLOWLISTED))
        })?;

        // Build the Touch ID message. The resolved canonical path is shown on
        // its own line so the user is approving the *resolved* program, not
        // the (potentially confusing) raw argv[0] from a remote peer.
        let who = who_at_host(&req.meta.user, &req.host);
        let argv_joined: String = req
            .argv
            .iter()
            .map(|a| sanitize_prompt(a, 80))
            .collect::<Vec<_>>()
            .join(" ");
        let argv_for_prompt = sanitize_prompt(&argv_joined, RUN_PROMPT_ARGV_MAX);
        let exe_display = sanitize_prompt(&resolved.display().to_string(), 160);
        let mut auth_message = header_with_who("run on this Mac", "from", &who);
        // The vt relay refuses run@vt, so the relay marker is a dead path
        // today — kept for uniformity with the other extension prompts as
        // cheap insurance against a future relay-filter change.
        self.append_relay_origin(&mut auth_message);
        self.append_caller_line(&mut auth_message);
        auth_message.push_str("\nexe: ");
        auth_message.push_str(&exe_display);
        auth_message.push_str("\nargv: ");
        auth_message.push_str(&argv_for_prompt);
        if let Some(reason) = req.reason.as_deref() {
            if !reason.is_empty() {
                auth_message.push_str("\nreason: ");
                auth_message.push_str(&sanitize_prompt(reason, 120));
            }
        }
        append_meta_lines(&mut auth_message, &req.meta);

        // Validation, allowlist resolution, and canonicalization above all run
        // before authorization. run@vt uses the shared engine but an explicit
        // Fresh policy, so every invocation still requires a human approval.
        let run_command = format!("exe: {}\nargv: {}", exe_display, argv_for_prompt);
        let run_reason = req.reason.as_deref().unwrap_or("");
        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::fresh(
                GrantScope::fresh(Operation::Run),
                auth_message,
            ))
            .await
        {
            Ok(permit) => permit,
            Err(failure) => {
                self.emit_audit(
                    "run",
                    failure.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &run_command,
                    run_reason,
                    0,
                    failure.latency_ms(),
                    self.audit_ctx(),
                );
                return Err(authorization_failure_wire(&failure));
            }
        };
        // Q5: emit `approved` at the human tap, BEFORE the spawn attempt, so a
        // denied launch (below) is distinguishable from a failed one (two rows).
        self.emit_audit(
            "run",
            permit.decision().audit_outcome(),
            &req.host,
            &req.meta,
            &run_command,
            run_reason,
            0,
            permit.latency_ms(),
            self.audit_ctx(),
        );

        // Spawn detached. `setsid` makes the child a new session leader so it
        // survives agent exit; closing fds 3..1024 prevents the child from
        // inheriting the agent's listener / keychain / tokio fds; redirecting
        // stdio to /dev/null means no remote channel back. The child inherits
        // the agent's UID and macOS TCC grants — that is intentional for a
        // GUI launcher (e.g. `zed` needs disk access) but documented here so
        // future maintainers don't accidentally widen what `run@vt` is.
        let pid = match spawn_detached(&resolved, &req.argv[1..]) {
            Ok(pid) => pid,
            Err(e) => {
                tracing::warn!("run@vt spawn failed: {}", e);
                // Second row: the launch was approved but failed to spawn.
                self.emit_audit(
                    "run",
                    "spawn_failed",
                    &req.host,
                    &req.meta,
                    &run_command,
                    run_reason,
                    0,
                    0,
                    self.audit_ctx(),
                );
                return Err((ErrKind::Generic, Some(DETAIL_RUN_SPAWN_FAILED)));
            }
        };
        tracing::info!(
            "run@vt: spawned pid={} exe={} from={}",
            pid,
            resolved.display(),
            who,
        );

        let result = RunRes { pid };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&result)
                .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?,
        );
        Ok(HandlerSuccess::authorized(bytes, permit))
    }

    /// `sign@vt`: VT_AUTH-gated signing with a Keychain-held key, displaying vt
    /// execution context (host/command/meta) in the Touch ID prompt. Unlike the
    /// standard `SIGN_REQUEST` path, the request is authenticated by the
    /// auth-cipher envelope and carries human context. The private key never
    /// leaves the agent.
    ///
    /// Uses the same `Operation::Sign` grant store as standard `SIGN_REQUEST`.
    /// Local callers get a kernel-verified workspace scope (one approval
    /// covers a same-project multi-host fan-out); relay callers stay confined
    /// to their connection. Duration `0` (the default) keeps per-request
    /// prompts. See docs/authorization-scopes-v2.md §3.4.
    pub(super) async fn handle_sign_vt(
        &self,
        decrypted: &[u8],
    ) -> Result<HandlerSuccess, WireFailure> {
        use ssh_agent_lib::ssh_encoding::Decode;

        let req: SignReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;
        if req.command.len() > PROMPT_DISPLAY_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_DISPLAY_FIELD_TOO_LARGE)));
        }

        // Decode the requested pubkey → KeyData → fingerprint (same fn as
        // storage, so the lookup key matches what the client advertised).
        // `&[u8]: Reader`, so `decode(&mut &[u8])` is the correct call pattern.
        let key_data = KeyData::decode(&mut req.pubkey.as_slice())
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_SIGN_BAD_PUBKEY)))?;
        let fp_str = fingerprint_str(&key_data);

        // Look up the key. "Not in this agent" is FALLBACK-ELIGIBLE (Generic),
        // NOT BadRequest — an agent-less/other-key host must be able to fall
        // back to decrypt-then-sign. Clone the PrivateKey out so the keys
        // read-lock is not held across the Touch ID prompt.
        self.ensure_keys_loaded()
            .await
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_SIGN_KEYS_LOAD)))?;
        let privkey = {
            let keys = self.keys.read().await;
            match keys.get(&fp_str) {
                Some(k) => k.clone(),
                None => return Err((ErrKind::Generic, Some(DETAIL_SIGN_KEY_NOT_IN_AGENT))),
            }
        };

        // Rich prompt from vt context (mirrors handle_decrypt formatting).
        let who = who_at_host(&req.meta.user, &req.host);
        let mut auth_message = header_with_who("ssh-sign", "for", &who);
        self.append_relay_origin(&mut auth_message);
        self.append_caller_line(&mut auth_message);
        // sign@vt can name ANY agent key, so the prompt must say which one
        // (comment, else SHA256 fingerprint — same label rule as
        // `Session::sign`). This line is agent-derived truth (the requested
        // key resolved against our own Keychain) and precedes the
        // client-reported command body below; sanitize the comment like every
        // other prompt field so a control-char/newline comment cannot inject
        // fake lines.
        auth_message.push_str("\nkey: ");
        if privkey.comment().is_empty() {
            auth_message.push_str(&fp_str);
        } else {
            auth_message.push_str(&sanitize_prompt(privkey.comment(), 80));
        }
        // Reuse line before the client-reported body/meta — same padding
        // rationale as the relay origin marker.
        let (scope, reuse_label) = self.sign_vt_scope(&fp_str, &req.meta.pwd);
        let scope = scope.with_display(reuse_label.clone().unwrap_or_default());
        append_reuse_line(&mut auth_message, &reuse_label, self.cache_ttls.sign_secs);
        let audit_ctx = {
            let mut ctx =
                self.audit_ctx_scoped(scope.family(), &reuse_label, self.cache_ttls.sign_secs);
            ctx.key_fp = fp_str.clone();
            ctx
        };
        let body = sanitize_prompt_multiline(
            &req.command,
            PROMPT_COMMAND_MAX_LINE_LEN,
            PROMPT_COMMAND_MAX_LINES,
        );
        if !body.is_empty() {
            auth_message.push('\n');
            auth_message.push_str(&body);
        }
        append_meta_lines(&mut auth_message, &req.meta);

        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::new(
                vec![scope],
                ReusePolicy::from_ttl_secs(self.cache_ttls.sign_secs),
                auth_message,
            ))
            .await
        {
            Ok(permit) => {
                self.emit_audit(
                    "ssh-sign",
                    permit.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &req.command,
                    "",
                    0,
                    permit.latency_ms(),
                    audit_ctx,
                );
                permit
            }
            Err(failure) => {
                self.emit_audit(
                    "ssh-sign",
                    failure.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &req.command,
                    "",
                    0,
                    failure.latency_ms(),
                    audit_ctx,
                );
                return Err(authorization_failure_wire(&failure));
            }
        };

        let sig = sign_data_with_privkey(&privkey, &req.data, req.flags)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_SIGN_FAILED)))?;
        let res = SignRes {
            algorithm: sig.algorithm().to_string(),
            signature: sig.as_bytes().to_vec(),
        };
        let bytes = serde_json::to_vec(&res)
            .map(Zeroizing::new)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?;
        let note = cache_hit_note_for(&permit, "sign", &reuse_label);
        Ok(HandlerSuccess::authorized(bytes, permit).with_cache_hit_note(note))
    }
}

#[cfg(test)]
mod tests {
    use super::super::RunAllowlist;
    use super::*;

    // ── Touch-ID prompt helpers ────────────────────────────────────────────

    #[test]
    fn sanitize_prompt_strips_control_chars() {
        // Newline, tab, carriage return, NUL, DEL — all must go. The decrypt
        // prompt is shown via LAContext.localizedReason; an attacker who
        // controls a forwarded agent socket could try to break out of the
        // prompt layout or smuggle in extra newlines that look like
        // legitimate `pwd:` / `via:` fields.
        let evil = "good\n\r\t\x00\x7fend";
        assert_eq!(sanitize_prompt(evil, 100), "goodend");
    }

    #[test]
    fn sanitize_prompt_truncates_with_ellipsis() {
        let long: String = "x".repeat(50);
        let out = sanitize_prompt(&long, 10);
        assert_eq!(out.chars().count(), 11, "10 chars + …");
        assert!(out.ends_with('…'));
        assert!(out.starts_with("xxxxxxxxxx"));
    }

    #[test]
    fn sanitize_prompt_passes_short_input_unchanged() {
        assert_eq!(sanitize_prompt("hi", 100), "hi");
        assert_eq!(sanitize_prompt("", 10), "");
    }

    #[test]
    fn who_at_host_renders_user_and_host() {
        assert_eq!(who_at_host("qiqi", "alpha"), "qiqi@alpha");
    }

    #[test]
    fn who_at_host_degrades_gracefully_for_old_clients() {
        // Old client doesn't send meta.user — fall back to bare host so the
        // prompt still reads naturally.
        assert_eq!(who_at_host("", "alpha"), "alpha");
        // Symmetrically, a missing host should not produce a leading "@".
        assert_eq!(who_at_host("qiqi", ""), "qiqi");
        assert_eq!(who_at_host("", ""), "");
    }

    #[test]
    fn who_at_host_strips_control_chars_in_either_field() {
        // Defense-in-depth: a hostile forwarded peer could lie about user
        // or host. The agent never trusts the wire for layout.
        assert_eq!(who_at_host("qi\nqi", "al\tpha"), "qiqi@alpha");
    }

    #[test]
    fn append_meta_lines_emits_only_populated_fields() {
        let meta = crate::core::ClientMeta {
            user: "qiqi".into(),
            pwd: "/tmp".into(),
            tty: "/dev/pts/3".into(), // intentionally skipped on prompt
            ppid_cmd: "".into(),      // empty — must be skipped
            ssh_client: "".into(),    // empty — must be skipped
        };
        let mut msg = String::from("auth: sudo on qiqi@alpha");
        append_meta_lines(&mut msg, &meta);
        assert_eq!(msg, "auth: sudo on qiqi@alpha\npwd: /tmp");
    }

    #[test]
    fn append_meta_lines_emits_all_when_present() {
        let meta = crate::core::ClientMeta {
            user: "qiqi".into(),
            pwd: "/tmp".into(),
            tty: "/dev/pts/3".into(),
            ppid_cmd: "zsh -i".into(),
            ssh_client: "10.0.0.5 5234 22".into(),
        };
        let mut msg = String::from("decrypt 1: [read] on qiqi@alpha");
        append_meta_lines(&mut msg, &meta);
        let lines: Vec<&str> = msg.split('\n').collect();
        assert_eq!(lines[0], "decrypt 1: [read] on qiqi@alpha");
        assert_eq!(lines[1], "pwd: /tmp");
        assert_eq!(lines[2], "via: zsh -i");
        assert_eq!(lines[3], "ssh: 10.0.0.5 5234 22");
        assert_eq!(lines.len(), 4, "tty must not be rendered on prompt");
    }

    #[test]
    fn append_meta_lines_is_noop_for_default_meta() {
        // Old clients deserialize to ClientMeta::default() — empty everywhere.
        // The prompt must remain a single line in that case.
        let meta = crate::core::ClientMeta::default();
        let mut msg = String::from("auth: sudo on alpha");
        append_meta_lines(&mut msg, &meta);
        assert_eq!(msg, "auth: sudo on alpha");
        assert!(!msg.contains('\n'));
    }

    // --- run@vt allowlist tests ----------------------------------------------

    #[test]
    fn run_allowlist_empty_means_disabled() {
        let a = RunAllowlist::parse("").unwrap();
        assert!(a.is_empty());
        let a = RunAllowlist::parse("   ,  ").unwrap();
        assert!(a.is_empty());
    }

    #[test]
    fn run_allowlist_rejects_relative_path_entry() {
        // Slash-bearing entries must be absolute; otherwise the canonicalize
        // would resolve against the agent's cwd at parse time — surprising.
        let err = RunAllowlist::parse("bin/zed").unwrap_err();
        assert!(err.contains("absolute"), "got: {}", err);
    }

    #[test]
    fn run_allowlist_rejects_nul_in_entry() {
        let err = RunAllowlist::parse("zed,fo\0o").unwrap_err();
        assert!(err.contains("NUL"), "got: {}", err);
    }

    #[test]
    fn run_allowlist_rejects_relative_argv0() {
        let a = RunAllowlist::parse("zed").unwrap();
        assert_eq!(a.resolve("./zed"), Err("argv[0] with / must be absolute"));
    }

    #[test]
    fn run_allowlist_rejects_dotdot_in_argv0() {
        let a = RunAllowlist::parse("/usr/bin/zed").unwrap_or_else(|_| {
            // /usr/bin/zed may not exist on this machine; fall back to a
            // bare-name allowlist for the .. rejection check.
            RunAllowlist::parse("zed").unwrap()
        });
        assert_eq!(
            a.resolve("/Applications/../etc/passwd"),
            Err("argv[0] has .. component")
        );
        assert_eq!(a.resolve("/foo/../bar"), Err("argv[0] has .. component"));
    }

    #[test]
    fn run_allowlist_rejects_empty_and_nul_argv0() {
        let a = RunAllowlist::parse("zed").unwrap();
        assert_eq!(a.resolve(""), Err("argv[0] empty"));
        assert_eq!(a.resolve("ze\0d"), Err("argv[0] has NUL byte"));
    }

    #[test]
    fn run_allowlist_bare_name_rejects_path_argv0() {
        // bare name "zed" must NOT let an attacker pass /tmp/zed.
        let a = RunAllowlist::parse("zed").unwrap();
        // /tmp exists; create a transient executable there to be sure
        // canonicalize doesn't trip on a missing file.
        use std::io::Write;
        let mut path = std::env::temp_dir();
        path.push(format!("vt-run-allow-test-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "#!/bin/sh\necho hi").unwrap();
        }
        // chmod +x so it'd be considered executable by resolve_in_path.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let res = a.resolve(&path.display().to_string());
        let _ = std::fs::remove_file(&path);
        assert_eq!(res, Err("argv[0] path not in allowlist"));
    }

    #[test]
    fn run_allowlist_resolves_bare_name_via_path() {
        // /bin/sh is essentially always on PATH on macOS dev hosts.
        let a = RunAllowlist::parse("sh").unwrap();
        let resolved = a.resolve("sh").expect("sh should resolve via PATH");
        assert!(
            resolved.is_absolute(),
            "expected absolute path, got {:?}",
            resolved
        );
        // basename should be `sh`; on some systems /bin/sh is a symlink so we
        // just sanity-check that the resolved file exists.
        assert!(resolved.exists());
    }

    #[test]
    fn run_allowlist_abs_path_exact_match() {
        // Use /bin/sh (or its canonicalized form) as a real exec on disk.
        let sh = std::fs::canonicalize("/bin/sh").expect("/bin/sh must exist on macOS");
        let spec = sh.display().to_string();
        let a = RunAllowlist::parse(&spec).unwrap();
        assert_eq!(a.resolve(&spec).unwrap(), sh);
        // Different absolute path → not allowlisted (use a canonicalize-able path).
        let other = std::fs::canonicalize("/bin/ls").expect("/bin/ls must exist on macOS");
        assert_eq!(
            a.resolve(&other.display().to_string()),
            Err("argv[0] path not in allowlist")
        );
    }

    #[test]
    fn plural_secrets_matches_count() {
        assert_eq!(plural_secrets(0), "secrets");
        assert_eq!(plural_secrets(1), "secret");
        assert_eq!(plural_secrets(2), "secrets");
    }

    /// End-to-end shape of the new decrypt prompt: header on line 1,
    /// the CLI's multi-line `command` body, then `append_meta_lines` rows.
    #[test]
    fn decrypt_prompt_renders_multiline_command_and_meta() {
        let who = who_at_host("qiqi", "xy4");
        let n = 5usize;
        let mut msg = format!("decrypt {} {} on {}", n, plural_secrets(n), who);
        let body = sanitize_prompt_multiline(
            "op: inject\nfile: /Users/qiqi/.config/aux/config.jsonc\ncmd: /bin/cat /Users/qiqi/.config/aux/config.jsonc\nreason: aux config.jsonc",
            PROMPT_COMMAND_MAX_LINE_LEN,
            PROMPT_COMMAND_MAX_LINES,
        );
        assert!(!body.is_empty());
        msg.push('\n');
        msg.push_str(&body);
        append_meta_lines(
            &mut msg,
            &crate::core::ClientMeta {
                user: "qiqi".into(),
                pwd: "/".into(),
                tty: String::new(),
                ppid_cmd: "/Applications/aux.app/Contents/MacOS/aux".into(),
                ssh_client: String::new(),
            },
        );
        let lines: Vec<&str> = msg.split('\n').collect();
        assert_eq!(lines[0], "decrypt 5 secrets on qiqi@xy4");
        assert_eq!(lines[1], "op: inject");
        assert_eq!(lines[2], "file: /Users/qiqi/.config/aux/config.jsonc");
        assert_eq!(
            lines[3],
            "cmd: /bin/cat /Users/qiqi/.config/aux/config.jsonc"
        );
        assert_eq!(lines[4], "reason: aux config.jsonc");
        assert_eq!(lines[5], "pwd: /");
        assert_eq!(lines[6], "via: /Applications/aux.app/Contents/MacOS/aux");
        assert_eq!(lines.len(), 7);
    }

    #[test]
    fn decrypt_prompt_caps_hostile_command_line_count() {
        // A malicious peer floods `command` with extra lines trying to push
        // the dialog off-screen — the multiline sanitizer must drop the tail.
        let huge = (0..50)
            .map(|i| format!("line {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        let body =
            sanitize_prompt_multiline(&huge, PROMPT_COMMAND_MAX_LINE_LEN, PROMPT_COMMAND_MAX_LINES);
        assert_eq!(body.split('\n').count(), PROMPT_COMMAND_MAX_LINES);
    }

    #[test]
    fn append_meta_lines_caps_long_fields() {
        // A hostile peer that floods e.g. pwd with megabytes of junk must
        // not be able to push the Touch ID dialog off-screen.
        let huge = "a".repeat(1000);
        let meta = crate::core::ClientMeta {
            pwd: huge.clone(),
            ppid_cmd: huge.clone(),
            ssh_client: huge,
            ..Default::default()
        };
        let mut msg = String::new();
        append_meta_lines(&mut msg, &meta);
        // pwd:100, via:100, ssh:80 — plus the labels and newlines.
        // Conservative upper bound: each line under 120 chars (label + 100 + …).
        for line in msg.split('\n').filter(|l| !l.is_empty()) {
            assert!(
                line.chars().count() <= 120,
                "prompt line too long ({} chars): {}",
                line.chars().count(),
                line,
            );
        }
    }
}
