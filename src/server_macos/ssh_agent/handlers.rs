//! Extension operations return serialized bodies and uncommitted permits.
//! The parent dispatcher alone encrypts responses, commits, and notifies.

use std::sync::atomic::Ordering;

use anyhow::Result;
use rand::RngCore;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Extension, Unparsed};
use ssh_key::public::KeyData;
use zeroize::Zeroizing;

use super::super::authorization::SeSessions;
use super::super::security::{require_v3, validate_master_material};
use super::super::store::KeychainStore;
use super::scopes::append_reuse_line;
use super::{
    agent_err, authorization_failure_wire, cache_hit_note_for, fingerprint_str, keys,
    sanitize_prompt, sanitize_prompt_exact, sanitize_prompt_multiline, sign_data_with_privkey,
    spawn_detached, HandlerSuccess, VtSshSession, WireFailure, DETAIL_BAD_REQUEST_JSON,
    DETAIL_BATCH_EMPTY, DETAIL_BATCH_TOO_LARGE, DETAIL_DISPLAY_FIELD_TOO_LARGE,
    DETAIL_INTERNAL_SERIALIZE, DETAIL_NOT_INITIALIZED, DETAIL_RUN_ARGV_EMPTY,
    DETAIL_RUN_ARGV_TOO_LARGE, DETAIL_RUN_ARGV_UNDISPLAYABLE, DETAIL_RUN_DISABLED,
    DETAIL_RUN_NOT_ALLOWLISTED, DETAIL_RUN_SPAWN_FAILED, DETAIL_SE_SESSION, DETAIL_SE_UNWRAP,
    DETAIL_SIGN_BAD_PUBKEY, DETAIL_SIGN_FAILED, DETAIL_SIGN_KEYS_LOAD,
    DETAIL_SIGN_KEY_NOT_IN_AGENT, DETAIL_UNKNOWN_SECRET_TYPE, MAX_CRYPTO_BATCH,
    PROMPT_COMMAND_MAX_LINES, PROMPT_COMMAND_MAX_LINE_LEN, PROMPT_DISPLAY_MAX_BYTES,
    RUN_PROMPT_ARGV_MAX, RUN_REQ_ARGV_MAX_BYTES,
};
use crate::core::authorization::{
    AuthorizationPermit, AuthorizationRequest, GrantScope, Operation, ReusePolicy,
};
use crate::core::crypto::derive_dek;
use crate::core::wire::ErrKind;
use crate::core::{
    AuthReq, AuthRes, DecryptInput, DecryptReq, DecryptResItem, DiagCacheReport, DiagPeerReport,
    DiagReq, DiagRes, EncryptReq, EncryptResItem, RunReq, RunRes, SignReq, SignRes, UiStatusReq,
    UiStatusRes, SALT_LEN,
};

/// Unwrap for a permit holder through pending or committed SE custody.
/// A failure drops the permit upstream without creating a grant.
pub(super) fn master_for(
    sessions: &SeSessions,
    store: &KeychainStore,
    reuse: ReusePolicy,
) -> Result<Zeroizing<[u8; 32]>, WireFailure> {
    let not_initialized = |_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED));
    require_v3(store).map_err(not_initialized)?;
    let (_, wrapped) = store.se_material_bytes().map_err(not_initialized)?;
    sessions
        .with_session(reuse, |session| session.unwrap_master(&wrapped))
        .ok_or((ErrKind::NotInitialized, Some(DETAIL_SE_SESSION)))?
        .map_err(|error| {
            tracing::warn!("{error}");
            (ErrKind::NotInitialized, Some(DETAIL_SE_UNWRAP))
        })
}

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
/// degrades gracefully for old clients that don't send `meta.user`. A host
/// that is already a `user@host` SSH destination (`vt ssh connect`) is shown
/// as-is rather than as `qiqi@git@github.com`.
fn who_at_host(user: &str, host: &str) -> String {
    let u = sanitize_prompt(user, 40);
    let h = sanitize_prompt(host, 60);
    match (u.is_empty(), h.is_empty()) {
        (true, true) => String::new(),
        (true, false) => h,
        (false, true) => u,
        (false, false) if h.contains('@') => h,
        (false, false) => format!("{}@{}", u, h),
    }
}

/// `who_at_host` plus, when the client sat in an SSH session, its peer
/// address as `(ssh 10.0.0.5)` — `SSH_CLIENT` also carries two port numbers,
/// which say nothing to the approver.
fn header_who(meta: &crate::core::ClientMeta, host: &str) -> String {
    let mut who = who_at_host(&meta.user, host);
    if let Some(addr) = meta.ssh_client.split_whitespace().next() {
        if !who.is_empty() {
            who.push(' ');
        }
        who.push_str("(ssh ");
        who.push_str(&sanitize_prompt(addr, 60));
        who.push(')');
    }
    who
}

/// Drop a trailing ` -> {dest}` from the client command label when the header
/// already names `dest` (`ssh-sign: fetch -> git@github.com` under a
/// `… on git@github.com` header). Display only; the scope is unchanged.
fn strip_repeated_destination(body: &str, dest: &str) -> String {
    if dest.is_empty() {
        return body.to_string();
    }
    body.strip_suffix(dest)
        .and_then(|rest| rest.strip_suffix(" -> "))
        .unwrap_or(body)
        .to_string()
}

/// Append the client-claimed context lines (pwd, parent process) to the
/// Touch ID prompt body. Each is on its own line — `LAContext`'s
/// `localizedReason` renders multi-line strings. Empty fields are skipped so
/// the prompt stays compact for old clients; `via:` is cut short because the
/// header already names the operation.
fn append_meta_lines(message: &mut String, meta: &crate::core::ClientMeta) {
    if !meta.pwd.is_empty() {
        message.push_str("\npwd: ");
        message.push_str(&sanitize_prompt(&meta.pwd, 100));
    }
    if !meta.ppid_cmd.is_empty() {
        message.push_str("\nvia: ");
        message.push_str(&sanitize_prompt(&meta.ppid_cmd, 40));
    }
}

impl VtSshSession {
    /// The private key for `fp`: from RAM, else every stored private key is
    /// decrypted through the master this permit unlocked and installed
    /// (docs/app-bundle.md#key-wiping-and-idle-timeout). Interactivity and agent
    /// lock are re-checked under the key-map write guard so keys are never
    /// installed after a clear. The master never crosses an await.
    pub(super) async fn private_key(
        &self,
        store: &KeychainStore,
        fp: &str,
        reuse: ReusePolicy,
    ) -> Result<ssh_key::private::PrivateKey, WireFailure> {
        let mut keys = self.keys.write().await;
        let unsafe_state = || (ErrKind::Generic, Some(DETAIL_SIGN_KEYS_LOAD));
        if self.locked.load(Ordering::Acquire)
            || !crate::server_macos::security::session_interactive_now()
        {
            return Err(unsafe_state());
        }
        // Even a resident key requires this permit's custody: a password or
        // failed bind must not borrow a key loaded by an earlier approval.
        let loaded = {
            let master = master_for(&self.se_sessions, store, reuse)?;
            if let Some(key) = keys.get(fp) {
                return Ok(key.clone());
            }
            keys::load_private_keys(store, &master).map_err(|error| {
                tracing::warn!("SSH key reload failed: {error}");
                unsafe_state()
            })?
        };
        if self.locked.load(Ordering::Acquire)
            || !crate::server_macos::security::session_interactive_now()
        {
            return Err(unsafe_state());
        }
        tracing::info!("Reloaded {} SSH keys after authorization", loaded.len());
        *keys = loaded;
        keys.get(fp)
            .cloned()
            .ok_or((ErrKind::Generic, Some(DETAIL_SIGN_KEY_NOT_IN_AGENT)))
    }

    /// Fresh approval for an `ssh-add` key-store mutation, returning the
    /// permit and a resolver the blocking store write calls for the master
    /// (so raw key material is unwrapped only inside that task).
    pub(super) async fn keystore_master(
        &self,
        prompt: &str,
    ) -> Result<
        (
            AuthorizationPermit,
            impl FnOnce(&KeychainStore) -> Result<Zeroizing<[u8; 32]>> + Send + 'static,
        ),
        AgentError,
    > {
        let mut auth_message = prompt.to_string();
        self.append_caller_line(&mut auth_message);
        let permit = self
            .authorize_audited(
                AuthorizationRequest::fresh(
                    GrantScope::fresh(Operation::KeyStore),
                    auth_message.clone(),
                ),
                "keystore",
                "",
                &crate::core::ClientMeta::default(),
                &auth_message,
                "",
                0,
                self.audit_ctx(),
            )
            .await
            .map_err(|_| AgentError::Failure)?;
        let sessions = std::sync::Arc::clone(&self.se_sessions);
        Ok((permit, move |store: &KeychainStore| {
            master_for(&sessions, store, ReusePolicy::Fresh)
                .map_err(|(kind, detail)| anyhow::anyhow!("{kind:?}: {}", detail.unwrap_or("")))
        }))
    }

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
    ) -> Result<HandlerSuccess, WireFailure> {
        // v2 envelope: agent allocates a fresh per-record (salt, DEK) pair
        // for each requested SecretType. The agent NEVER receives plaintext
        // on this path. The salt is generated server-side (never accepted
        // from the client) — this is the security invariant that prevents
        // any peer on the socket from extracting a salt from a stored
        // vt://0{salt||ct} URL and requesting its DEK to bypass Touch ID.
        let req: EncryptReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;
        if req.types.len() > MAX_CRYPTO_BATCH {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_TOO_LARGE)));
        }
        if req.types.is_empty() {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_EMPTY)));
        }
        validate_master_material(store)
            .map_err(|_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED)))?;

        // Minting a DEK releases key material like decrypt does, so it is
        // authorized under the decrypt TTL with the same scope families; one
        // scope per requested type. EncryptReq carries no client meta, so the
        // prompt is agent truth only.
        let n = req.types.len();
        let mut auth_message = format!("encrypt {} {}", n, plural_secrets(n));
        self.append_relay_origin(&mut auth_message);
        self.append_caller_line(&mut auth_message);
        let (scopes, reuse_label) = self.encrypt_scopes(&req.types);
        let display = reuse_label.clone().unwrap_or_default();
        let scopes: Vec<GrantScope> = scopes
            .into_iter()
            .map(|scope| scope.with_display(display.clone()))
            .collect();
        append_reuse_line(
            &mut auth_message,
            &reuse_label,
            self.cache_ttls.decrypt_secs,
        );
        let reuse = ReusePolicy::from_ttl_secs(self.cache_ttls.decrypt_secs);
        let audit_ctx = self.audit_ctx_scoped(
            scopes.first().and_then(GrantScope::family),
            &reuse_label,
            self.cache_ttls.decrypt_secs,
        );
        let permit = self
            .authorize_audited(
                AuthorizationRequest::new(scopes, reuse, auth_message),
                "encrypt",
                "",
                &crate::core::ClientMeta::default(),
                "",
                "",
                n,
                audit_ctx,
            )
            .await
            .map_err(|failure| authorization_failure_wire(&failure))?;
        let mac_key = master_for(&self.se_sessions, store, permit.session_policy())?;
        let mut result = Zeroizing::new(Vec::<EncryptResItem>::with_capacity(req.types.len()));
        for _t in &req.types {
            let mut salt = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            result.push(EncryptResItem {
                salt,
                dek: derive_dek(&mac_key, &salt),
                err_message: String::new(),
            });
        }
        drop(mac_key);
        let bytes = serde_json::to_vec(&*result)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?;
        let note = cache_hit_note_for(&permit, "encrypt", &reuse_label);
        Ok(HandlerSuccess::authorized(Zeroizing::new(bytes), permit).with_cache_hit_note(note))
    }

    pub(super) async fn handle_decrypt(
        &self,
        decrypted: &[u8],
        store: &KeychainStore,
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
        // for any peer on the socket.
        if req.items.is_empty() {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_EMPTY)));
        }

        // Reject `SecretType::UNKNOWN` v2 items: serde would otherwise
        // accept them from a malformed `DecryptInput::V2`, the downstream
        // decrypt would fail on AAD mismatch, but the cache could be
        // polluted with `t.as_byte() == b'_'` entries in the meantime.
        let mut v2_inputs: Vec<(crate::core::SecretType, [u8; SALT_LEN])> =
            Vec::with_capacity(req.items.len());
        for DecryptInput::V2 { t, salt } in &req.items {
            if *t == crate::core::SecretType::UNKNOWN {
                tracing::warn!("decrypt@vt rejecting v2 item with UNKNOWN type");
                return Err((ErrKind::BadRequest, Some(DETAIL_UNKNOWN_SECRET_TYPE)));
            }
            v2_inputs.push((*t, *salt));
        }

        // Preflight the stored shape without unwrapping before authorization.
        validate_master_material(store)
            .map_err(|_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED)))?;

        let who = header_who(&req.meta, &req.host);
        let n = req.items.len();
        let mut local_auth_message =
            header_with_who(&format!("decrypt {} {}", n, plural_secrets(n)), "on", &who);
        self.append_relay_origin(&mut local_auth_message);
        self.append_caller_line(&mut local_auth_message);
        // One atomic scope per record; reuse requires an all-of hit.
        // The reuse line is agent-derived truth and is appended BEFORE the
        // client-reported body/meta below, for the same reason as the relay
        // origin marker: a hostile caller must not be able to pad the one
        // line that says the tap creates a standing grant off-screen.
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
        let reuse = ReusePolicy::from_ttl_secs(self.cache_ttls.decrypt_secs);
        let audit_ctx = self.audit_ctx_scoped(
            scopes.first().and_then(GrantScope::family),
            &reuse_label,
            self.cache_ttls.decrypt_secs,
        );
        let body = sanitize_prompt_multiline(
            &strip_repeated_destination(&req.command, &who_at_host(&req.meta.user, &req.host)),
            PROMPT_COMMAND_MAX_LINE_LEN,
            PROMPT_COMMAND_MAX_LINES,
        );
        if !body.is_empty() {
            local_auth_message.push('\n');
            local_auth_message.push_str(&body);
        }
        append_meta_lines(&mut local_auth_message, &req.meta);
        let permit = self
            .authorize_audited(
                AuthorizationRequest::new(scopes, reuse, local_auth_message),
                "decrypt",
                &req.host,
                &req.meta,
                &req.command,
                "",
                req.items.len(),
                audit_ctx,
            )
            .await
            .map_err(|failure| authorization_failure_wire(&failure))?;
        let mac_key = master_for(&self.se_sessions, store, permit.session_policy())?;
        let mut result = Zeroizing::new(Vec::<DecryptResItem>::with_capacity(req.items.len()));
        for DecryptInput::V2 { salt, .. } in req.items {
            result.push(DecryptResItem::V2 {
                dek: derive_dek(&mac_key, &salt),
                err_message: String::new(),
            });
        }
        drop(mac_key);
        let bytes = Zeroizing::new(
            serde_json::to_vec(&*result)
                .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?,
        );
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

        let who = header_who(&req.meta, &req.host);
        let mut auth_message = header_with_who("auth", "on", &who);
        self.append_relay_origin(&mut auth_message);
        self.append_caller_line(&mut auth_message);
        let reason = sanitize_prompt(&req.reason, 100);
        if !reason.is_empty() {
            auth_message.push_str("\nreason: ");
            auth_message.push_str(&reason);
        }
        append_meta_lines(&mut auth_message, &req.meta);

        let permit = self
            .authorize_audited(
                AuthorizationRequest::fresh(GrantScope::fresh(Operation::Auth), auth_message),
                "auth",
                &req.host,
                &req.meta,
                "",
                &req.reason,
                0,
                self.audit_ctx(),
            )
            .await
            .map_err(|failure| authorization_failure_wire(&failure))?;

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
    /// THIS connection's resolved context; accepted disclosure tradeoffs are in
    /// `docs/unified-authorization-engine.md#visibility`.
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

    /// `ui-status@vt` (docs/app-bundle.md#status-and-revoke-boundary): token-gated status/revoke
    /// channel for the VT.app shell. Runs BEFORE the lock check and the
    /// Keychain store load, never touches the idle clock, is
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
        // The user approves exactly the argv line they see: refuse rather than
        // truncate, so no tail can hide past the prompt's display cap.
        let argv_for_prompt = sanitize_prompt_exact(&req.argv.join(" "), RUN_PROMPT_ARGV_MAX)
            .ok_or((ErrKind::BadRequest, Some(DETAIL_RUN_ARGV_UNDISPLAYABLE)))?;

        let resolved = self.run_allow.resolve(&req.argv[0]).map_err(|why| {
            tracing::warn!("run@vt rejected: {} (argv0={:?})", why, &req.argv[0]);
            (ErrKind::BadRequest, Some(DETAIL_RUN_NOT_ALLOWLISTED))
        })?;

        // Build the Touch ID message. The resolved canonical path is shown on
        // its own line so the user is approving the *resolved* program, not
        // the (potentially confusing) raw argv[0] from a remote peer.
        let who = header_who(&req.meta, &req.host);
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
        // Q5: `approved` lands at the human tap, BEFORE the spawn attempt, so a
        // denied launch (below) is distinguishable from a failed one (two rows).
        let permit = self
            .authorize_audited(
                AuthorizationRequest::fresh(GrantScope::fresh(Operation::Run), auth_message),
                "run",
                &req.host,
                &req.meta,
                &run_command,
                run_reason,
                0,
                self.audit_ctx(),
            )
            .await
            .map_err(|failure| authorization_failure_wire(&failure))?;

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

    /// `sign@vt`: signing with a Keychain-held key, displaying vt execution
    /// context (host/command/meta) in the Touch ID prompt. Unlike the standard
    /// `SIGN_REQUEST` path, the request carries human context (advisory,
    /// sanitized). The private key never leaves the agent.
    ///
    /// Uses the same `Operation::Sign` grant store as standard `SIGN_REQUEST`.
    /// Local callers get a kernel-verified workspace scope (one approval
    /// covers a same-project multi-host fan-out); relay callers stay confined
    /// to their connection. Duration `0` (the default) keeps per-request
    /// prompts. See docs/unified-authorization-engine.md#scopes.
    pub(super) async fn handle_sign_vt(
        &self,
        decrypted: &[u8],
        store: &KeychainStore,
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

        // Look up the identity in the plaintext public list. "Not in this
        // agent" is FALLBACK-ELIGIBLE (Generic), NOT BadRequest — an
        // agent-less/other-key host must be able to fall back to
        // decrypt-then-sign. The private key is loaded after authorization.
        let comment = keys::public_entries(store)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_SIGN_KEYS_LOAD)))?
            .into_iter()
            .find(|entry| entry.fingerprint == fp_str)
            .ok_or((ErrKind::Generic, Some(DETAIL_SIGN_KEY_NOT_IN_AGENT)))?
            .comment;

        // Rich prompt from vt context (mirrors handle_decrypt formatting).
        let who = header_who(&req.meta, &req.host);
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
        if comment.is_empty() {
            auth_message.push_str(&fp_str);
        } else {
            auth_message.push_str(&sanitize_prompt(&comment, 80));
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
        // The header already reads `ssh-sign`; keep only the op (`push`).
        let command =
            strip_repeated_destination(&req.command, &who_at_host(&req.meta.user, &req.host));
        let body = sanitize_prompt_multiline(
            command.strip_prefix("ssh-sign: ").unwrap_or(&command),
            PROMPT_COMMAND_MAX_LINE_LEN,
            PROMPT_COMMAND_MAX_LINES,
        );
        if !body.is_empty() {
            auth_message.push('\n');
            auth_message.push_str(&body);
        }
        append_meta_lines(&mut auth_message, &req.meta);

        let reuse = ReusePolicy::from_ttl_secs(self.cache_ttls.sign_secs);
        let permit = self
            .authorize_audited(
                AuthorizationRequest::new(vec![scope], reuse, auth_message),
                "ssh-sign",
                &req.host,
                &req.meta,
                &req.command,
                "",
                0,
                audit_ctx,
            )
            .await
            .map_err(|failure| authorization_failure_wire(&failure))?;

        let privkey = self
            .private_key(store, &fp_str, permit.session_policy())
            .await?;
        let sig = sign_data_with_privkey(&privkey, &req.data)
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
    use super::super::tests::{test_session, TestAuthenticator, TestValidator};
    use super::super::RunAllowlist;
    use super::*;
    use crate::core::authorization::{AuthorizationAuthenticator, AuthorizationEngine};
    use crate::core::crypto::AesGcmCrypto;
    use crate::core::session::AuthOutcome;
    use crate::server_macos::se::test_support::software_store;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    struct RejectingAuthenticator;

    #[async_trait::async_trait]
    impl AuthorizationAuthenticator for RejectingAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _operation: Operation,
            _reuse: ReusePolicy,
            _revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            AuthOutcome::Rejected
        }
    }

    fn engine(
        authenticator: impl AuthorizationAuthenticator + 'static,
    ) -> Arc<AuthorizationEngine> {
        AuthorizationEngine::new(Arc::new(authenticator), Arc::new(TestValidator))
    }

    fn encrypt_payload(types: Vec<crate::core::SecretType>) -> Vec<u8> {
        serde_json::to_vec(&EncryptReq { types }).unwrap()
    }

    /// encrypt@vt passes the engine: a rejected approval mints nothing, an
    /// approved one returns DEKs derived from the store's master and hands
    /// the permit up for commit. An empty batch is refused before any prompt.
    #[tokio::test]
    async fn encrypt_requires_authorization() {
        use crate::core::SecretType;
        let master = AesGcmCrypto::generate_key();
        let (store, custody) = software_store(&master);
        let payload = encrypt_payload(vec![SecretType::RAW, SecretType::TOTP]);

        let mut session = test_session(0, 0);
        session.authorization = engine(RejectingAuthenticator);
        let err = session
            .handle_encrypt(&payload, &store)
            .await
            .err()
            .expect("rejected");
        assert_eq!(err.0, ErrKind::AuthRejected);
        let err = session
            .handle_encrypt(&encrypt_payload(vec![]), &store)
            .await
            .err()
            .expect("empty batch refused");
        assert_eq!(err, (ErrKind::BadRequest, Some(DETAIL_BATCH_EMPTY)));

        session.authorization = engine(TestAuthenticator);
        session.se_sessions.put(ReusePolicy::Fresh, custody);
        let ok = session.handle_encrypt(&payload, &store).await.unwrap();
        assert!(
            ok.authorization.is_some(),
            "permit travels to the dispatcher"
        );
        let items: Vec<EncryptResItem> = serde_json::from_slice(&ok.bytes).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].dek, derive_dek(&master, &items[0].salt));
        assert_ne!(items[0].salt, items[1].salt);
    }

    /// Wrap v3 fails closed without a Secure Enclave session, and with a
    /// session whose key cannot unwrap the stored ciphertext.
    #[test]
    fn master_for_v3_fails_closed_without_usable_session() {
        use crate::server_macos::se::test_support::software_session;
        let sessions = SeSessions::default();
        let store = KeychainStore::new_v3(&[1u8; 8], &[2u8; 113]);
        let fresh = ReusePolicy::Fresh;
        assert_eq!(
            master_for(&sessions, &store, fresh).unwrap_err(),
            (ErrKind::NotInitialized, Some(DETAIL_SE_SESSION))
        );
        sessions.put(fresh, software_session());
        assert_eq!(
            master_for(&sessions, &store, fresh).unwrap_err(),
            (ErrKind::NotInitialized, Some(DETAIL_SE_UNWRAP))
        );
        // The approval guard owns cleanup; repeated access cannot select a
        // different session while that permit is alive.
        assert_eq!(
            master_for(&sessions, &store, fresh).unwrap_err(),
            (ErrKind::NotInitialized, Some(DETAIL_SE_UNWRAP))
        );
    }

    #[tokio::test]
    async fn cached_private_key_requires_current_custody_and_lock_check() {
        let session = test_session(0, 0);
        let key = ssh_key::private::PrivateKey::random(
            &mut rand::rngs::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let fp = fingerprint_str(key.public_key().key_data());
        session.keys.write().await.insert(fp.clone(), key);
        let store = KeychainStore::new_v3(&[1; 8], &[2; 113]);
        assert!(
            session
                .private_key(&store, &fp, ReusePolicy::Fresh)
                .await
                .is_err(),
            "cached keys must not bypass a missing biometric session"
        );
        session.locked.store(true, Ordering::Release);
        assert!(session
            .private_key(&store, &fp, ReusePolicy::Fresh)
            .await
            .is_err());
    }

    /// Private keys load on the first authorized sign after a wipe, through
    /// the store's master; a locked agent never installs them.
    #[tokio::test]
    async fn private_key_reloads_lazily_and_respects_lock() {
        if !crate::server_macos::security::session_interactive_now() {
            eprintln!("skipped: no interactive GUI session");
            return;
        }
        let master = AesGcmCrypto::generate_key();
        let (mut store, custody) = software_store(&master);
        let privkey = ssh_key::private::PrivateKey::random(
            &mut rand::rngs::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let fp = fingerprint_str(privkey.public_key().key_data());
        let entry = super::super::SshKeyEntry {
            fingerprint: fp.clone(),
            algorithm: "ssh-ed25519".into(),
            comment: "lazy".into(),
            key_data: privkey
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        };
        keys::modify_ssh_keys(&mut store, &master, |entries| {
            entries.push(entry);
            Ok(true)
        })
        .unwrap();

        let session = test_session(0, 0);
        session.se_sessions.put(ReusePolicy::Fresh, custody);
        assert!(session.keys.read().await.is_empty());
        let loaded = session
            .private_key(&store, &fp, ReusePolicy::Fresh)
            .await
            .unwrap();
        assert_eq!(loaded.public_key(), privkey.public_key());
        assert_eq!(session.keys.read().await.len(), 1);
        assert!(session
            .private_key(&store, "SHA256:unknown", ReusePolicy::Fresh)
            .await
            .is_err());

        assert_eq!(super::super::clear_private_keys(&session.keys).await, 1);
        session.locked.store(true, Ordering::Release);
        assert!(session
            .private_key(&store, &fp, ReusePolicy::Fresh)
            .await
            .is_err());
        assert!(
            session.keys.read().await.is_empty(),
            "no install under lock"
        );
        session.locked.store(false, Ordering::Release);
        assert!(session
            .private_key(&store, &fp, ReusePolicy::Fresh)
            .await
            .is_ok());
    }

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
    fn who_at_host_keeps_ssh_destination_unprefixed() {
        assert_eq!(who_at_host("qiqi", "git@github.com"), "git@github.com");
    }

    #[test]
    fn strip_repeated_destination_only_drops_exact_header_match() {
        let who = "git@github.com";
        assert_eq!(
            strip_repeated_destination("ssh-sign: fetch -> git@github.com", who),
            "ssh-sign: fetch"
        );
        assert_eq!(
            strip_repeated_destination("ssh-sign: fetch -> other.host", who),
            "ssh-sign: fetch -> other.host"
        );
        assert_eq!(strip_repeated_destination("[read]", who), "[read]");
        assert_eq!(strip_repeated_destination("x -> ", ""), "x -> ");
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
        let mut msg = format!("decrypt 1: [read] on {}", header_who(&meta, "alpha"));
        append_meta_lines(&mut msg, &meta);
        let lines: Vec<&str> = msg.split('\n').collect();
        // SSH peer address rides the header, ports dropped; no `ssh:` row.
        assert_eq!(lines[0], "decrypt 1: [read] on qiqi@alpha (ssh 10.0.0.5)");
        assert_eq!(lines[1], "pwd: /tmp");
        assert_eq!(lines[2], "via: zsh -i");
        assert_eq!(lines.len(), 3, "tty and ssh must not be rendered as rows");
    }

    #[test]
    fn header_who_without_ssh_session_is_plain() {
        let meta = crate::core::ClientMeta {
            user: "qiqi".into(),
            ..Default::default()
        };
        assert_eq!(header_who(&meta, "alpha"), "qiqi@alpha");
        assert_eq!(header_who(&crate::core::ClientMeta::default(), ""), "");
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
            ssh_client: huge.clone(),
            ..Default::default()
        };
        let mut msg = header_who(&meta, &huge);
        append_meta_lines(&mut msg, &meta);
        // header: host 60 + ssh 60; pwd:100, via:40 — plus labels and newlines.
        // Conservative upper bound: each line under 140 chars.
        for line in msg.split('\n').filter(|l| !l.is_empty()) {
            assert!(
                line.chars().count() <= 140,
                "prompt line too long ({} chars): {}",
                line.chars().count(),
                line,
            );
        }
    }
}
