'use strict';

// Reusable Passkey approval ceremony.
//
// The full WebAuthn + key-derivation + /api/approve|reject flow lives here ONCE,
// exposed as `vt.mountApprove({ data, root, showMeta, onSettled })`. It builds
// its own interactive DOM (meta / cache selector / approve+reject / status) into
// the provided `root` element using class hooks (no global ids), so it can run
// both as the standalone approval page AND inline inside the admin audit page's
// detail modal — no forked ceremony logic to keep in sync.
//
//   • standalone page (/a/:token): auto-mounts against #vt-approve-root from the
//     embedded #vt-data block; onSettled closes the tab.
//   • audit page: audit.js fetches the same page data via /api/page/:token and
//     mounts into the detail card; onSettled closes the modal.

(function () {
    var ENC = new TextEncoder();

    // Pre-warm the PRF input digest at module load so the awaits inside the
    // click handler land on an already-resolved promise — iOS Safari drops the
    // user-gesture window at the first real async boundary.
    var prfInputReady = crypto.subtle.digest(
        'SHA-256', ENC.encode('vt-passkey-prf-v1')
    ).then(function (buf) { return new Uint8Array(buf); });

    var el = vt.el, ttlLabel = vt.ttlLabel;

    // Build the ceremony UI into `root`; return element refs. Class-scoped so
    // duplicate ids can't collide with a host page (e.g. audit's own #status).
    function buildUi(root, showMeta) {
        root.classList.add('vt-approve');
        root.innerHTML = '';
        var refs = {};

        if (showMeta) {
            // The decision line (operation, record count) and the decision
            // fields (records, host, command) stay above the fold; the rest of the
            // request folds into Details (docs/approval-transparency.md#presentation).
            var metaSec = el('section', 'vt-ap-meta-section');
            refs.decision = el('h2', 'vt-ap-decision');
            metaSec.appendChild(refs.decision);
            refs.meta = el('dl', 'vt-ap-meta');
            metaSec.appendChild(refs.meta);
            refs.details = el('details', 'vt-ap-details');
            refs.details.appendChild(el('summary', null, 'Details'));
            refs.detailMeta = el('dl', 'vt-ap-meta');
            refs.details.appendChild(refs.detailMeta);
            metaSec.appendChild(refs.details);
            refs.metaNote = el('p', 'hint vt-ap-meta-note');
            metaSec.appendChild(refs.metaNote);
            root.appendChild(metaSec);
        }

        var cacheSec = el('section', 'vt-ap-cache-section');
        cacheSec.hidden = true;
        cacheSec.appendChild(el('h2', null, 'Cache decrypt authorization'));
        // The reuse scope this approval would arm, in one line: what the cache
        // key binds — host token (verified) + project (client-reported, its
        // repository's common git dir, so every worktree shares one cache) — and
        // what that buys, a decrypt with no phone approval. No cache is the
        // duration control's own default, so it needs no sentence.
        refs.cacheScope = el('p', 'hint cache-scope');
        refs.cacheScope.hidden = true;
        cacheSec.appendChild(refs.cacheScope);
        // Duration control: a glass segmented control, No cache first and default.
        refs.cacheOpts = el('div', 'seg glass');
        refs.cacheOpts.setAttribute('role', 'radiogroup');
        refs.cacheOpts.setAttribute('aria-label', 'Cache duration');
        cacheSec.appendChild(refs.cacheOpts);
        refs.cacheSection = cacheSec;
        root.appendChild(cacheSec);

        // Action bar: the status line over Approve (2fr) / Reject (1fr). Floats over
        // the standalone card; sticks to the sheet's bottom inline (admin.css).
        var bar = el('div', 'vt-ap-bar glass');
        refs.status = el('p', 'vt-ap-status');
        refs.status.setAttribute('role', 'status');
        refs.status.setAttribute('aria-live', 'polite');
        bar.appendChild(refs.status);
        var actions = el('div', 'vt-ap-actions');
        refs.approve = el('button', 'vt-ap-approve', 'Approve');
        refs.approve.type = 'button';
        refs.reject = el('button', 'vt-ap-reject', 'Reject');
        refs.reject.type = 'button';
        actions.appendChild(refs.approve);
        actions.appendChild(refs.reject);
        bar.appendChild(actions);
        root.appendChild(bar);

        return refs;
    }

    function mountApprove(opts) {
        var data = opts.data;
        var root = opts.root;
        if (!data || !root) return;
        var showMeta = opts.showMeta !== false;
        var onSettled = opts.onSettled || function () {};

        var b64uDec = vt.b64uDec, b64uEnc = vt.b64uEnc;

        // User-verification level for BOTH ceremonies below. The worker decides
        // it per challenge (uv_policy.ts) and the worker enforces the same value
        // on the assertion, so the page only relays it. An old/garbled payload
        // falls back to 'required' — the strict direction, and what the worker
        // verifies a pre-policy challenge at.
        var UV = ['discouraged', 'preferred', 'required']
            .indexOf(data.user_verification) < 0 ? 'required' : data.user_verification;

        var refs = buildUi(root, showMeta);
        var setStatus = vt.statusLine(refs.status);

        // Name inputs of the unnamed records, keyed by index into salts_b64u.
        // Read at the Approve tap (no await in between) and posted with the
        // approval; the Worker writes them only after the assertion verifies.
        var nameInputs = [];

        // One line per record. Server-owned names are truth lines and come
        // first, read-only (rename lives in admin); an unnamed record gets a
        // name input and, when the client sent a claim, a chip labeled as the
        // client's that fills the input in one tap.
        function renderRecords(records) {
            var ul = el('ul', 'vt-ap-records');
            var named = records.filter(function (r) { return r.name; });
            var unnamed = records.filter(function (r) { return !r.name; });
            named.concat(unnamed).forEach(function (r) {
                var li = document.createElement('li');
                if (r.name) {
                    var text = el('span', 'rec-text');
                    text.appendChild(el('strong', null, r.name));
                    if (r.claimed && r.claimed !== r.name) {
                        text.appendChild(el('span', 'muted', ' (client calls it ' + r.claimed + ')'));
                    }
                    li.appendChild(text);
                } else {
                    var input = document.createElement('input');
                    input.type = 'text';
                    input.className = 'vt-ap-name';
                    input.placeholder = 'record name';
                    input.maxLength = 40;
                    input.autocomplete = 'off';
                    input.setAttribute('aria-label', 'Record name');
                    input.setAttribute('data-index', String(records.indexOf(r)));
                    li.appendChild(input);
                    if (r.claimed) {
                        var chip = el('button', 'chip', 'client calls it ' + r.claimed);
                        chip.type = 'button';
                        chip.addEventListener('click', function () { input.value = r.claimed; });
                        li.appendChild(chip);
                    }
                    nameInputs.push(input);
                }
                ul.appendChild(li);
            });
            return ul;
        }

        // `[{index, name}]` for every non-empty input, in salt order.
        function typedNames() {
            return nameInputs.map(function (i) {
                return { index: parseInt(i.getAttribute('data-index'), 10), name: i.value.trim() };
            }).filter(function (n) { return n.name; });
        }

        function addRow(dl, label, value) {
            if (value == null || value === '') return;
            var row = document.createElement('div');
            row.appendChild(el('dt', null, label));
            var dd = el('dd', null, typeof value === 'string' ? value : null);
            if (typeof value !== 'string') dd.appendChild(value);
            row.appendChild(dd);
            dl.appendChild(row);
        }

        // ── Request metadata ─────────────────────────────────────────────
        if (showMeta && refs.meta) {
            var meta = data.metadata;
            refs.meta.innerHTML = '';
            if (meta) {
                // Trust per field: record names are server-owned; `ip` is
                // worker-verified (CF-Connecting-IP); host/user come from the
                // host-token record (verified at enrollment) unless this ceremony
                // IS the enrollment, where they are the requester's own claim;
                // the rest is client-reported.
                var enrolling = !!data.enroll_pair_code;
                var hostVerified = !enrolling && !!data.host_verified;
                var records = Array.isArray(data.records) ? data.records : [];
                // Type + N records (N worker-derived) form the decision line;
                // the records themselves, named first, sit right under it.
                refs.decision.textContent = (meta.op_kind || '')
                    + (records.length > 0 ? ' · ' + records.length + ' records' : '');
                if (records.length > 0) refs.meta.parentNode.insertBefore(renderRecords(records), refs.meta);
                var who = [meta.user, meta.host].filter(Boolean).join('@');
                addRow(refs.meta, hostVerified ? 'Host (verified)' : 'Host', who);
                addRow(refs.meta, 'Command', meta.command);
                // Enrollment: the pairing code is the approver's proof that this
                // request is the terminal in front of them, not a stranger's
                // concurrent one. Big, on its own row.
                if (enrolling) {
                    var prow = document.createElement('div');
                    prow.appendChild(el('dt', null, 'Pairing code'));
                    prow.appendChild(el('dd', 'vt-ap-pair', data.enroll_pair_code));
                    refs.meta.appendChild(prow);
                }
                addRow(refs.detailMeta, 'Directory', meta.pwd);
                addRow(refs.detailMeta, 'Project', meta.project);
                addRow(refs.detailMeta, 'Parent process', meta.ppid_cmd);
                // Host-token path: this token last spoke from another IP.
                addRow(refs.detailMeta, 'IP (verified)', meta.ip
                    ? meta.ip + (meta.ip_prev ? ' (last ' + meta.ip_prev + ')' : '') : '');
                addRow(refs.detailMeta, 'Reason', meta.reason);
                refs.details.hidden = !refs.detailMeta.firstChild;
                refs.metaNote.textContent = enrolling
                    ? 'Host / user are claimed by the requester; IP and origin are server-verified. Approve only if the pairing code matches the terminal.'
                    : hostVerified
                        ? 'Record names are server-stored; host / user come from the enrolled host token, IP is verified; the rest is client-claimed, for reference only.'
                        : 'Record names are server-stored; everything but the IP is client-claimed, for reference only (host not yet enrolled).';
            }
        }

        // ── DEK-cache duration selector ──────────────────────────────────
        // Shown when this ceremony has DEKs to cache. Default = 0 ("No cache"),
        // which writes nothing.
        (function renderCacheOptions() {
            var optsList = data.cache_options_s || [];
            var pk = data.cache_pubkey_b64u || '';
            if (!pk || optsList.length <= 1) return;
            var scope = (data.metadata && data.metadata.project) || '';
            if (scope) {
                refs.cacheScope.innerHTML = '';
                refs.cacheScope.appendChild(document.createTextNode('Skips phone approval for the '));
                refs.cacheScope.appendChild(el('strong', null, 'same host token (verified)'));
                refs.cacheScope.appendChild(document.createTextNode(' and project (client-reported) '));
                refs.cacheScope.appendChild(el('strong', 'cache-path', scope));
                var literal = (data.metadata && data.metadata.pwd) || '';
                if (literal && literal !== scope) {
                    refs.cacheScope.appendChild(
                        document.createTextNode(' — this directory: ' + literal + ', other directories of the project hit too'));
                }
                refs.cacheScope.hidden = false;
            }
            refs.cacheOpts.innerHTML = '';
            optsList.forEach(function (s, i) {
                var label = el('label', null);
                var input = document.createElement('input');
                input.type = 'radio';
                input.name = 'cache-ttl';
                input.value = String(s);
                if (i === 0) input.checked = true; // 0 first → default No cache
                label.appendChild(input);
                label.appendChild(el('span', null, ttlLabel(s)));
                refs.cacheOpts.appendChild(label);
            });
            vt.seg(refs.cacheOpts);
            refs.cacheSection.hidden = false;
        })();

        function selectedTtl() {
            var sel = refs.cacheOpts.querySelector('input[name="cache-ttl"]:checked');
            var v = sel ? parseInt(sel.value, 10) : 0;
            return (Number.isFinite(v) && v > 0) ? v : 0;
        }

        async function runApprove() {
            var k = null, kWrap = null, masterKey = null, deks = null;
            var shared = null, bindingKey = null;
            try {
                setStatus('Touch the Passkey to verify…');
                // Read before the ceremony: the inputs are what the approver saw
                // when they tapped Approve, not whatever a later edit made of them.
                var adoptNames = typedNames();

                var PRF_INPUT = await prfInputReady;

                // Ephemeral X25519 keypair (non-extractable; docs/sealed-box-v1.md),
                // then commit pwa_pk into the WebAuthn challenge:
                // effective_challenge = SHA-256(approve_challenge_hash || pwa_pk).
                var kp = await vt.x25519Keypair();
                var pwaPk = kp.pk;
                var approveChHash = b64uDec(data.approve_challenge_b64u);
                var concat = new Uint8Array(approveChHash.length + pwaPk.length);
                concat.set(approveChHash, 0);
                concat.set(pwaPk, approveChHash.length);
                var effectiveChallenge = await vt.sha256(concat);

                var assertion = await navigator.credentials.get({
                    publicKey: {
                        challenge: effectiveChallenge,
                        rpId: data.rp_id,
                        allowCredentials: data.allow_credentials.map(function (c) {
                            return { type: 'public-key', id: b64uDec(c.id_b64u) };
                        }),
                        userVerification: UV,
                        extensions: { prf: { eval: { first: PRF_INPUT } } },
                    },
                });

                setStatus('Processing…');

                var usedId = b64uEnc(new Uint8Array(assertion.rawId));
                var entry = null;
                for (var j = 0; j < data.allow_credentials.length; j++) {
                    if (data.allow_credentials[j].id_b64u === usedId) { entry = data.allow_credentials[j]; break; }
                }
                if (!entry) throw new Error('The Passkey used is not on the allow list');

                var ext = assertion.getClientExtensionResults && assertion.getClientExtensionResults();
                var prfResult = ext && ext.prf && ext.prf.results && ext.prf.results.first;
                if (!prfResult) {
                    setStatus('This Passkey lacks the PRF extension; use 1Password or YubiKey', 'error');
                    return;
                }
                k = new Uint8Array(prfResult);

                kWrap = await vt.deriveKWrap(k);
                var kBytes = b64uDec(entry.k_b64u);
                if (kBytes.length !== 60) throw new Error('unexpected k length: ' + kBytes.length);
                var iv = kBytes.slice(0, 12);
                var ctTag = kBytes.slice(12);
                var hBytes = b64uDec(entry.h_b64u);
                var aad = new Uint8Array(16 + hBytes.length);
                aad.set(ENC.encode('vt-master-key-v1'), 0);
                aad.set(hBytes, 16);
                var kWrapKey = await crypto.subtle.importKey('raw', kWrap, { name: 'AES-GCM' }, false, ['decrypt']);
                var masterKeyBuf;
                try {
                    masterKeyBuf = await crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: iv, additionalData: aad }, kWrapKey, ctTag);
                } catch (_) {
                    throw new Error('AES-GCM decrypt failed: PRF output does not match the registration; the Passkey may need re-registering');
                }
                masterKey = new Uint8Array(masterKeyBuf);
                if (masterKey.length !== 32) throw new Error('unexpected master_key length: ' + masterKey.length);

                var salts = data.salts_b64u || [];
                deks = new Uint8Array(Math.max(salts.length, 1) * 32);
                if (salts.length === 0) {
                    deks.fill(0); // auth-only: placeholder DEK, daemon discards
                } else {
                    for (var s = 0; s < salts.length; s++) {
                        var dek = await vt.deriveDek(masterKey, b64uDec(salts[s]));
                        deks.set(dek, s * 32);
                        dek.fill(0);
                    }
                }
                masterKey.fill(0); kWrap.fill(0); k.fill(0);
                masterKey = null; kWrap = null; k = null;

                var daemonPk = b64uDec(data.daemon_pubkey_b64u);
                if (daemonPk.length !== 32) throw new Error('unexpected daemon_pubkey length');
                var sealedDeks = await vt.sealBox(deks, daemonPk);

                // INVARIANT: cache sealing MUST happen here — after sealing to the
                // daemon and BEFORE `deks.fill(0)` below. Only when the user picked
                // TTL > 0 do we seal each DEK to the worker's CACHE_PUBKEY.
                var cacheTtlS = selectedTtl();
                var cacheSealed = null;
                if (cacheTtlS > 0 && data.cache_pubkey_b64u && salts.length > 0) {
                    var cachePk = b64uDec(data.cache_pubkey_b64u);
                    if (cachePk.length !== 32) throw new Error('unexpected cache_pubkey length');
                    cacheSealed = [];
                    for (var ci = 0; ci < salts.length; ci++) {
                        var dekSlice = deks.subarray(ci * 32, (ci + 1) * 32);
                        cacheSealed.push(b64uEnc(await vt.sealBox(dekSlice, cachePk)));
                    }
                }

                deks.fill(0); deks = null;

                // Bind sealed_deks via ECDH(pwa_sk, daemon_pk) → HKDF → HMAC.
                shared = await vt.x25519(kp.privateKey, daemonPk);
                bindingKey = await vt.hkdfSha256(shared, ENC.encode('vt-sealed-deks-bind-v1'), 32);
                var domain = ENC.encode('vt-bind-v1');
                var msg = new Uint8Array(domain.length + approveChHash.length + daemonPk.length + pwaPk.length + sealedDeks.length);
                var off = 0;
                msg.set(domain, off); off += domain.length;
                msg.set(approveChHash, off); off += approveChHash.length;
                msg.set(daemonPk, off); off += daemonPk.length;
                msg.set(pwaPk, off); off += pwaPk.length;
                msg.set(sealedDeks, off);
                var bindingTag = await vt.hmacSha256(bindingKey, msg);

                vt.zeroize(shared); shared = null;
                vt.zeroize(bindingKey); bindingKey = null;

                setStatus('Submitting…');
                var resp = await fetch('/api/approve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        approve_token: data.approve_token,
                        credential_id_b64u: usedId,
                        sealed_deks_b64u: b64uEnc(sealedDeks),
                        client_data_json_b64u: b64uEnc(new Uint8Array(assertion.response.clientDataJSON)),
                        authenticator_data_b64u: b64uEnc(new Uint8Array(assertion.response.authenticatorData)),
                        signature_b64u: b64uEnc(new Uint8Array(assertion.response.signature)),
                        pwa_pk_b64u: b64uEnc(pwaPk),
                        binding_tag_b64u: b64uEnc(bindingTag),
                        cache_ttl_s: cacheTtlS,
                        cache_sealed_deks_b64u: cacheSealed,
                        adopt_names: adoptNames,
                    }),
                });
                if (!resp.ok) throw new Error('Submit failed (HTTP ' + resp.status + ')');
                setStatus('✓ Approved', 'ok');
                refs.approve.disabled = true;
                refs.reject.disabled = true;
                onSettled('approved');
            } catch (e) {
                var m = (e && e.message) ? e.message : String(e);
                if (/NotAllowed|not allowed/i.test(m)) m = 'No matching Passkey, or the prompt was cancelled';
                setStatus('Error: ' + m, 'error');
                console.error(e);
            } finally {
                vt.zeroize(k); vt.zeroize(kWrap); vt.zeroize(masterKey); vt.zeroize(deks);
                vt.zeroize(shared); vt.zeroize(bindingKey);
            }
        }

        async function runReject() {
            refs.approve.disabled = true; refs.reject.disabled = true;
            try {
                setStatus('Touch the Passkey to reject…');
                var assertion = await navigator.credentials.get({
                    publicKey: {
                        challenge: b64uDec(data.reject_challenge_b64u),
                        rpId: data.rp_id,
                        allowCredentials: data.allow_credentials.map(function (c) {
                            return { type: 'public-key', id: b64uDec(c.id_b64u) };
                        }),
                        userVerification: UV,
                    },
                });
                var usedId = b64uEnc(new Uint8Array(assertion.rawId));
                setStatus('Submitting rejection…');
                var resp = await fetch('/api/reject', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        approve_token: data.approve_token,
                        credential_id_b64u: usedId,
                        client_data_json_b64u: b64uEnc(new Uint8Array(assertion.response.clientDataJSON)),
                        authenticator_data_b64u: b64uEnc(new Uint8Array(assertion.response.authenticatorData)),
                        signature_b64u: b64uEnc(new Uint8Array(assertion.response.signature)),
                    }),
                });
                if (!resp.ok) {
                    if (resp.status === 410) setStatus('Request no longer valid (already decided or timed out)', 'error');
                    else setStatus('Reject failed (HTTP ' + resp.status + ')', 'error');
                    refs.approve.disabled = false; refs.reject.disabled = false;
                    return;
                }
                setStatus('✓ Rejected', 'ok');
                onSettled('rejected');
            } catch (e) {
                var m = (e && e.message) ? e.message : String(e);
                if (/NotAllowed|not allowed/i.test(m)) m = 'No matching Passkey, or the prompt was cancelled';
                setStatus('Error: ' + m, 'error');
                console.error(e);
                refs.approve.disabled = false; refs.reject.disabled = false;
            }
        }

        refs.approve.addEventListener('click', runApprove);
        refs.reject.addEventListener('click', runReject);
        return refs;
    }

    vt.mountApprove = mountApprove;

    // Standalone approval page (/a/:token): auto-mount from the embedded data,
    // then land on the console shortly after a decision — the token is spent, so
    // the page would only reload as 410. window.close() is a no-op for a window
    // the script did not open (every notification and CLI-link arrival).
    // The admin shell has no such root.
    var reload = document.getElementById('ap-reload');
    if (reload) reload.addEventListener('click', function () { location.reload(); });

    var root = document.getElementById('vt-approve-root');
    if (root) {
        var data = vt.bootData();
        if (data) {
            mountApprove({
                data: data,
                root: root,
                showMeta: true,
                onSettled: function () { setTimeout(function () { location.replace('/admin'); }, 800); },
            });
        }
    }
})();
