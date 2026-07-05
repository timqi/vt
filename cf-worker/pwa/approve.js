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

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }

    function ttlLabel(s) {
        if (s === 0) return '不缓存';
        if (s % 3600 === 0) return (s / 3600) + ' 小时';
        if (s % 60 === 0) return (s / 60) + ' 分钟';
        return s + ' 秒';
    }

    // Build the ceremony UI into `root`; return element refs. Class-scoped so
    // duplicate ids can't collide with a host page (e.g. audit's own #status).
    function buildUi(root, showMeta) {
        root.classList.add('vt-approve');
        root.innerHTML = '';
        var refs = {};

        if (showMeta) {
            var metaSec = el('section', 'vt-ap-meta-section');
            metaSec.appendChild(el('h2', null, '请求信息'));
            refs.meta = el('dl', 'vt-ap-meta');
            metaSec.appendChild(refs.meta);
            root.appendChild(metaSec);
        }

        var cacheSec = el('section', 'vt-ap-cache-section');
        cacheSec.hidden = true;
        cacheSec.appendChild(el('h2', null, '缓存解密授权'));
        var warn = el('p', 'hint cache-warn');
        // Cache ctx binds source IP (hard) + working directory (advisory) — see
        // docs/dek-cache.md. Built as nodes to keep the <strong> emphasis under CSP.
        warn.appendChild(document.createTextNode('选择后，在该时长内、'));
        warn.appendChild(el('strong', null, '同一来源 IP 且同一工作目录'));
        warn.appendChild(document.createTextNode('对这些记录的解密将'));
        warn.appendChild(el('strong', null, '免手机审批'));
        warn.appendChild(document.createTextNode('。默认不缓存。'));
        cacheSec.appendChild(warn);
        refs.cacheOpts = el('div', 'vt-ap-cache-opts');
        refs.cacheOpts.setAttribute('role', 'radiogroup');
        refs.cacheOpts.setAttribute('aria-label', '缓存时长');
        cacheSec.appendChild(refs.cacheOpts);
        refs.cacheSection = cacheSec;
        root.appendChild(cacheSec);

        var actions = el('div', 'vt-ap-actions');
        refs.approve = el('button', 'vt-ap-approve', '✓ 同意');
        refs.approve.type = 'button';
        refs.reject = el('button', 'vt-ap-reject', '拒绝');
        refs.reject.type = 'button';
        actions.appendChild(refs.approve);
        actions.appendChild(refs.reject);
        root.appendChild(actions);

        refs.status = el('p', 'vt-ap-status');
        refs.status.setAttribute('role', 'status');
        refs.status.setAttribute('aria-live', 'polite');
        root.appendChild(refs.status);

        return refs;
    }

    function mountApprove(opts) {
        var data = opts.data;
        var root = opts.root;
        if (!data || !root) return;
        var showMeta = opts.showMeta !== false;
        var onSettled = opts.onSettled || function () {};

        var b64uDec = vt.b64uDec, b64uEnc = vt.b64uEnc;
        var sodiumReady = (typeof sodium !== 'undefined') ? sodium.ready
            : Promise.reject(new Error('libsodium 未加载'));

        var refs = buildUi(root, showMeta);

        function setStatus(text, kind) {
            refs.status.textContent = text || '';
            refs.status.className = 'vt-ap-status ' + (kind || '');
        }

        // ── Request metadata ─────────────────────────────────────────────
        if (showMeta && refs.meta) {
            var meta = data.metadata;
            refs.meta.innerHTML = '';
            if (meta) {
                var fields = [
                    ['op_kind',    '类型'],
                    ['host',       '主机'],
                    ['user',       '用户'],
                    ['pwd',        '目录'],
                    ['command',    '命令'],
                    ['tty',        '终端'],
                    ['ppid_cmd',   '父进程'],
                    ['ssh_client', 'SSH 来源'],
                    ['ip',         'IP'],
                    ['reason',     '原因']
                ];
                for (var i = 0; i < fields.length; i++) {
                    var key = fields[i][0], label = fields[i][1];
                    if (meta[key] == null || meta[key] === '') continue;
                    var row = document.createElement('div');
                    row.appendChild(el('dt', null, label));
                    row.appendChild(el('dd', null, String(meta[key])));
                    refs.meta.appendChild(row);
                }
            }
        }

        // ── DEK-cache duration selector ──────────────────────────────────
        // Shown only when the worker offers caching (CACHE_SECKEY set) AND this
        // ceremony has DEKs to cache. Default = 0 ("不缓存").
        (function renderCacheOptions() {
            var optsList = data.cache_options_s || [];
            var pk = data.cache_pubkey_b64u || '';
            if (!pk || optsList.length <= 1) return;
            refs.cacheOpts.innerHTML = '';
            optsList.forEach(function (s, i) {
                var label = el('label', 'cache-opt');
                var input = document.createElement('input');
                input.type = 'radio';
                input.name = 'cache-ttl';
                input.value = String(s);
                if (i === 0) input.checked = true; // 0 first → default 不缓存
                label.appendChild(input);
                label.appendChild(el('span', null, ttlLabel(s)));
                refs.cacheOpts.appendChild(label);
            });
            refs.cacheSection.hidden = false;
        })();

        function selectedTtl() {
            var sel = refs.cacheOpts.querySelector('input[name="cache-ttl"]:checked');
            var v = sel ? parseInt(sel.value, 10) : 0;
            return (Number.isFinite(v) && v > 0) ? v : 0;
        }

        async function runApprove() {
            var k = null, kWrap = null, masterKey = null, deks = null;
            var pwaSk = null, shared = null, bindingKey = null;
            try {
                setStatus('请触摸 Passkey 完成验证…');

                var PRF_INPUT = await prfInputReady;
                await sodiumReady;

                // Ephemeral X25519 keypair, then commit pwa_pk into the WebAuthn
                // challenge: effective_challenge = SHA-256(approve_challenge_hash || pwa_pk).
                var kp = sodium.crypto_box_keypair();
                var pwaPk = kp.publicKey;
                pwaSk = kp.privateKey;
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
                        userVerification: 'required',
                        extensions: { prf: { eval: { first: PRF_INPUT } } },
                    },
                });

                setStatus('正在处理…');

                var usedId = b64uEnc(new Uint8Array(assertion.rawId));
                var entry = null;
                for (var j = 0; j < data.allow_credentials.length; j++) {
                    if (data.allow_credentials[j].id_b64u === usedId) { entry = data.allow_credentials[j]; break; }
                }
                if (!entry) throw new Error('使用的 Passkey 不在允许列表中');

                var ext = assertion.getClientExtensionResults && assertion.getClientExtensionResults();
                var prfResult = ext && ext.prf && ext.prf.results && ext.prf.results.first;
                if (!prfResult) {
                    setStatus('此 Passkey 不支持 PRF 扩展，请换用 1Password 或 YubiKey', 'error');
                    return;
                }
                k = new Uint8Array(prfResult);

                kWrap = await vt.deriveKWrap(k);
                var kBytes = b64uDec(entry.k_b64u);
                if (kBytes.length !== 60) throw new Error('k 字段长度异常: ' + kBytes.length);
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
                    throw new Error('AES-GCM 解密失败：PRF 输出与注册记录不匹配，可能需要重新注册 Passkey');
                }
                masterKey = new Uint8Array(masterKeyBuf);
                if (masterKey.length !== 32) throw new Error('master_key 长度异常: ' + masterKey.length);

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
                if (daemonPk.length !== 32) throw new Error('daemon_pubkey 长度异常');
                var sealedDeks = sodium.crypto_box_seal(deks, daemonPk);

                // INVARIANT: cache sealing MUST happen here — after sealing to the
                // daemon and BEFORE `deks.fill(0)` below. Only when the user picked
                // TTL > 0 do we seal each DEK to the worker's CACHE_PUBKEY.
                var cacheTtlS = selectedTtl();
                var cacheSealed = null;
                if (cacheTtlS > 0 && data.cache_pubkey_b64u && salts.length > 0) {
                    var cachePk = b64uDec(data.cache_pubkey_b64u);
                    if (cachePk.length !== 32) throw new Error('cache_pubkey 长度异常');
                    cacheSealed = [];
                    for (var ci = 0; ci < salts.length; ci++) {
                        var dekSlice = deks.subarray(ci * 32, (ci + 1) * 32);
                        cacheSealed.push(b64uEnc(sodium.crypto_box_seal(dekSlice, cachePk)));
                    }
                }

                deks.fill(0); deks = null;

                // Bind sealed_deks via ECDH(pwa_sk, daemon_pk) → HKDF → HMAC.
                shared = sodium.crypto_scalarmult(pwaSk, daemonPk);
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
                vt.zeroize(pwaSk); pwaSk = null;

                setStatus('正在提交…');
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
                    }),
                });
                if (!resp.ok) throw new Error('提交失败（HTTP ' + resp.status + '）');
                setStatus('✓ 审批成功', 'ok');
                refs.approve.disabled = true;
                refs.reject.disabled = true;
                onSettled('approved');
            } catch (e) {
                var m = (e && e.message) ? e.message : String(e);
                if (/NotAllowed|not allowed/i.test(m)) m = '未找到匹配的 Passkey，或操作被取消';
                setStatus('错误：' + m, 'error');
                console.error(e);
            } finally {
                vt.zeroize(k); vt.zeroize(kWrap); vt.zeroize(masterKey); vt.zeroize(deks);
                vt.zeroize(pwaSk); vt.zeroize(shared); vt.zeroize(bindingKey);
            }
        }

        async function runReject() {
            refs.approve.disabled = true; refs.reject.disabled = true;
            try {
                setStatus('请触摸 Passkey 完成拒绝…');
                var assertion = await navigator.credentials.get({
                    publicKey: {
                        challenge: b64uDec(data.reject_challenge_b64u),
                        rpId: data.rp_id,
                        allowCredentials: data.allow_credentials.map(function (c) {
                            return { type: 'public-key', id: b64uDec(c.id_b64u) };
                        }),
                        userVerification: 'required',
                    },
                });
                var usedId = b64uEnc(new Uint8Array(assertion.rawId));
                setStatus('正在提交拒绝…');
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
                    if (resp.status === 410) setStatus('请求已失效（已审批或超时）', 'error');
                    else setStatus('拒绝失败（HTTP ' + resp.status + '）', 'error');
                    refs.approve.disabled = false; refs.reject.disabled = false;
                    return;
                }
                setStatus('✓ 已拒绝', 'ok');
                onSettled('rejected');
            } catch (e) {
                var m = (e && e.message) ? e.message : String(e);
                if (/NotAllowed|not allowed/i.test(m)) m = '未找到匹配的 Passkey，或操作被取消';
                setStatus('错误：' + m, 'error');
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
    // close the tab shortly after a decision.
    if (document.getElementById('vt-data')) {
        var data = vt.bootData();
        var root = document.getElementById('vt-approve-root');
        if (data && root) {
            mountApprove({
                data: data,
                root: root,
                showMeta: true,
                onSettled: function () { setTimeout(function () { window.close(); }, 800); },
            });
        }
    }
})();
