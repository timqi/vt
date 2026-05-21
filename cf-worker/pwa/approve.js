'use strict';

(function () {
    var data = vt.bootData();
    if (!data) return;
    var b64uDec = vt.b64uDec, b64uEnc = vt.b64uEnc, setStatus = vt.setStatus;
    var ENC = new TextEncoder();

    // Pre-warm everything that runApprove() needs before navigator.credentials.get()
    // so that those awaits land on already-resolved promises by the time the
    // user taps. iOS Safari is strict about the user-gesture window — once we
    // hit a real async boundary, the gesture is gone and the Passkey prompt
    // won't appear.
    var prfInputReady = crypto.subtle.digest(
        'SHA-256', ENC.encode('vt-passkey-prf-v1')
    ).then(function (buf) { return new Uint8Array(buf); });
    var sodiumReady = (typeof sodium !== 'undefined') ? sodium.ready : Promise.reject(new Error('libsodium 未加载'));

    function renderMeta(meta) {
        var dl = document.getElementById('meta');
        dl.innerHTML = '';
        if (!meta) return;
        // Order top-down by "does this help me recognize the session": who/where
        // first, then what command, then transport details, last the free-form
        // reason and the request kind.
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
            var dt = document.createElement('dt'); dt.textContent = label;
            var dd = document.createElement('dd'); dd.textContent = String(meta[key]);
            row.appendChild(dt); row.appendChild(dd);
            dl.appendChild(row);
        }
    }
    renderMeta(data.metadata);

    async function runApprove() {
        var k = null, kWrap = null, masterKey = null, deks = null;
        var pwaSk = null, shared = null, bindingKey = null;
        try {
            setStatus('请触摸 Passkey 完成验证…');

            // Both promises were kicked off at page load and are resolved by now.
            var PRF_INPUT = await prfInputReady;
            await sodiumReady;

            // Ephemeral X25519 keypair, then commit pwa_pk into the WebAuthn
            // challenge: effective_challenge = SHA-256(approve_challenge_hash || pwa_pk).
            // Any swap of pwa_pk on the wire invalidates the assertion signature.
            var kp = sodium.crypto_box_keypair();
            var pwaPk = kp.publicKey;
            pwaSk = kp.privateKey;
            var approveChHash = b64uDec(data.approve_challenge_b64u);
            var concat = new Uint8Array(approveChHash.length + pwaPk.length);
            concat.set(approveChHash, 0);
            concat.set(pwaPk, approveChHash.length);
            var effectiveChallenge = await vt.sha256(concat);

            // Use eval.first (not evalByCredential): PRF input is the same for
            // every credential, so both forms produce identical PRF results.
            // eval.first is more broadly supported across iOS/Safari versions.
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
            deks.fill(0); deks = null;

            // Bind sealed_deks via ECDH(pwa_sk, daemon_pk) → HKDF → HMAC, so an
            // attacker between PWA and Worker can't substitute sealed_deks
            // without forging a MAC keyed on a secret only the PWA and the
            // daemon hold.
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
            var resp = await fetch(vt.apiPath('/api/approve'), {
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
                }),
            });
            if (!resp.ok) throw new Error('提交失败（HTTP ' + resp.status + '）');
            setStatus('✓ 审批成功', 'ok');
            document.getElementById('approve').disabled = true;
            document.getElementById('reject').disabled = true;
            setTimeout(function () { window.close(); }, 800);
        } catch (e) {
            var msg = (e && e.message) ? e.message : String(e);
            if (/NotAllowed|not allowed/i.test(msg)) msg = '未找到匹配的 Passkey，或操作被取消';
            setStatus('错误：' + msg, 'error');
            console.error(e);
        } finally {
            vt.zeroize(k); vt.zeroize(kWrap); vt.zeroize(masterKey); vt.zeroize(deks);
            vt.zeroize(pwaSk); vt.zeroize(shared); vt.zeroize(bindingKey);
        }
    }

    async function runReject() {
        var approveBtn = document.getElementById('approve');
        var rejectBtn  = document.getElementById('reject');
        approveBtn.disabled = true; rejectBtn.disabled = true;
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
            var resp = await fetch(vt.apiPath('/api/reject'), {
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
                approveBtn.disabled = false; rejectBtn.disabled = false;
                return;
            }
            setStatus('✓ 已拒绝', 'ok');
            setTimeout(function () { window.close(); }, 800);
        } catch (e) {
            var msg = (e && e.message) ? e.message : String(e);
            if (/NotAllowed|not allowed/i.test(msg)) msg = '未找到匹配的 Passkey，或操作被取消';
            setStatus('错误：' + msg, 'error');
            console.error(e);
            approveBtn.disabled = false; rejectBtn.disabled = false;
        }
    }

    document.getElementById('approve').addEventListener('click', runApprove);
    document.getElementById('reject').addEventListener('click', runReject);
})();
